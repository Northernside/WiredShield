package http

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

type RequestLog struct {
	RequestTime          time.Time       `json:"request_time"`
	ClientIP             string          `json:"client_ip"`
	Method               string          `json:"method"`
	Host                 string          `json:"host"`
	Path                 string          `json:"path"`
	QueryParams          string          `json:"query_params"`
	RequestHeaders       json.RawMessage `json:"request_headers"`
	ResponseHeaders      json.RawMessage `json:"response_headers"`
	ResponseStatusOrigin int             `json:"response_status_origin"`
	ResponseStatusProxy  int             `json:"response_status_proxy"`
	ResponseTime         time.Duration   `json:"response_time"`
	TLSVersion           string          `json:"tls_version"`
	RequestSize          int64           `json:"request_size"`
	ResponseSize         int64           `json:"response_size"`
	RequestHTTPVersion   string          `json:"request_http_version"`
}

var (
	requestsChannel    = make(chan *fasthttp.Request)
	requestLogsChannel = make(chan *RequestLog, 1024*16)
	clientPool         sync.Pool
	service            *services.Service
	certCache          sync.Map
	dbConn             *sql.DB
)

func init() {
	env.LoadEnvFile()
	time.Sleep(1 * time.Second)
	var err error
	dbConn, err = sql.Open("postgres", fmt.Sprintf(
		"user=%s password=%s dbname=%s sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_DB", "reverseproxy"),
	))
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	go processRequestLogs()
}

func Prepare(_service *services.Service) func() {
	service = _service

	go handleRequestLogging()

	return func() {
		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		clientPool.New = func() interface{} {
			return &fasthttp.Client{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
		}

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		server := &fasthttp.Server{
			Handler: ProxyHandler,
			TLSConfig: &tls.Config{
				MinVersion:               tls.VersionTLS10,
				MaxVersion:               tls.VersionTLS13,
				GetCertificate:           getCertificateForDomain,
				InsecureSkipVerify:       false,
				ClientCAs:                nil,
				PreferServerCipherSuites: true,
			},
			DisableKeepalive: false,
		}

		err := server.ListenAndServeTLS(addr, "", "")
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func ProxyHandler(ctx *fasthttp.RequestCtx) {
	timeStart := time.Now()
	targetRecords, err := db.GetRecords("A", string(ctx.Host()))
	if err != nil || len(targetRecords) == 0 {
		ctx.Error("could not resolve target", fasthttp.StatusBadGateway)
		return
	}
	targetRecord := targetRecords[0].(db.ARecord)
	targetURL := "http://" + targetRecord.IP + string(ctx.Path())

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetRequestURI(targetURL + string(ctx.URI().String()))
	req.Header.SetMethodBytes(ctx.Method())
	req.Header.Set("wired-origin-ip", ctx.RemoteAddr().String())
	req.Header.Set("host", string(ctx.Host()))

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		req.Header.SetBytesKV(key, value)
	})

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := clientPool.Get().(*fasthttp.Client)
	defer clientPool.Put(client)

	err = client.Do(req, resp)
	if err != nil {
		ctx.Error("error contacting backend", fasthttp.StatusBadGateway)
		return
	}

	resp.Header.VisitAll(func(key, value []byte) {
		ctx.Response.Header.SetBytesKV(key, value)
	})

	ctx.Response.Header.Set("server", "wiredshield")
	ctx.Response.Header.Set("x-proxy-time", time.Since(timeStart).String())
	ctx.SetStatusCode(resp.StatusCode())
	ctx.SetBody(resp.Body())

	reqHeaders, _ := json.Marshal(convertHeaders(&ctx.Request.Header))
	respHeaders, _ := json.Marshal(convertHeaders(&resp.Header))

	requestLogsChannel <- &RequestLog{
		RequestTime:          timeStart,
		ClientIP:             ctx.RemoteAddr().String(),
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          string(ctx.URI().QueryString()),
		RequestHeaders:       reqHeaders,
		ResponseHeaders:      respHeaders,
		ResponseStatusOrigin: resp.StatusCode(),
		ResponseStatusProxy:  ctx.Response.StatusCode(),
		ResponseTime:         time.Since(timeStart),
		TLSVersion:           tlsVersionToString(ctx.TLSConnectionState().Version),
		RequestSize:          int64(ctx.Request.Header.ContentLength()),
		ResponseSize:         int64(resp.Header.ContentLength()),
		RequestHTTPVersion:   string(ctx.Request.Header.Protocol()),
	}

	select {
	case requestsChannel <- req:
	default:
		ctx.Error("service unavailable", fasthttp.StatusServiceUnavailable)
	}
}

func convertHeaders(headers interface{}) map[string]string {
	result := make(map[string]string)
	switch h := headers.(type) {
	case *fasthttp.RequestHeader:
		h.VisitAll(func(key, value []byte) {
			result[string(key)] = string(value)
		})
	case *fasthttp.ResponseHeader:
		h.VisitAll(func(key, value []byte) {
			result[string(key)] = string(value)
		})
	}

	return result
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS v1.0"
	case tls.VersionTLS11:
		return "TLS v1.1"
	case tls.VersionTLS12:
		return "TLS v1.2"
	case tls.VersionTLS13:
		return "TLS v1.3"
	default:
		return "Unknown"
	}
}

func handleRequestLogging() {
	for req := range requestsChannel {
		service.InfoLog("Request to " + string(req.URI().Host()))
	}
}

func processRequestLogs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		flushRequestLogs()
	}
}

func flushRequestLogs() {
	var logsBuffer bytes.Buffer

	for {
		select {
		case log := <-requestLogsChannel:
			logLine, err := json.Marshal(log)
			if err != nil {
				service.WarnLog(fmt.Sprintf("Failed to marshal log: %v", err))
				continue
			}
			logsBuffer.Write(logLine)
			logsBuffer.WriteByte('\n')
		default:
			goto INSERT
		}
	}

INSERT:
	if logsBuffer.Len() == 0 {
		return
	}

	_, err := dbConn.Exec(`COPY requests (data) FROM STDIN`, logsBuffer.String())
	if err != nil {
		service.WarnLog(fmt.Sprintf("Failed to insert logs: %v", err))
	}
}

func getCertificateForDomain(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no SNI provided by client")
	}

	if cert, ok := certCache.Load(domain); ok {
		return cert.(*tls.Certificate), nil
	}

	service.InfoLog("Loading certificate for " + domain)
	c, err := tls.LoadX509KeyPair(fmt.Sprintf("certs/%s.crt", domain), fmt.Sprintf("certs/%s.key", domain))
	if err == nil {
		certCache.Store(domain, &c)
	}

	return &c, err
}
