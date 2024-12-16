package http

import (
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"wiredshield/modules/env"
	"wiredshield/services"

	_ "github.com/lib/pq"
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
	requestLogsChannel = make(chan *RequestLog, 1000)
	clientPool         sync.Pool
	service            *services.Service
	certCache          sync.Map
	dbConn             *sql.DB
)

func init() {
	env.LoadEnvFile()
	time.Sleep(500 * time.Millisecond)
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
				MinVersion:               tls.VersionTLS12,
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

	reqHeadersMap := make(map[string]string)
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		reqHeadersMap[string(key)] = string(value)
	})
	reqHeaders, _ := json.Marshal(reqHeadersMap)

	respHeadersMap := make(map[string]string)
	ctx.Response.Header.VisitAll(func(key, value []byte) {
		respHeadersMap[string(key)] = string(value)
	})
	respHeaders, _ := json.Marshal(respHeadersMap)

	requestLogsChannel <- &RequestLog{
		RequestTime:          timeStart,
		ClientIP:             ctx.RemoteAddr().String(),
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          string(ctx.URI().QueryString()),
		RequestHeaders:       reqHeaders,
		ResponseHeaders:      respHeaders,
		ResponseStatusOrigin: ctx.Response.StatusCode(),
		ResponseStatusProxy:  fasthttp.StatusOK,
		ResponseTime:         time.Since(timeStart),
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
