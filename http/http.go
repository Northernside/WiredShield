package http

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"wiredshield/modules/db"
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
	requestLogsChannel = make(chan *RequestLog, 1024^2)
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
		"postgres://%s:%s@localhost/%s?sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_DB", "reverseproxy"),
	))
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	service.InfoLog(fmt.Sprintf("postgres://%s:%s@localhost/%s?sslmode=disable", env.GetEnv("PSQL_USER", "wiredshield"), env.GetEnv("PSQL_PASSWORD", ""), env.GetEnv("PSQL_DB", "reverseproxy")))

	dbConn.SetMaxOpenConns(512)
	dbConn.SetMaxIdleConns(16)

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
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		flushRequestLogs()
	}
}

func flushRequestLogs() {
	var logsBuffer []string

	for {
		select {
		case log := <-requestLogsChannel:
			logLine, err := json.Marshal(log)
			if err != nil {
				service.WarnLog(fmt.Sprintf("Failed to marshal log: %v", err))
				continue
			}

			service.InfoLog(string(logLine))
			logsBuffer = append(logsBuffer, string(logLine))
		default:
			if len(logsBuffer) == 0 {
				return
			}

			goto INSERT
		}
	}

INSERT:
	txn, err := dbConn.Begin()
	if err != nil {
		service.WarnLog(fmt.Sprintf("Failed to begin transaction: %v", err))
		return
	}

	stmt, err := txn.Prepare("COPY requests (data) FROM STDIN")
	if err != nil {
		service.WarnLog(fmt.Sprintf("Failed to prepare COPY statement: %v", err))
		_ = txn.Rollback()
		return
	}
	defer stmt.Close()

	for _, log := range logsBuffer {
		service.InfoLog(fmt.Sprintf(">>>>>>> Inserting log: %s", log))
		_, err = stmt.Exec([]byte(log + "\n"))
		if err != nil {
			service.WarnLog(fmt.Sprintf("Failed to execute COPY statement: %v", err))
			_ = txn.Rollback()
			return
		}
	}

	if err := txn.Commit(); err != nil {
		service.WarnLog(fmt.Sprintf("Failed to commit transaction: %v", err))
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
