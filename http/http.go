package http

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

type requestLog struct {
	RequestTime          int64           `json:"request_time"`
	ClientIP             string          `json:"client_ip"`
	Method               string          `json:"method"`
	Host                 string          `json:"host"`
	Path                 string          `json:"path"`
	QueryParams          json.RawMessage `json:"query_params"`
	RequestHeaders       json.RawMessage `json:"request_headers"`
	ResponseHeaders      json.RawMessage `json:"response_headers"`
	ResponseStatusOrigin int             `json:"response_status_origin"`
	ResponseStatusProxy  int             `json:"response_status_proxy"`
	ResponseTime         int64           `json:"response_time"`
	TLSVersion           string          `json:"tls_version"`
	RequestSize          int64           `json:"request_size"`
	ResponseSize         int64           `json:"response_size"`
	RequestHTTPVersion   string          `json:"request_http_version"`
}

var (
	requestLogsChannel = make(chan *requestLog, (1024^2)*8)
	service            *services.Service
	certCache          sync.Map
	dbConn             *sql.DB
	certLoadMutex      sync.RWMutex
	clientPool         = &sync.Pool{
		New: func() interface{} {
			return &fasthttp.Client{
				MaxConnsPerHost: 2048,
			}
		},
	}
)

func init() {
	env.LoadEnvFile()
	time.Sleep(500 * time.Millisecond)
}

func Prepare(_service *services.Service) func() {
	service = _service

	var err error
	dbConn, err = sql.Open("postgres", fmt.Sprintf(
		"postgres://%s:%s@localhost:5432/%s?sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_DB", "reverseproxy"),
	))
	if err != nil {
		panic(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	dbConn.SetMaxOpenConns(0)
	dbConn.SetMaxIdleConns(2048)
	dbConn.SetConnMaxLifetime(5 * time.Minute)

	err = dbConn.Ping()
	if err != nil {
		panic(fmt.Sprintf("Failed to ping database: %v", err))
	}

	return func() {
		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		go processRequestLogs()

		server := &fasthttp.Server{
			Handler: ProxyHandler,
			Name:    "wiredshield",
			TLSConfig: &tls.Config{
				NextProtos:               []string{"http/1.1"},
				MinVersion:               tls.VersionTLS10,
				MaxVersion:               tls.VersionTLS13,
				InsecureSkipVerify:       true,
				PreferServerCipherSuites: true,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return getCertificateForDomain(hello)
				},
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{
						NextProtos:               []string{"http/1.1"},
						MinVersion:               tls.VersionTLS10,
						MaxVersion:               tls.VersionTLS13,
						PreferServerCipherSuites: true,
						CipherSuites: []uint16{
							tls.TLS_AES_128_GCM_SHA256,
							tls.TLS_AES_256_GCM_SHA384,
							tls.TLS_CHACHA20_POLY1305_SHA256,
							tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
							tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
							tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
							tls.TLS_RSA_WITH_AES_128_CBC_SHA,
							tls.TLS_RSA_WITH_AES_256_CBC_SHA,
							tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
							tls.TLS_RSA_WITH_AES_128_CBC_SHA,
							tls.TLS_RSA_WITH_AES_256_CBC_SHA,
							tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
						},
						CurvePreferences: []tls.CurveID{
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
						},
						GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
							return getCertificateForDomain(hello)
						},
						InsecureSkipVerify: false,
					}, nil
				},
			},
		}

		go func() {
			httpAddr := binding + ":80"
			service.InfoLog("Starting HTTP redirect server on " + httpAddr)
			httpServer := &fasthttp.Server{
				Handler: redirectToHTTPS,
			}

			if err := httpServer.ListenAndServe(httpAddr); err != nil {
				service.FatalLog("HTTP redirect server failed: " + err.Error())
			}
		}()

		err := server.ListenAndServeTLS(addr, "", "")
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func redirectToHTTPS(ctx *fasthttp.RequestCtx) {
	target := "https://" + string(ctx.Host()) + string(ctx.RequestURI())
	ctx.Redirect(target, fasthttp.StatusMovedPermanently)
}

func ProxyHandler(ctx *fasthttp.RequestCtx) {
	timeStart := time.Now()
	requestSize := calculateRequestSize(ctx)

	targetRecords, err := db.GetRecords("A", string(ctx.Host()))
	if err != nil || len(targetRecords) == 0 {
		ctx.Error("could not resolve target", fasthttp.StatusBadGateway)
		return
	}

	targetRecord := targetRecords[0].(db.ARecord)
	targetURL := "http://" + targetRecord.IP + ":80" + string(ctx.RequestURI())

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	ctx.Request.CopyTo(req)
	req.SetRequestURI(targetURL)
	req.Header.Set("wired-origin-ip", getIp(ctx))
	req.Header.Set("host", string(ctx.Host()))

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	client := clientPool.Get().(*fasthttp.Client)
	defer clientPool.Put(client)

	if err := client.Do(req, resp); err != nil {
		ctx.Error(fmt.Sprintf("error contacting backend: %v", err), fasthttp.StatusBadGateway)
		logRequest(ctx, resp, timeStart, 603, requestSize, 0)
		return
	}

	ctx.Response.Header.Set("server", "wiredshield")
	ctx.Response.Header.Set("x-proxy-time", fmt.Sprintf("%dms", time.Since(timeStart).Milliseconds()))
	resp.Header.CopyTo(&ctx.Response.Header)
	ctx.SetStatusCode(resp.StatusCode())

	var responseBodySize int64
	switch resp.StatusCode() {
	case fasthttp.StatusContinue, fasthttp.StatusSwitchingProtocols, fasthttp.StatusProcessing, fasthttp.StatusEarlyHints:
	case fasthttp.StatusNoContent, fasthttp.StatusResetContent:
	case fasthttp.StatusNotModified:
		ctx.SetStatusCode(resp.StatusCode())
	default:
		responseBodySize = int64(len(resp.Body()))
		ctx.SetBody(resp.Body())
	}

	logRequest(ctx, resp, timeStart, 0, requestSize, responseBodySize)
}

func logRequest(ctx *fasthttp.RequestCtx, resp *fasthttp.Response, timeStart time.Time, internalCode int, requestSize, responseSize int64) {
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

	requestLogsChannel <- &requestLog{
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             getIp(ctx),
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          queryParamString(string(ctx.URI().QueryString())),
		RequestHeaders:       reqHeaders,
		ResponseHeaders:      respHeaders,
		ResponseStatusOrigin: resp.StatusCode(),
		ResponseStatusProxy: func() int {
			if internalCode != 0 {
				return internalCode
			}
			return resp.StatusCode()
		}(),
		ResponseTime:       time.Since(timeStart).Milliseconds(),
		TLSVersion:         tlsVersionToString(ctx.TLSConnectionState().Version),
		RequestSize:        requestSize,
		ResponseSize:       responseSize,
		RequestHTTPVersion: string(ctx.Request.Header.Protocol()),
	}
}

func calculateRequestSize(ctx *fasthttp.RequestCtx) int64 {
	var size int64
	size += int64(len(ctx.Method()) + len(ctx.RequestURI()) + len(ctx.Request.Header.Protocol()) + 2) // req line
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		size += int64(len(key) + len(value) + 4) // header line
	})
	size += int64(len(ctx.PostBody()))
	return size
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}

func queryParamString(query string) json.RawMessage {
	params := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			continue
		}
		params[parts[0]] = parts[1]
	}
	data, _ := json.Marshal(params)
	return data
}

func processRequestLogs() {
	logWorkers := 128
	for i := 0; i < logWorkers; i++ {
		go func() {
			for log := range requestLogsChannel {
				logs := collectAdditionalLogs(log)
				if len(logs) > 0 {
					if err := batchInsertRequestLogs(logs); err != nil {
						service.ErrorLog(fmt.Sprintf("Failed to insert logs: %v", err))
					}
				}
			}
		}()
	}
}

func collectAdditionalLogs(initialLog *requestLog) []*requestLog {
	logs := []*requestLog{initialLog}
	for len(logs) < 128 {
		select {
		case log := <-requestLogsChannel:
			logs = append(logs, log)
		default:
			return logs
		}
	}
	return logs
}

func batchInsertRequestLogs(logs []*requestLog) error {
	if len(logs) == 0 {
		return nil
	}

	placeholders := make([]string, len(logs))
	values := make([]interface{}, 0, len(logs)*15)

	for i, log := range logs {
		placeholders[i] = fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*15+1, i*15+2, i*15+3, i*15+4, i*15+5, i*15+6, i*15+7, i*15+8,
			i*15+9, i*15+10, i*15+11, i*15+12, i*15+13, i*15+14, i*15+15,
		)

		reqHeaders, err := json.Marshal(log.RequestHeaders)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("Failed to marshal request headers: %v", err))
			reqHeaders = []byte("{}")
		}

		respHeaders, err := json.Marshal(log.ResponseHeaders)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("Failed to marshal response headers: %v", err))
			respHeaders = []byte("{}")
		}

		values = append(values,
			log.RequestTime,
			log.ClientIP,
			log.Method,
			log.Host,
			log.Path,
			log.QueryParams,
			reqHeaders,
			respHeaders,
			log.ResponseStatusOrigin,
			log.ResponseStatusProxy,
			log.ResponseTime,
			log.TLSVersion,
			log.RequestSize,
			log.ResponseSize,
			log.RequestHTTPVersion,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO requests (
			request_time, client_ip, method, host, path, query_params, 
			request_headers, response_headers, response_status_origin, 
			response_status_proxy, response_time, tls_version, 
			request_size, response_size, request_http_version
		) VALUES %s
	`, strings.Join(placeholders, ","))

	_, err := dbConn.Exec(query, values...)
	if err != nil {
		return fmt.Errorf("batch insert failed: %v", err)
	}

	return nil
}

func getCertificateForDomain(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("SNI (Server Name Indication) is missing in the TLS handshake")
	}

	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no SNI provided by client")
	}

	certLoadMutex.RLock()
	if cert, ok := certCache.Load(domain); ok {
		certLoadMutex.RUnlock()
		return cert.(*tls.Certificate), nil
	}
	certLoadMutex.RUnlock()

	certLoadMutex.Lock()
	defer certLoadMutex.Unlock()

	if cert, ok := certCache.Load(domain); ok {
		return cert.(*tls.Certificate), nil
	}

	c, err := tls.LoadX509KeyPair(fmt.Sprintf("certs/%s.crt", domain), fmt.Sprintf("certs/%s.key", domain))
	if err == nil {
		certCache.Store(domain, &c)
	}

	return &c, err
}

func getIp(ctx *fasthttp.RequestCtx) string {
	ip := ctx.RemoteIP().String()
	return ip
}
