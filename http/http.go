package http

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	"github.com/jackc/pgx/v4/pgxpool"
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
	clientPool         sync.Pool
	service            *services.Service
	certCache          sync.Map
	dbConn             *pgxpool.Pool
	certLoadMutex      sync.RWMutex
)

func init() {
	env.LoadEnvFile()
	time.Sleep(500 * time.Millisecond)
}

func Prepare(_service *services.Service) func() {
	service = _service

	var err error
	connString := fmt.Sprintf(
		"postgres://%s:%s@localhost:5432/%s?sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_DB", "reverseproxy"),
	)

	dbConn, err = pgxpool.Connect(context.Background(), connString)
	if err != nil {
		service.FatalLog(fmt.Sprintf("failed to connect to database: %v", err))
	}

	return func() {
		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		clientPool = sync.Pool{
			New: func() interface{} {
				return &fasthttp.Client{
					ReadTimeout:     30 * time.Second,
					WriteTimeout:    30 * time.Second,
					MaxConnsPerHost: 1024 * 256,
					Dial: (&fasthttp.TCPDialer{
						Concurrency:      1024 * 256,
						DNSCacheDuration: 5 * time.Minute,
					}).Dial,
				}
			},
		}

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		server := &fasthttp.Server{
			Concurrency:   1024 * 256,
			Handler:       ProxyHandler,
			Name:          "wiredshield",
			MaxConnsPerIP: 1024 * 256,
			TLSConfig: &tls.Config{
				NextProtos:               []string{"http/1.1"},
				MinVersion:               tls.VersionTLS10,
				MaxVersion:               tls.VersionTLS13,
				GetCertificate:           getCertificateForDomain,
				InsecureSkipVerify:       false,
				ClientCAs:                nil,
				PreferServerCipherSuites: true,
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					return &tls.Config{
						NextProtos:               []string{"http/1.1"},
						MinVersion:               tls.VersionTLS10,
						MaxVersion:               tls.VersionTLS13,
						GetCertificate:           getCertificateForDomain,
						InsecureSkipVerify:       false,
						ClientCAs:                nil,
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
					}, nil
				},
			},
		}

		go processRequestLogs()

		go func() {
			httpAddr := binding + ":80"
			service.InfoLog("Starting HTTP redirect server on " + httpAddr)
			httpServer := &http.Server{
				Addr:    httpAddr,
				Handler: http.HandlerFunc(redirectToHTTPS),
			}

			err := httpServer.ListenAndServe()
			if err != nil {
				service.FatalLog(err.Error())
			}
		}()

		err := server.ListenAndServeTLS(addr, "", "")
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}

	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func ProxyHandler(ctx *fasthttp.RequestCtx) {
	if strings.HasPrefix(string(ctx.Path()), "/#wiredshield#/") {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("hello world")
		return
	}

	timeStart := time.Now()
	targetRecords, err := db.GetRecords("A", string(ctx.Host()))
	if err != nil || len(targetRecords) == 0 {
		ctx.Error("could not resolve target", fasthttp.StatusBadGateway)
		logRequest(ctx, nil, timeStart, 601, 0, 0)
		return
	}

	targetRecord := targetRecords[0].(db.ARecord)
	targetURL := "http://" + targetRecord.IP + ":80" + string(ctx.Path())

	requestSize := getRequestSize(ctx)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.Set("host", string(ctx.Host()))
	req.Header.Set("wired-origin-ip", getIp(ctx))
	req.UseHostHeader = true
	req.Header.SetMethodBytes(ctx.Method())
	req.SetRequestURI(targetURL)

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		req.Header.SetBytesKV(key, value)
	})

	req.SetBody(ctx.Request.Body())

	client := clientPool.Get().(*fasthttp.Client)
	defer clientPool.Put(client)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	err = client.Do(req, resp)
	if err != nil {
		ctx.Error("error contacting backend", fasthttp.StatusBadGateway)
		logRequest(ctx, resp, timeStart, 603, 0, 0)
		return
	}

	resp.Header.VisitAll(func(key, value []byte) {
		ctx.Response.Header.SetBytesKV(key, value)
	})

	ctx.Response.Header.Set("server", "wiredshield")
	ctx.Response.Header.Set("x-proxy-time", time.Since(timeStart).String())
	ctx.SetStatusCode(resp.StatusCode())
	ctx.SetBody(resp.Body())

	responseSize := getResponseSize(ctx, resp)

	switch resp.StatusCode() {
	case http.StatusContinue, http.StatusSwitchingProtocols, http.StatusProcessing, http.StatusEarlyHints:
	case http.StatusNoContent, http.StatusResetContent:
	case http.StatusNotModified:
		ctx.SetStatusCode(resp.StatusCode())
	default:
		if err != nil {
			service.ErrorLog(fmt.Sprintf("%d error streaming response body: %v", resp.StatusCode(), err))
			logRequest(ctx, resp, timeStart, 604, 0, 0)
			return
		}
	}

	logRequest(ctx, resp, timeStart, resp.StatusCode(), requestSize, responseSize)
}

// both methods still inaccurate, will fix at a later time
func getRequestSize(ctx *fasthttp.RequestCtx) int64 {
	totalSize := int64(0)

	totalSize += int64(len(ctx.Method()))
	url := ctx.URI().String()
	totalSize += int64(len(url))

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		totalSize += int64(len(key) + len(value))
	})

	totalSize += int64(len(ctx.Request.Body()))

	return totalSize
}

func getResponseSize(ctx *fasthttp.RequestCtx, resp *fasthttp.Response) int64 {
	totalSize := int64(0)

	totalSize += int64(len(fmt.Sprintf("%d", resp.StatusCode())))

	resp.Header.VisitAll(func(key, value []byte) {
		totalSize += int64(len(key) + len(value))
	})

	totalSize += int64(len(resp.Body()))

	return totalSize
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
		QueryParams:          queryParamString(string(ctx.QueryArgs().String())),
		RequestHeaders:       json.RawMessage(reqHeaders),
		ResponseHeaders:      json.RawMessage(respHeaders),
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

type QueryParams map[string]string

func queryParamString(query string) json.RawMessage {
	params := make(QueryParams)
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

func processRequestLogs() {
	logWorkers := 512
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

	conn, err := dbConn.Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	transaction, err := conn.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer transaction.Rollback(context.Background())

	placeholders := make([]string, len(logs))
	values := make([]interface{}, 0, len(logs)*15)

	for i, log := range logs {
		placeholders[i] = fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*15+1, i*15+2, i*15+3, i*15+4, i*15+5, i*15+6, i*15+7, i*15+8,
			i*15+9, i*15+10, i*15+11, i*15+12, i*15+13, i*15+14, i*15+15,
		)
		values = append(values,
			log.RequestTime,
			log.ClientIP,
			log.Method,
			log.Host,
			log.Path,
			log.QueryParams,
			log.RequestHeaders,
			log.ResponseHeaders,
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

	_, err = transaction.Exec(context.Background(), query, values...)
	if err != nil {
		return fmt.Errorf("batch insert failed: %v", err)
	}

	return transaction.Commit(context.Background())
}

func getCertificateForDomain(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
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

func getIp(reqCtx *fasthttp.RequestCtx) string {
	addr := reqCtx.RemoteAddr()
	ipAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return ""
	}

	return ipAddr.IP.String()
}
