package http

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	"github.com/kataras/iris/v12"
	_ "github.com/lib/pq"
)

type requestLog struct {
	RequestTime          int64               `json:"request_time"`
	ClientIP             string              `json:"client_ip"`
	Method               string              `json:"method"`
	Host                 string              `json:"host"`
	Path                 string              `json:"path"`
	QueryParams          json.RawMessage     `json:"query_params"`
	RequestHeaders       map[string][]string `json:"request_headers"`
	ResponseHeaders      map[string][]string `json:"response_headers"`
	ResponseStatusOrigin int                 `json:"response_status_origin"`
	ResponseStatusProxy  int                 `json:"response_status_proxy"`
	ResponseTime         int64               `json:"response_time"`
	TLSVersion           string              `json:"tls_version"`
	RequestSize          int64               `json:"request_size"`
	ResponseSize         int64               `json:"response_size"`
	RequestHTTPVersion   string              `json:"request_http_version"`
}

var (
	requestLogsChannel = make(chan *requestLog, (1024^2)*8)
	service            *services.Service
	certCache          sync.Map
	dbConn             *sql.DB
	certLoadMutex      sync.RWMutex
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
		app := iris.New()

		app.Get("/", ProxyHandler)

		go processRequestLogs()

		tlsConfig := &tls.Config{
			MinVersion:               tls.VersionTLS10,
			MaxVersion:               tls.VersionTLS13,
			GetCertificate:           getCertificateForDomain,
			InsecureSkipVerify:       false,
			PreferServerCipherSuites: true,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
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
		}

		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		go func() {
			httpAddr := binding + ":80"
			service.InfoLog("Starting HTTP redirect server on " + httpAddr)
			httpServer := &http.Server{
				Addr:    httpAddr,
				Handler: http.HandlerFunc(redirectToHTTPS),
			}

			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				service.FatalLog("HTTP redirect server failed: " + err.Error())
			}
		}()

		server := &http.Server{
			Addr:      ":443",
			TLSConfig: tlsConfig,
		}

		if err := app.Run(iris.Server(server)); err != nil {
			service.FatalLog("HTTPS proxy server failed: " + err.Error())
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

func ProxyHandler(ctx iris.Context) {
	timeStart := time.Now()
	requestSize := calculateRequestSize(ctx.Request())

	targetRecords, err := db.GetRecords("A", ctx.Host())
	if err != nil || len(targetRecords) == 0 {
		ctx.StatusCode(http.StatusBadGateway)
		ctx.WriteString("could not resolve target")
		resp := &http.Response{StatusCode: http.StatusBadGateway, Header: http.Header{}, ContentLength: 0}
		logRequest(ctx.Request(), resp, timeStart, 601, requestSize, 0)
		return
	}

	targetRecord := targetRecords[0].(db.ARecord)
	targetURL := "http://" + targetRecord.IP + ":80" + ctx.Request().URL.Path

	req, err := http.NewRequest(ctx.Method(), targetURL, ctx.Request().Body)
	if err != nil {
		ctx.StatusCode(http.StatusInternalServerError)
		ctx.WriteString("error creating request")
		resp := &http.Response{StatusCode: http.StatusInternalServerError, Header: http.Header{}, ContentLength: 0}
		logRequest(ctx.Request(), resp, timeStart, 602, requestSize, 0)
		return
	}

	req.Header = ctx.Request().Header
	req.Header.Set("wired-origin-ip", getIp(ctx.Request()))
	req.Header.Set("host", ctx.Host())

	req.Host = ctx.Host()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		ctx.StatusCode(http.StatusBadGateway)
		ctx.WriteString("error contacting backend")
		logRequest(ctx.Request(), resp, timeStart, 603, requestSize, 0)
		return
	}
	defer resp.Body.Close()

	for key, value := range resp.Header {
		ctx.Header(key, value[0])
	}

	ctx.Header("server", "wiredshield")
	ctx.Header("x-proxy-time", fmt.Sprintf("%dms", time.Since(timeStart).Milliseconds()))
	ctx.StatusCode(resp.StatusCode)

	var responseBodySize int64
	switch resp.StatusCode {
	case http.StatusContinue, http.StatusSwitchingProtocols, http.StatusProcessing, http.StatusEarlyHints:
	case http.StatusNoContent, http.StatusResetContent:
	case http.StatusNotModified:
		ctx.StatusCode(resp.StatusCode)
	default:
		responseBodySize, err = io.Copy(ctx.ResponseWriter(), resp.Body)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("%d error streaming response body: %v", resp.StatusCode, err))
			logRequest(ctx.Request(), resp, timeStart, 604, requestSize, 0)
			return
		}
	}

	logRequest(ctx.Request(), resp, timeStart, 0, requestSize, responseBodySize)
}

func calculateRequestSize(r *http.Request) int64 {
	var size int64
	size += int64(len(r.Method) + len(r.URL.String()) + len(r.Proto) + 2) // req line
	for k, v := range r.Header {
		size += int64(len(k) + len(v[0]) + 4) // header line
	}

	if r.Body != nil {
		bodyBytes, _ := ioutil.ReadAll(r.Body)
		size += int64(len(bodyBytes))
		r.Body = ioutil.NopCloser(strings.NewReader(string(bodyBytes))) // reset body
	}

	return size
}

func logRequest(r *http.Request, resp *http.Response, timeStart time.Time, internalCode int, requestSize, responseSize int64) {
	requestLogsChannel <- &requestLog{
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             getIp(r),
		Method:               r.Method,
		Host:                 r.Host,
		Path:                 r.URL.Path,
		QueryParams:          queryParamString(r.URL.RawQuery),
		RequestHeaders:       r.Header,
		ResponseHeaders:      resp.Header,
		ResponseStatusOrigin: resp.StatusCode,
		ResponseStatusProxy: func() int {
			if internalCode != 0 {
				return internalCode
			}

			return resp.StatusCode
		}(),
		ResponseTime:       time.Since(timeStart).Milliseconds(),
		TLSVersion:         tlsVersionToString(r.TLS.Version),
		RequestSize:        requestSize,
		ResponseSize:       responseSize,
		RequestHTTPVersion: r.Proto,
	}
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

func getIp(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func requestLogger(ctx iris.Context) {
	start := time.Now()
	ctx.Next()
	duration := time.Since(start)
	log.Printf("Request: %s %s %s %v", ctx.Method(), ctx.Path(), ctx.RemoteAddr(), duration)
}
