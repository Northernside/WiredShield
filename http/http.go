package http

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	_ "github.com/lib/pq"
)

type RequestLog struct {
	RequestTime          int64           `json:"request_time"`
	ClientIP             string          `json:"client_ip"`
	Method               string          `json:"method"`
	Host                 string          `json:"host"`
	Path                 string          `json:"path"`
	QueryParams          json.RawMessage `json:"query_params"`
	RequestHeaders       http.Header     `json:"request_headers"`
	ResponseHeaders      http.Header     `json:"response_headers"`
	ResponseStatusOrigin int             `json:"response_status_origin"`
	ResponseStatusProxy  int             `json:"response_status_proxy"`
	ResponseTime         int64           `json:"response_time"`
	TLSVersion           string          `json:"tls_version"`
	RequestSize          int64           `json:"request_size"`
	ResponseSize         int64           `json:"response_size"`
	RequestHTTPVersion   string          `json:"request_http_version"`
}

var (
	requestLogsChannel = make(chan *RequestLog, (1024^2)*8)
	clientPool         sync.Pool
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
		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		clientPool = sync.Pool{
			New: func() interface{} {
				return &http.Client{
					Transport: &http.Transport{
						TLSClientConfig: &tls.Config{
							InsecureSkipVerify: false,
						},
						MaxIdleConns:        200,
						MaxIdleConnsPerHost: 200,
						IdleConnTimeout:     30 * time.Second,
						DisableKeepAlives:   false,
						MaxConnsPerHost:     1000,
					},
					Timeout: 30 * time.Second,
				}
			},
		}

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		http.HandleFunc("/", ProxyHandler)

		go processRequestLogs()

		server := &http.Server{
			Addr: addr,
			TLSConfig: &tls.Config{
				MinVersion:               tls.VersionTLS12,
				MaxVersion:               tls.VersionTLS13,
				GetCertificate:           getCertificateForDomain,
				InsecureSkipVerify:       false,
				PreferServerCipherSuites: true,
			},
		}

		err := server.ListenAndServeTLS("", "")
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	timeStart := time.Now()
	targetRecords, err := db.GetRecords("A", r.Host)
	if err != nil || len(targetRecords) == 0 {
		http.Error(w, "could not resolve target", http.StatusBadGateway)
		return
	}

	targetRecord := targetRecords[0].(db.ARecord)
	targetURL := "http://" + targetRecord.IP + ":80" + r.URL.Path
	service.InfoLog(fmt.Sprintf("Proxying request to %s", targetURL))

	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "error creating request", http.StatusInternalServerError)
		return
	}

	req.Header = r.Header
	req.Header.Set("wired-origin-ip", getIp(r))
	req.Header.Set("host", r.Host)

	req.Host = r.Host

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "error contacting backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, value := range resp.Header {
		w.Header()[key] = value
	}

	w.Header().Set("server", "wiredshield")
	w.Header().Set("x-proxy-time", fmt.Sprintf("%dms", time.Since(timeStart).Milliseconds()))
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		service.ErrorLog(fmt.Sprintf("error streaming response body: %v", err))
		return
	}

	requestLogsChannel <- &RequestLog{
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             getIp(r),
		Method:               r.Method,
		Host:                 r.Host,
		Path:                 r.URL.Path,
		QueryParams:          queryParamString(r.URL.RawQuery),
		RequestHeaders:       r.Header,
		ResponseHeaders:      resp.Header,
		ResponseStatusOrigin: resp.StatusCode,
		ResponseStatusProxy:  http.StatusOK,
		ResponseTime:         time.Since(timeStart).Milliseconds(),
		TLSVersion:           tlsVersionToString(r.TLS.Version),
		RequestSize:          int64(r.ContentLength),
		ResponseSize:         int64(resp.ContentLength),
		RequestHTTPVersion:   r.Proto,
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

func collectAdditionalLogs(initialLog *RequestLog) []*RequestLog {
	logs := []*RequestLog{initialLog}

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

func batchInsertRequestLogs(logs []*RequestLog) error {
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
