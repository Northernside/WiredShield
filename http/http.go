package http

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

type RequestLog struct {
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
	requestLogsChannel = make(chan *RequestLog, (1024^2)*8)
	clientPool         sync.Pool
	service            *services.Service
	certCache          sync.Map
	dbConn             *sql.DB
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
	dbConn.SetMaxIdleConns(32)

	err = dbConn.Ping()
	if err != nil {
		panic(fmt.Sprintf("Failed to ping database: %v", err))
	}

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

		go processRequestLogs()

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
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             getIp(ctx),
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          queryParamString(string(ctx.QueryArgs().QueryString())),
		RequestHeaders:       json.RawMessage(reqHeaders),
		ResponseHeaders:      json.RawMessage(respHeaders),
		ResponseStatusOrigin: ctx.Response.StatusCode(),
		ResponseStatusProxy:  fasthttp.StatusOK,
		ResponseTime:         time.Since(timeStart).Milliseconds(),
		TLSVersion:           tlsVersionToString(ctx.TLSConnectionState().Version),
		RequestSize:          int64(ctx.Request.Header.Len()),
		ResponseSize:         int64(len(ctx.Response.Body())),
		RequestHTTPVersion:   string(ctx.Request.Header.Protocol()),
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

/*
	insertQuery := `INSERT INTO requests
		(request_time, client_ip, method, host, path, query_params, request_headers, response_headers, response_status_origin,
		response_status_proxy, response_time, tls_version, request_size, response_size, request_http_version)
		VALUES %s`
*/

func processRequestLogs() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logs := collectLogsFromChannel()

			if len(logs) > 0 {
				err := batchInsertRequestLogs(logs)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("Failed to insert request logs: %v", err))
				}
			}
		}
	}
}

func collectLogsFromChannel() []*RequestLog {
	logs := make([]*RequestLog, 0, 64)

	for {
		select {
		case log := <-requestLogsChannel:
			logs = append(logs, log)
			if len(logs) >= 64 {
				return logs
			}
		default:
			return logs
		}
	}
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

	start := time.Now()
	_, err := dbConn.Exec(query, values...)
	elapsed := time.Since(start)

	if err != nil {
		return fmt.Errorf("batch insert failed: %v", err)
	}

	service.InfoLog(fmt.Sprintf(
		"Batch inserted %d logs in %v",
		len(logs),
		elapsed,
	))

	return nil
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

func getIp(reqCtx *fasthttp.RequestCtx) string {
	addr := reqCtx.RemoteAddr()
	service.InfoLog("Client IP ddd: " + addr.String())
	ipAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return ""
	}

	return ipAddr.IP.String()
}
