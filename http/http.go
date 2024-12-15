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

var (
	requestsChannel = make(chan *fasthttp.RequestCtx, 1000)
	requestBuffer   = make([][]interface{}, 0, 1000)
	bufferLock      sync.Mutex
	certCache       sync.Map
	clientPool      sync.Pool
	service         *services.Service
	dbConn          *sql.DB
)

func Prepare(_service *services.Service) func() {
	service = _service

	var err error
	dbConn, err = sql.Open("postgres", fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", env.GetEnv("PSQL_USER", "wiredshield"), env.GetEnv("PSQL_PASSWORD", ""), env.GetEnv("PSQL_DB", "reverseproxy")))
	if err != nil {
		service.FatalLog(fmt.Sprintf("database connection failed: %v", err))
	}

	_, err = dbConn.Exec(`
	CREATE TABLE IF NOT EXISTS requests (
		id SERIAL PRIMARY KEY,
		request_time TIMESTAMPTZ,
		client_ip INET,
		method TEXT,
		host TEXT,
		path TEXT,
		query_params JSONB,
		request_headers JSONB,
		response_headers JSONB,
		response_status_origin SMALLINT,
		response_status_proxy SMALLINT,
		response_time INTERVAL,
		tls_version TEXT,
		request_size BIGINT,
		response_size BIGINT,
		request_http_version TEXT
	) `)
	if err != nil {
		service.FatalLog(fmt.Sprintf("Failed to ensure requests table exists: %v", err))
	}

	go processRequests()
	go flushRequestBuffer()

	clientPool.New = func() interface{} {
		return &fasthttp.Client{
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
	}

	return func() {
		port := env.GetEnv("HTTP_PORT", "443")
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + port

		service.InfoLog(fmt.Sprintf("Starting proxy on %s", addr))
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
	host := string(ctx.Host())
	var targetURL string
	if targetURL, found := certCache.Load(host); found {
		targetURL = targetURL.(string)
	} else {
		targetRecords, err := db.GetRecords("A", host)
		if err != nil || len(targetRecords) == 0 {
			ctx.Error(fmt.Sprintf("no records found for %s\ndebug: %v\ntargetRecords: %v", host, err, targetRecords), fasthttp.StatusNotFound)
			return
		}

		targetRecord := targetRecords[0].(db.ARecord)
		targetURL := "http://" + targetRecord.IP + string(ctx.Path())
		certCache.Store(host, targetURL)
		time.AfterFunc(1*time.Hour, func() {
			certCache.Delete(host)
		})
	}

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

	err := client.Do(req, resp)
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

	select {
	case requestsChannel <- ctx:
	default:
	}
}

func buildRequestRow(ctx *fasthttp.RequestCtx, resp *fasthttp.Response, responseTime time.Duration) []interface{} {
	requestHeaders := make(map[string]string)
	ctx.Request.Header.VisitAll(func(k, v []byte) {
		requestHeaders[string(k)] = string(v)
	})

	responseHeaders := make(map[string]string)
	resp.Header.VisitAll(func(k, v []byte) {
		responseHeaders[string(k)] = string(v)
	})

	queryParams := make(map[string]string)
	ctx.QueryArgs().VisitAll(func(k, v []byte) {
		queryParams[string(k)] = string(v)
	})

	requestSize := len(ctx.Request.Body())
	responseSize := len(resp.Body())
	tlsVersion := "unknown"
	if tlsConnState := ctx.TLSConnectionState(); tlsConnState != nil {
		switch tlsConnState.Version {
		case tls.VersionTLS10:
			tlsVersion = "TLS 1.0"
		case tls.VersionTLS11:
			tlsVersion = "TLS 1.1"
		case tls.VersionTLS12:
			tlsVersion = "TLS 1.2"
		case tls.VersionTLS13:
			tlsVersion = "TLS 1.3"
		}
	}

	return []interface{}{
		time.Now().UTC(),
		ctx.RemoteAddr().String(),
		string(ctx.Method()),
		string(ctx.Host()),
		string(ctx.Path()),
		jsonMapToJSON(queryParams),
		jsonMapToJSON(requestHeaders),
		jsonMapToJSON(responseHeaders),
		resp.StatusCode(),
		ctx.Response.StatusCode(),
		responseTime,
		tlsVersion,
		requestSize,
		responseSize,
		string(ctx.Request.Header.Protocol()),
	}
}

func processRequests() {
	for req := range requestsChannel {
		timeStart := time.Now()

		if req != nil {
			resp := fasthttp.AcquireResponse()
			bufferLock.Lock()
			requestBuffer = append(requestBuffer, buildRequestRow(req, resp, time.Since(timeStart)))
			bufferLock.Unlock()
			fasthttp.ReleaseResponse(resp)
		} else {
			service.ErrorLog("nil request received")
		}
	}
}

func flushRequestBuffer() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		bufferLock.Lock()
		if len(requestBuffer) > 0 {
			flushBuffer := requestBuffer
			requestBuffer = make([][]interface{}, 0, 1000)
			bufferLock.Unlock()

			tx, err := dbConn.Begin()
			if err != nil {
				service.ErrorLog(fmt.Sprintf("Failed to start transaction: %v", err))
				continue
			}

			stmt, err := tx.Prepare(`
			COPY requests (request_time, client_ip, method, host, path, query_params, request_headers, response_headers, response_status_origin, response_status_proxy, response_time, tls_version, request_size, response_size, request_http_version) 
			FROM STDIN`)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("Failed to prepare COPY statement: %v", err))
				tx.Rollback()
				continue
			}

			for _, row := range flushBuffer {
				_, err := stmt.Exec(row...)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("Failed to execute COPY statement: %v", err))
					tx.Rollback()
					break
				}
			}

			if err := tx.Commit(); err != nil {
				service.ErrorLog(fmt.Sprintf("Failed to commit transaction: %v", err))
			}
		} else {
			bufferLock.Unlock()
		}
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

	service.InfoLog("loading certificate for " + domain)
	c, err := tls.LoadX509KeyPair(fmt.Sprintf("certs/%s.crt", domain), fmt.Sprintf("certs/%s.key", domain))
	if err == nil {
		certCache.Store(domain, &c)
	}

	return &c, err
}

func jsonMapToJSON(data map[string]string) []byte {
	result, _ := json.Marshal(data)
	return result
}
