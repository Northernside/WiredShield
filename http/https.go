package wiredhttps

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/http/routes"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/modules/logging"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

var (
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

	service       *services.Service
	certCache     sync.Map
	certLoadMutex sync.RWMutex
)

func init() {
	env.LoadEnvFile()
	time.Sleep(500 * time.Millisecond)
}

func Prepare(_service *services.Service) func() {
	service = _service

	return func() {
		binding := env.GetEnv("HTTP_BINDING", "0.0.0.0")
		addr := binding + ":" + env.GetEnv("HTTP_PORT", "443")

		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		server := &fasthttp.Server{
			Concurrency:   1024 * 256,
			Handler:       proxyHandler,
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

func proxyHandler(ctx *fasthttp.RequestCtx) {
	defer func() {
		if err := recover(); err != nil {
			service.ErrorLog(fmt.Sprintf("recovered from panic in proxyHandler: %v", err))
			ctx.Error("Internal Server Error (Backend Panic)", fasthttp.StatusInternalServerError)
		}
	}()

	if strings.HasPrefix(string(ctx.Path()), "/.wiredshield/") {
		handleWiredShieldEndpoints(ctx)
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
	req.Header.Set("Connection", "keep-alive")
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
		service.ErrorLog(fmt.Sprintf("error contacting backend: %v", err))
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

func handleWiredShieldEndpoints(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/.wiredshield/proxy-auth":
		routes.ProxyAuth(ctx)
		return
	case "/.wiredshield/info":
		routes.Info(ctx)
		return
	default:
		ctx.Error("not found", fasthttp.StatusNotFound)
	}
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

	responseStatusOrigin := 0
	if resp != nil {
		responseStatusOrigin = resp.StatusCode()
	}

	logging.RequestLogsChannel <- &logging.RequestLog{
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             getIp(ctx),
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          queryParamString(string(ctx.QueryArgs().String())),
		RequestHeaders:       json.RawMessage(reqHeaders),
		ResponseHeaders:      json.RawMessage(respHeaders),
		ResponseStatusOrigin: responseStatusOrigin,
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
			for log := range logging.RequestLogsChannel {
				logs := logging.CollectAdditionalLogs(log)
				if len(logs) > 0 {
					if err := logging.BatchInsertRequestLogs(logs); err != nil {
						service.ErrorLog(fmt.Sprintf("Failed to insert logs: %v", err))
					}
				}
			}
		}()
	}
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
