package http

import (
	"crypto/tls"
	"fmt"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var (
	requestsChannel = make(chan *fasthttp.Request)
	requestsMade    = new(uint64)
	clientPool      sync.Pool
	service         *services.Service
	certCache       sync.Map
)

func Prepare(_service *services.Service) func() {
	service = _service

	return func() {
		port := env.GetEnv("PORT", "443")
		addr := "0.0.0.0:" + port
		clientPool.New = func() interface{} {
			return &fasthttp.Client{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
		}

		service.InfoLog(fmt.Sprintf("Starting proxy on :%s", port))

		go requestsHandler()
		service.InfoLog("Starting HTTPS proxy on " + addr)
		service.OnlineSince = time.Now().Unix()

		tlsConfig := &tls.Config{
			GetCertificate: getCertificateForDomain,
		}

		server := &fasthttp.Server{
			Handler:          ProxyHandler,
			TLSConfig:        tlsConfig,
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

	requestsChannel <- req
}

func requestsHandler() {
	for range requestsChannel {
		*requestsMade++
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

	certPath := fmt.Sprintf("certs/%s.fullchain.crt", domain)
	keyPath := fmt.Sprintf("certs/%s.key", domain)

	service.InfoLog(fmt.Sprintf("Loading certificate for domain %s", domain))
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		service.ErrorLog(fmt.Sprintf("Failed to load certificate for domain %s: %v", domain, err))
		return nil, err
	}

	service.InfoLog(fmt.Sprintf("Certificate: %s", cert.Certificate[0]))

	certCache.Store(domain, &cert)
	return &cert, nil
}
