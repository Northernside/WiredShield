package http

import (
	"bytes"
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

	// Log info
	fmt.Printf("Loading certificate for domain %s\n", domain)

	c, err := tls.LoadX509KeyPair(fmt.Sprintf("certs/%s.crt", domain), fmt.Sprintf("certs/%s.key", domain))
	if err == nil {
		certCache.Store(domain, &c)
	}
	return &c, err
}

func cleanCertificateData(certData []byte) []byte {
	certData = bytes.TrimSpace(certData)
	if !bytes.HasPrefix(certData, []byte("-----BEGIN CERTIFICATE-----")) {
		service.ErrorLog("Certificate PEM data does not start with BEGIN CERTIFICATE")
		return nil
	}

	endCertIdx := bytes.LastIndex(certData, []byte("-----END CERTIFICATE-----"))
	if endCertIdx == -1 {
		service.ErrorLog("No END CERTIFICATE found in PEM data")
		return nil
	}

	return certData[:endCertIdx+len("-----END CERTIFICATE-----")]
}
