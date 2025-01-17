package wiredhttps

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	errorpages "wiredshield/pages/error"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

var (
	service       *services.Service
	certCache     sync.Map
	certLoadMutex sync.RWMutex
)

func Prepare(_service *services.Service) func() {
	service = _service
	binding := env.GetEnv("HTTP_BINDING", "")
	httpsAddr := binding + ":" + env.GetEnv("HTTP_PORT", "443")
	httpAddr := binding + ":" + env.GetEnv("HTTP_REDIRECT_PORT", "80")

	return func() {
		// logging
		go processRequestLogs()

		// http redirect
		go func() {
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

		// https logic
		service.InfoLog("Starting HTTPS proxy on " + httpsAddr)
		service.OnlineSince = time.Now().Unix()
		ln, err := net.Listen("tcp", httpsAddr)
		if err != nil {
			service.FatalLog(fmt.Sprintf("Error creating listener: %v", err))
			return
		}

		tlsListener := tls.NewListener(ln, server.TLSConfig)
		err = server.Serve(tlsListener)
		if err != nil {
			service.FatalLog(fmt.Sprintf("Error serving: %v", err))
		}
	}
}

func httpsProxyHandler(ctx *fasthttp.RequestCtx) {
	defer func() {
		if err := recover(); err != nil {
			service.ErrorLog(fmt.Sprintf("recovered from panic in httpsProxyHandler: %v", err))
			ctx.Error("Internal Server Error (Backend Panic)", fasthttp.StatusInternalServerError)
		}
	}()

	// internal routes
	cleanedPath := strings.Split(string(ctx.Path()), "?")[0]
	cleanedPath = strings.Split(cleanedPath, "#")[0]

	if handler, exists := GetHandler(fmt.Sprintf("%s:%s", string(ctx.Method()), cleanedPath)); exists {
		handler(ctx)
		return
	}

	timeStart := time.Now()
	targetRecords, err := db.GetRecords("A", string(ctx.Host()))
	if err != nil || len(targetRecords) == 0 {
		// ctx.Error("could not resolve target", fasthttp.StatusBadGateway)
		errorPage := errorpages.ErrorPage{Code: 601, Message: errorpages.Error601}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)

		services.GetService("https").ErrorLog(err.Error())
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		logRequest(ctx, nil, timeStart, 601, 0, 0)
		return
	}

	if targetRecords[0].(*db.ARecord).IP == "45.157.11.82" || targetRecords[0].(*db.ARecord).IP == "85.117.241.142" {
		errorPage := errorpages.ErrorPage{Code: 604, Message: errorpages.Error604}
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		logRequest(ctx, nil, timeStart, 604, 0, 0)
		return
	}

	targetRecord := targetRecords[0].(*db.ARecord)
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

	timeout := 10 * time.Second
	err = client.DoTimeout(req, resp, timeout)
	if err != nil {
		if err == fasthttp.ErrTimeout {
			service.ErrorLog(fmt.Sprintf("timeout contacting backend (%s): %v", targetURL, err))

			errorPage := errorpages.ErrorPage{Code: 605, Message: errorpages.Error605}
			ctx.SetStatusCode(fasthttp.StatusGatewayTimeout)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, resp, timeStart, 605, 0, 0)
		} else {
			service.ErrorLog(fmt.Sprintf("error contacting backend (%s): %v", targetURL, err))

			errorPage := errorpages.ErrorPage{Code: 603, Message: errorpages.Error603}
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, resp, timeStart, 603, 0, 0)
		}

		return
	}

	switch statusCode := resp.StatusCode(); statusCode {
	// 301 & 308 -> permanent redirect
	// 302, 303, 307 -> temporary redirect
	case 301, 308, 302, 303, 307:
		location := resp.Header.Peek("Location")
		if len(location) == 0 {
			services.GetService("https").ErrorLog(err.Error())
			ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
			return
		}

		ctx.Response.Header.Set("Location", string(location))
		ctx.SetStatusCode(statusCode)
		logRequest(ctx, resp, timeStart, statusCode, requestSize, getResponseSize(ctx, resp))
		return
	}

	resp.Header.VisitAll(func(key, value []byte) {
		ctx.Response.Header.SetBytesKV(key, value)
	})

	ctx.Response.Header.Set("server", "wiredshield")
	ctx.Response.Header.Set("x-proxy-time", time.Since(timeStart).String())
	ctx.SetBody(resp.Body())

	if bodyStream := resp.BodyStream(); bodyStream != nil {
		_, err = io.Copy(ctx.Response.BodyWriter(), bodyStream)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("error streaming response body: %v", err))
			ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
			return
		}
	} else {
		ctx.SetBody(resp.Body())
	}

	logRequest(ctx, resp, timeStart, resp.StatusCode(), requestSize, getResponseSize(ctx, resp))
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}

	http.Redirect(w, r, target, http.StatusMovedPermanently)
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
	} else {
		if strings.Contains(err.Error(), "no such file or directory") {
			return &c, nil
		}
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
