package wiredhttps

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/db/passthrough"
	"wiredshield/modules/env"
	"wiredshield/modules/rules"
	errorpages "wiredshield/pages/error"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

var (
	service          *services.Service
	certCache        sync.Map
	certLoadMutex    sync.RWMutex
	passthroughCache sync.Map
	blockedPage      string
)

type ptEntry struct {
	target string
	expiry time.Time
}

func Prepare(_service *services.Service) func() {
	service = _service
	binding := env.GetEnv("HTTP_BINDING", "")
	httpsAddr := binding + ":" + env.GetEnv("HTTP_PORT", "443")
	httpAddr := binding + ":" + env.GetEnv("HTTP_REDIRECT_PORT", "80")

	return func() {
		_page := errorpages.ErrorPage{Code: 403, Message: errorpages.Error403}
		blockedPage = _page.ToHTML()

		// logging
		go processRequestLogs()

		// http redirect
		go func() {
			service.InfoLog("Starting HTTP proxy on " + httpAddr)
			err := fasthttp.ListenAndServe(httpAddr, httpHandler)
			if err != nil {
				service.FatalLog(fmt.Sprintf("Error starting HTTP proxy: %v", err))
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

			var msgs []string = errorpages.Error606
			msgs = append(msgs, fmt.Sprintf("%v", err))

			errorPage := errorpages.ErrorPage{Code: 606, Message: msgs}
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())

			logRequest(ctx, nil, time.Now(), 606, 0, 0)
		}
	}()

	var userIp = getIp(ctx)
	if userIp != "85.117.241.142" && userIp != "45.157.11.82" {
		if rules.MatchRules(ctx) {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(blockedPage)
			return
		}
	}
	var targetURL_UV bool = ctx.UserValue("targetURL") != nil
	if !targetURL_UV {
		loadPassthrough(ctx)
	}

	// internal routes
	cleanedPath := string(ctx.Path())
	if idx := strings.IndexByte(cleanedPath, '?'); idx != -1 {
		cleanedPath = cleanedPath[:idx]
	}

	if idx := strings.IndexByte(cleanedPath, '#'); idx != -1 {
		cleanedPath = cleanedPath[:idx]
	}

	if handler, exists := GetHandler(fmt.Sprintf("%s:%s", string(ctx.Method()), cleanedPath)); exists {
		handler(ctx)
		return
	}

	timeStart := time.Now()
	var targetURL string
	var resolve bool = ctx.UserValue("resolve") != nil
	if !resolve {
		targetRecords, err := db.GetRecords("A", string(ctx.Host()))
		if err != nil || len(targetRecords) == 0 {
			errorPage := errorpages.ErrorPage{Code: 601, Message: errorpages.Error601}
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, nil, timeStart, 601, 0, 0)
			return
		}

		targetRecord := targetRecords[0].(*db.ARecord)
		if targetRecord.IP == "45.157.11.82" || targetRecord.IP == "85.117.241.142" {
			errorPage := errorpages.ErrorPage{Code: 604, Message: errorpages.Error604}
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, nil, timeStart, 604, 0, 0)
			return
		}

		targetURL = fmt.Sprintf("http://%s:80%s", targetRecord.IP, ctx.Path())
	} else {
		if ctx.UserValue("targetURL") == nil {
			errorPage := errorpages.ErrorPage{Code: 602, Message: errorpages.Error602}
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())

			logRequest(ctx, nil, timeStart, 602, 0, 0)
			return
		}

		targetURL = ctx.UserValue("targetURL").(string)
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.Header.SetBytesKV([]byte("host"), ctx.Host())
	req.Header.SetBytesKV([]byte("wired-origin-ip"), []byte(userIp))
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
	err := client.DoTimeout(req, resp, timeout)
	if err != nil {
		var errorCode int
		var message []string

		if err != fasthttp.ErrTimeout {
			errorCode = fasthttp.StatusBadGateway
			service.ErrorLog(fmt.Sprintf("error fetching target URL %s %s %s %v", targetURL, ctx.Host(), ctx.Path(), err))
			message = errorpages.Error603
		} else {
			errorCode = fasthttp.StatusGatewayTimeout
			message = errorpages.Error605
		}

		errorPage := errorpages.ErrorPage{Code: errorCode, Message: message}
		ctx.SetStatusCode(errorCode)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		logRequest(ctx, resp, timeStart, errorCode, 0, 0)
		return
	}

	switch statusCode := resp.StatusCode(); statusCode {
	// 301 & 308 -> permanent redirect
	// 302, 303, 307 -> temporary redirect
	case 301, 308, 302, 303, 307:
		location := resp.Header.Peek("Location")
		if len(location) == 0 {
			ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
			return
		}

		ctx.Response.Header.Set("Location", string(location))
		ctx.SetStatusCode(statusCode)
		logRequest(ctx, resp, timeStart, statusCode, getRequestSize(ctx), getResponseSize(ctx, resp))
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
	}

	logRequest(ctx, resp, timeStart, resp.StatusCode(), getRequestSize(ctx), getResponseSize(ctx, resp))
}

func loadPassthrough(ctx *fasthttp.RequestCtx) {
	cacheKey := fmt.Sprintf("%s:%s", string(ctx.Host()), string(ctx.Path()))
	if entry, ok := passthroughCache.Load(cacheKey); ok {
		if entry.(ptEntry).expiry.After(time.Now()) {
			service.InfoLog(fmt.Sprint("%s%s - %s", ctx.Host(), ctx.Path(), entry.(ptEntry).target))
			ctx.SetUserValue("targetURL", entry.(ptEntry).target)
			ctx.SetUserValue("resolve", true)
			ctx.SetUserValue("passthrough", true)
			return
		} else {
			passthroughCache.Delete(cacheKey)
		}
	}

	passthroughs, err := passthrough.GetAllPassthroughs()
	if err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return
	}

	for _, passthrough := range passthroughs {
		if string(ctx.Host()) == passthrough.Domain && strings.HasPrefix(string(ctx.Path()), passthrough.Path) {
			// ctx.Path but minus passthrough.Path
			normalizedPath := string(ctx.Path())[len(passthrough.Path):]
			target := fmt.Sprintf("http://%s:%d%s", passthrough.TargetAddr, passthrough.TargetPort, normalizedPath)

			entry := ptEntry{target: target, expiry: time.Now().Add(24 * time.Hour)}
			passthroughCache.Store(cacheKey, entry)

			ctx.SetUserValue("targetURL", target)
			ctx.SetUserValue("resolve", true)
			httpsProxyHandler(ctx)
			return
		}
	}
}

func httpHandler(ctx *fasthttp.RequestCtx) {
	loadPassthrough(ctx)

	target := "https://" + string(ctx.Host()) + string(ctx.Path())
	if len(ctx.URI().QueryString()) > 0 {
		target += "?" + string(ctx.URI().QueryString())
	}

	ctx.Redirect(target, fasthttp.StatusMovedPermanently)
}

func getCertificateForDomain(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		return nil, fmt.Errorf("no SNI provided by client")
	}

	cert, ok := certCache.Load(domain)
	if ok {
		return cert.(*tls.Certificate), nil
	}

	certLoadMutex.Lock()
	defer certLoadMutex.Unlock()

	cert, ok = certCache.Load(domain)
	if ok {
		return cert.(*tls.Certificate), nil
	}

	c, err := tls.LoadX509KeyPair(fmt.Sprintf("certs/%s.crt", domain), fmt.Sprintf("certs/%s.key", domain))
	if err == nil {
		certCache.Store(domain, &c)
	}

	return &c, err
}

func getIp(reqCtx *fasthttp.RequestCtx) string {
	if tcpAddr, ok := reqCtx.RemoteAddr().(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}

	return ""
}
