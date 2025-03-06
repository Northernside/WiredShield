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
	"wiredshield/modules/threadsafe"
	errorpages "wiredshield/pages/error"
	"wiredshield/services"

	_ "github.com/lib/pq"
	"github.com/valyala/fasthttp"
)

type cacheEntry struct {
	status  int
	headers map[string]string
	body    []byte
}

type ptEntry struct {
	target string
	expiry time.Time
}

var (
	service          *services.Service
	certCache        sync.Map
	certLoadMutex    sync.RWMutex
	passthroughCache sync.Map
	blockedPage      string
	cacheInstances   = make(map[string]*threadsafe.Map[string, cacheEntry])
	allowedTypes     = []string{"html", "css", "js", "jpg", "jpeg", "gif", "png", "mp4", "webp", "webm", "mov", "mkv", "tiff", "pdf", "ico", "mp3", "apng", "svg", "aac", "flac"}
)

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

			logRequest(ctx, nil, time.Now(), 606, 0, 0, "")
		}
	}()

	// check if cacheInstances[domain] exists
	if _, ok := cacheInstances[string(ctx.Host())]; !ok {
		service.DebugLog(fmt.Sprintf("creating new threadsafe cache map for %s", ctx.Host()))
		cacheInstances[string(ctx.Host())] = threadsafe.NewMap[string, cacheEntry]()
	}

	cache := cacheInstances[string(ctx.Host())]

	var userIp = getIp(ctx)
	if userIp != env.GetEnv("WOOF_IP", "2.56.244.12") && userIp != env.GetEnv("MEOW_IP", "2.56.244.19") {
		if matched, ruleName := rules.MatchRules(ctx); matched {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(blockedPage)
			logRequest(ctx, nil, time.Now(), 606, 0, 0, ruleName)
			return
		}
	}

	var targetURL_UV bool = ctx.UserValue("targetURL") != nil
	if !targetURL_UV {
		found := loadPassthrough(ctx)
		if found {
			return
		}
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
	var cachable bool = false

	// check if url ends with . + ${html, css, js, jpg, jpeg, gif, png, mp4, webp, webm, mov, mkv, tiff, pdf, ico, mp3, apng, svg, aac, flac}
	for _, allowedType := range allowedTypes {
		if strings.HasSuffix(string(ctx.Path()), "."+allowedType) {
			// check if in cache
			if entry, found := cache.Get(string(ctx.Path())); found {
				service.DebugLog(fmt.Sprintf("%s cache hit", ctx.Path()))
				for key, value := range entry.headers {
					ctx.Response.Header.Set(key, value)
				}

				var tBody []byte = entry.body
				ctx.SetStatusCode(entry.status)
				ctx.SetBody(tBody)

				var cachedResponse *fasthttp.Response
				if tBody != nil {
					cachedResponse = &fasthttp.Response{}

					for key, value := range entry.headers {
						cachedResponse.Header.Set(key, value)
					}

					cachedResponse.SetStatusCode(entry.status)
					cachedResponse.SetBody(tBody)

					logRequest(ctx, cachedResponse, timeStart, entry.status, getRequestSize(ctx), getResponseSize(ctx, cachedResponse), "")
				}

				return
			} else {
				// cachable = true
				// service.DebugLog(fmt.Sprintf("%s cache miss", ctx.Path()))
			}
		}
	}

	var ctxPath = string(ctx.Path())
	if !strings.HasPrefix(ctxPath, "/") {
		ctxPath = "/" + ctxPath
	}

	var resolve bool = ctx.UserValue("resolve") != nil
	if !resolve {
		targetRecords, err := db.GetRecords("A", string(ctx.Host()))
		if err != nil || len(targetRecords) == 0 {
			errorPage := errorpages.ErrorPage{Code: 601, Message: errorpages.Error601}
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, nil, timeStart, 601, 0, 0, "")
			return
		}

		targetRecord := targetRecords[0].(*db.ARecord)
		if targetRecord.IP == env.GetEnv("WOOF_IP", "2.56.244.12") || targetRecord.IP == env.GetEnv("MEOW_IP", "2.56.244.19") {
			errorPage := errorpages.ErrorPage{Code: 604, Message: errorpages.Error604}
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			logRequest(ctx, nil, timeStart, 604, 0, 0, "")
			return
		}

		targetURL = fmt.Sprintf("http://%s:80%s", targetRecord.IP, ctxPath)
	} else {
		if ctx.UserValue("targetURL") == nil {
			errorPage := errorpages.ErrorPage{Code: 602, Message: errorpages.Error602}
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())

			logRequest(ctx, nil, timeStart, 602, 0, 0, "")
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
		logRequest(ctx, resp, timeStart, errorCode, 0, 0, "")
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
		logRequest(ctx, resp, timeStart, statusCode, getRequestSize(ctx), getResponseSize(ctx, resp), "")
		return
	}

	resp.Header.VisitAll(func(key, value []byte) {
		ctx.Response.Header.SetBytesKV(key, value)
	})

	ctx.Response.Header.Set("server", "wiredshield")
	ctx.Response.Header.Set("x-proxy-time", time.Since(timeStart).String())

	ctx.Response.Header.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	ctx.Response.Header.Set("Pragma", "no-cache")
	ctx.Response.Header.Set("Expires", "0")

	var body []byte = resp.Body()
	ctx.SetBody(body)

	if bodyStream := resp.BodyStream(); bodyStream != nil {
		_, err = io.Copy(ctx.Response.BodyWriter(), bodyStream)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("error streaming response body: %v", err))
			ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
			return
		}
	}

	if cachable {
		headers := make(map[string]string)
		ctx.Response.Header.VisitAll(func(key, value []byte) {
			headers[string(key)] = string(value)
		})

		entry := cacheEntry{status: resp.StatusCode(), headers: headers, body: body}
		service.DebugLog(fmt.Sprintf("cacheEntry: %v", entry))
		cache.Set(string(ctx.Path()), entry)
	}

	logRequest(ctx, resp, timeStart, resp.StatusCode(), getRequestSize(ctx), getResponseSize(ctx, resp), "")
}

func loadPassthrough(ctx *fasthttp.RequestCtx) bool {
	cacheKey := fmt.Sprintf("%s:%s", string(ctx.Host()), string(ctx.URI().Path()))
	if entry, ok := passthroughCache.Load(cacheKey); ok {
		if entry.(ptEntry).expiry.After(time.Now()) {
			ctx.SetUserValue("targetURL", entry.(ptEntry).target)
			ctx.SetUserValue("resolve", true)
			ctx.SetUserValue("passthrough", true)
			httpsProxyHandler(ctx)
			return true
		} else {
			passthroughCache.Delete(cacheKey)
		}
	}

	passthroughs, err := passthrough.GetAllPassthroughs()
	if err != nil {
		ctx.Error("Internal Server Error", fasthttp.StatusInternalServerError)
		return false
	}

	for _, passthrough := range passthroughs {
		if string(ctx.Host()) == passthrough.Domain && strings.HasPrefix(string(ctx.Path()), passthrough.Path) {
			// ctx.Path but minus passthrough.Path
			normalizedPath := string(ctx.Path())[len(passthrough.Path):]
			if !strings.HasPrefix(normalizedPath, "/") {
				normalizedPath = "/" + normalizedPath
			}

			target := fmt.Sprintf("http://%s:%d%s", passthrough.TargetAddr, passthrough.TargetPort, normalizedPath)

			entry := ptEntry{target: target, expiry: time.Now().Add(24 * time.Hour)}
			passthroughCache.Store(cacheKey, entry)

			ctx.SetUserValue("targetURL", target)
			ctx.SetUserValue("resolve", true)
			httpsProxyHandler(ctx)
			return true
		}
	}

	return false
}

func httpHandler(ctx *fasthttp.RequestCtx) {
	found := loadPassthrough(ctx)
	if found {
		return
	}

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
