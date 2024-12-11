package http

import (
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
)

func Prepare(_service *services.Service) func() {
	service = _service

	return func() {
		addr := "0.0.0.0:80"
		clientPool.New = func() interface{} {
			return &fasthttp.Client{
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
			}
		}

		port := env.GetEnv("PORT", "80")
		service.InfoLog(fmt.Sprintf("Starting proxy on :%s", port))

		go requestsHandler()
		service.InfoLog("Starting HTTP proxy on " + addr)
		service.OnlineSince = time.Now().Unix()
		err := fasthttp.ListenAndServe(fmt.Sprintf(":%s", port), ProxyHandler)
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func ProxyHandler(ctx *fasthttp.RequestCtx) {
	targetRecords, err := db.GetRecords("A", string(ctx.Host()))
	if err != nil || len(targetRecords) == 0 {
		ctx.Error("could not resolve target", fasthttp.StatusBadGateway)
		return
	}

	// convert to ARecord type
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
	ctx.SetStatusCode(resp.StatusCode())
	ctx.SetBody(resp.Body())

	requestsChannel <- req
}

func requestsHandler() {
	for range requestsChannel {
		*requestsMade++
	}
}
