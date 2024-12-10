package http

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"
)

var (
	requestsChannel = make(chan *http.Request)
	requestsMade    = new(uint64)
	clientPool      sync.Pool
	service         *services.Service
)

func Prepare(_service *services.Service) func() {
	service = _service

	return func() {
		addr := "0.0.0.0:80"
		clientPool.New = func() interface{} {
			return &http.Client{
				Timeout: 30 * time.Second,
			}
		}

		http.HandleFunc("/", ProxyHandler)
		port := env.GetEnv("PORT", "80")
		service.InfoLog(fmt.Sprintf("Starting proxy on :%s\n", port))

		go requestsHandler()
		service.InfoLog("Starting HTTP proxy on " + addr)
		service.OnlineSince = time.Now().Unix()
		err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
		if err != nil {
			service.FatalLog(err.Error())
		}
	}
}

func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	targetAddress, err := db.GetRecord("A", r.Host)
	if err != nil {
		http.Error(w, "could not resolve target", http.StatusBadGateway)
		return
	}

	targetURL := "http://" + targetAddress + r.URL.Path

	req, err := http.NewRequest(r.Method, targetURL+r.RequestURI, r.Body)
	if err != nil {
		http.Error(w, "could not create request", http.StatusInternalServerError)
		return
	}

	req.Header = r.Header
	req.Header.Set("wired-origin-ip", r.RemoteAddr)
	req.Header.Set("host", r.Host)

	client := clientPool.Get().(*http.Client)
	defer clientPool.Put(client)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "error contacting backend", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.Header().Set("server", "wiredshield")

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	requestsChannel <- req
}

func requestsHandler() {
	for _ = range requestsChannel {
		*requestsMade++
	}
}

func formatHost(host string) string {
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	return host
}
