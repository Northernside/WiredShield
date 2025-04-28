package http

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
	"wired/modules/logger"
)

var (
	certMap  = make(map[string]tls.Certificate)
	proxyMap = make(map[string]*httputil.ReverseProxy)

	tlsConfig = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(hello.ServerName)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			if cert, ok := certMap[host]; ok {
				return &cert, nil
			}

			return nil, fmt.Errorf("no certificate available for %s", host)
		},
	}
)

func Start() {
	loadTargets()
	initBackends()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		proxy, ok := proxyMap[host]
		if !ok {
			http.Error(w, "Invalid host", http.StatusNotFound)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	httpsServer := &http.Server{
		Addr:              "[::]:443",
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 13, // 8KB
	}

	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
			panic(fmt.Sprintf("Failed to start server: %v", err))
		}
	}()

	logger.Println("HTTPS reverse proxy started on port 443")

	select {}
}

func initBackends() {
	for host, addr := range hosts {
		host = strings.TrimSuffix(host, ".")
		certFile := fmt.Sprintf("certs/%s.crt", host)
		keyFile := fmt.Sprintf("certs/%s.key", host)
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			panic(fmt.Sprintf("Failed to load certificate for %s: %v", host, err))
		}

		certMap[host] = cert

		backendAddr := addr.String()
		target, _ := url.Parse(fmt.Sprintf("http://%s", backendAddr))
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{
			MaxIdleConns:          0,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		}

		proxyMap[host] = proxy
	}
}
