package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"wired/modules/logger"
	"wired/modules/types"
	"wired/services/dns"
)

var (
	CertMap     = make(map[string]tls.Certificate)
	CertMapLock = &sync.RWMutex{}
	proxyMap    = make(map[string]*httputil.ReverseProxy)

	tlsConfig = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(hello.ServerName)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			if cert, ok := CertMap[host]; ok {
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
		if strings.HasPrefix(r.URL.Path, "/.wired/") {
			handleWiredRequest(w, r)
			return
		}

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
		ErrorLog:          log.New(&errorFilter{}, "", 0),
	}

	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
			panic(fmt.Sprintf("Failed to start server: %v", err))
		}
	}()

	logger.Println("HTTPS reverse proxy started on port 443")

	select {}
}

func handleWiredRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Handling Wired path: %s", r.URL.Path)
}

func initBackends() {
	sanCerts := make(map[string]tls.Certificate)
	sanFiles, _ := filepath.Glob("certs/san_*.crt")
	for _, certFile := range sanFiles {
		base := strings.TrimSuffix(filepath.Base(certFile), ".crt")
		keyFile := filepath.Join("certs", base+".key")

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("Error loading SAN certificate %s: %v", base, err)
			continue
		}

		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}

		if cert.Leaf != nil {
			for _, dnsName := range cert.Leaf.DNSNames {
				sanCerts[strings.ToLower(dnsName)] = cert
			}
		}
	}

	for host, addr := range hosts {
		normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
		var cert tls.Certificate
		var err error

		if sanCert, exists := sanCerts[normalizedHost]; exists {
			cert = sanCert
		} else {
			certFile := fmt.Sprintf("certs/%s.crt", normalizedHost)
			keyFile := fmt.Sprintf("certs/%s.key", normalizedHost)
			cert, err = tls.LoadX509KeyPair(certFile, keyFile)
			if err != nil {
				panic(fmt.Sprintf("Failed to load certificate for %s: %v", host, err))
			}
		}

		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}

		CertMap[normalizedHost] = cert

		backendAddr := addr.String()
		target, _ := url.Parse(fmt.Sprintf("http://%s", backendAddr))
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorLog = log.New(&errorFilter{}, "", 0)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Println("Error in reverse proxy:", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		}
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

		proxyMap[normalizedHost] = proxy

		// overwrite .Metadata.SSLInfo
		dns.ZonesMux.Lock()
		for i, record := range dns.Zones[normalizedHost+"."] {
			record.Metadata.SSLInfo = types.SSLInfo{
				IssuedAt:  cert.Leaf.NotBefore,
				ExpiresAt: cert.Leaf.NotAfter,
			}

			dns.Zones[normalizedHost+"."][i] = record
		}
		dns.ZonesMux.Unlock()
	}
}
