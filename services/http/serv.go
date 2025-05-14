package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"wired/modules/env"
	"wired/modules/exif"
	"wired/modules/logger"
	"wired/modules/pages"
	"wired/services/dns"
	http_internal "wired/services/http/internal"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type SSLEntry struct {
	RecordId string
	Cert     *tls.Certificate
}

var (
	CertMap            = make(map[string]*SSLEntry)
	CertMapLock        = &sync.RWMutex{}
	proxyMap           = make(map[string]*httputil.ReverseProxy)
	httpRedirectServer *http.Server
	httpsServer        *http.Server
	https3Server       *http3.Server

	tlsConfig = &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(hello.ServerName)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}

			if SSLEntry, ok := CertMap[host]; ok {
				return SSLEntry.Cert, nil
			}

			return nil, fmt.Errorf("no certificate available for %s", host)
		},
		Certificates: []tls.Certificate{},
		NextProtos: []string{
			"h3",
			"h2",
			"http/1.1",
		},
	}
)

func Start(ctx context.Context) {
	http_internal.PostStart()
	loadProtectedHosts()
	initReverseProxies()

	rootHosts := strings.Split(env.GetEnv("ROOT_HOSTS", ""), ",")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor < 3 {
			err := https3Server.SetQUICHeaders(w.Header())
			if err != nil {
				logger.Println("Error setting QUIC headers:", err)
			}
		}

		if strings.HasPrefix(r.URL.Path, "/dash") && strings.Split(env.GetEnv("ROOT_HOSTS", ""), ",") != nil {
			http_internal.HandleWiredRequest(w, r)
			return
		}

		if slices.Contains(rootHosts, strings.ToLower(r.Host)) {
			http.ServeFile(w, r, env.GetEnv("PUBLIC_DIR", "")+"/website/index.html")
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

	httpsServer = &http.Server{
		Addr:              "[::]:443",
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 13, // 8KB
		ErrorLog:          log.New(&errorFilter{}, "", 0),
	}

	https3Server = &http3.Server{
		Addr:            "[::]:443",
		Handler:         handler,
		TLSConfig:       tlsConfig,
		EnableDatagrams: true,
		IdleTimeout:     90 * time.Second,
		MaxHeaderBytes:  1 << 13, // 8KB
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        90 * time.Second,
			MaxIncomingStreams:    0,
			MaxIncomingUniStreams: 0,
			HandshakeIdleTimeout:  2 * time.Second,
		},
	}

	httpRedirectServer = &http.Server{
		Addr: "[::]:80",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.String(), http.StatusMovedPermanently)
		}),
		ReadTimeout:       2 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 13, // 8KB
		ErrorLog:          log.New(&errorFilter{}, "", 0),
	}

	go func() {
		if err := httpRedirectServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTP redirect server: ", err)
		}
	}()

	logger.Println("HTTP  (http1.1 / h2) redirect server started on port 80")

	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTPS (http1.1 / h2) server: ", err)
		}
	}()

	logger.Println("HTTPS (http1.1 / h2) reverse proxy started on port 443")

	go func() {
		if err := https3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start HTTPS (h3) server: ", err)
		}
	}()

	logger.Println("HTTPS (h3) reverse proxy started on port 443")

	<-ctx.Done()
	logger.Println("Shutting down HTTP servers...")
	if err := httpRedirectServer.Shutdown(context.Background()); err != nil {
		logger.Println("Error shutting down HTTP redirect server:", err)
	}

	if err := httpsServer.Shutdown(context.Background()); err != nil {
		logger.Println("Error shutting down HTTPS server:", err)
	}

	if err := https3Server.Shutdown(context.Background()); err != nil {
		logger.Println("Error shutting down HTTPS 3 server:", err)
	}

	logger.Println("HTTP(S) servers shut down successfully")
}

func initReverseProxies() {
	sanCerts := make(map[string]*tls.Certificate)
	sanFiles, _ := filepath.Glob("certs/san_*.crt")
	for _, certFile := range sanFiles {
		base := strings.TrimSuffix(filepath.Base(certFile), ".crt")
		keyFile := filepath.Join("certs", base+".key")

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			logger.Printf("Error loading SAN certificate %s: %v", base, err)
			continue
		}

		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}

		if cert.Leaf != nil {
			for _, dnsName := range cert.Leaf.DNSNames {
				sanCerts[strings.ToLower(dnsName)] = &cert
			}
		}

		tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
	}

	for host, backendInfo := range protectedHosts {
		normalizedHost := strings.ToLower(strings.TrimSuffix(host, "."))
		var cert *tls.Certificate

		if sanCert, exists := sanCerts[normalizedHost]; exists {
			cert = sanCert
		} else {
			certFile := fmt.Sprintf("certs/%s.crt", normalizedHost)
			keyFile := fmt.Sprintf("certs/%s.key", normalizedHost)
			certValue, err := tls.LoadX509KeyPair(certFile, keyFile)
			cert = &certValue
			if err != nil {
				logger.Fatal(fmt.Sprintf("Error loading certificate for %s: %v", normalizedHost, err))
			}
		}

		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
		}

		CertMap[normalizedHost] = &SSLEntry{
			RecordId: backendInfo.recordId,
			Cert:     cert,
		}

		backendAddr := backendInfo.addr.String()
		target, _ := url.Parse(fmt.Sprintf("http://%s", backendAddr))
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorLog = log.New(&errorFilter{}, "", 0)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Println("Error in reverse proxy: ", err)
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(502)
			w.Write(pages.ErrorPages[502].Html)
		}
		proxy.ModifyResponse = func(resp *http.Response) error {
			if resp.Request.Method == http.MethodHead || resp.Body == nil {
				return nil
			}

			resp.Header.Set("server", "wired")
			resp.Header.Set("wired-request-id", "-")
			resp.Header.Set("wired-http-version", resp.Request.Proto)

			contentType := resp.Header.Get("Content-Type")
			if contentType != "image/jpeg" && contentType != "image/png" {
				return nil
			}

			originalBody := resp.Body
			pr, pw := io.Pipe()
			resp.Body = pr

			resp.Header.Del("Content-Length")
			resp.Header.Del("Content-Encoding")
			resp.ContentLength = -1

			go func() {
				defer pw.Close()

				switch {
				case strings.HasPrefix(contentType, "image/jpeg"):
					err := exif.CleanJPEG(originalBody, pw)
					if err != nil {
						pw.CloseWithError(err)
					}
				case strings.HasPrefix(contentType, "image/png"):
					err := exif.CleanPNG(originalBody, pw)
					if err != nil {
						pw.CloseWithError(err)
					}
				default:
					io.Copy(pw, originalBody)
				}
			}()

			return nil
		}
		proxy.Transport = &http.Transport{
			MaxIdleConns:          0,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			DisableKeepAlives:     false,
			ForceAttemptHTTP2:     true,
			MaxConnsPerHost:       0,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		}

		proxyMap[normalizedHost] = proxy

		indexedRecord := dns.ZoneIndexId[backendInfo.recordId]
		if indexedRecord == nil {
			logger.Println("Record not found for host: ", host)
			continue
		}

		mutex, ok := dns.ZoneFileMutexes[indexedRecord.Domain]
		if ok {
			mutex.Lock()
			defer mutex.Unlock()
		}

		indexedRecord.Record.Metadata.SSLInfo.IssuedAt = cert.Leaf.NotBefore
		indexedRecord.Record.Metadata.SSLInfo.ExpiresAt = cert.Leaf.NotAfter
	}
}
