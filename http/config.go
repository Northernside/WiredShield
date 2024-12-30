package wiredhttps

import (
	"crypto/tls"
	"sync"
	"time"
	"wiredshield/modules/env"

	"github.com/valyala/fasthttp"
)

var (
	server = &fasthttp.Server{
		Concurrency:   1024 ^ 2,
		Handler:       httpsProxyHandler,
		Name:          "wiredshield",
		MaxConnsPerIP: 1024 ^ 2,
		ReadTimeout:   5 * time.Second,
		ErrorHandler: func(ctx *fasthttp.RequestCtx, err error) {
			ctx.Error(err.Error(), 500)
		},
		LogAllErrors: false,
		Logger:       nil,
		TLSConfig: &tls.Config{
			NextProtos:               []string{"http/1.1"},
			MinVersion:               tls.VersionTLS10,
			MaxVersion:               tls.VersionTLS13,
			GetCertificate:           getCertificateForDomain,
			InsecureSkipVerify:       false,
			ClientCAs:                nil,
			PreferServerCipherSuites: true,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{
					NextProtos:               []string{"http/1.1"},
					MinVersion:               tls.VersionTLS10,
					MaxVersion:               tls.VersionTLS13,
					GetCertificate:           getCertificateForDomain,
					InsecureSkipVerify:       false,
					ClientCAs:                nil,
					PreferServerCipherSuites: true,
					CipherSuites: []uint16{
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					},
					CurvePreferences: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					},
				}, nil
			},
		},
	}
	clientPool = sync.Pool{
		New: func() interface{} {
			return &fasthttp.Client{
				ReadTimeout:     60 * time.Second,
				WriteTimeout:    60 * time.Second,
				MaxConnDuration: 60 * time.Second,
				MaxConnsPerHost: 1024 * 256,
				Dial: (&fasthttp.TCPDialer{
					Concurrency:      1024 * 256,
					DNSCacheDuration: 1 * time.Hour,
				}).Dial,
			}
		},
	}
	binding   = env.GetEnv("HTTP_BINDING", "")
	httpsAddr = binding + ":" + env.GetEnv("HTTP_PORT", "443")
	httpAddr  = binding + ":" + env.GetEnv("HTTP_REDIRECT_PORT", "80")
)
