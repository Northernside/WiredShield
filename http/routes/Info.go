package routes

import (
	"crypto/tls"
	"fmt"
	"strings"
	"time"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

func Info(ctx *fasthttp.RequestCtx) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("h=%s\n", string(ctx.Request.Header.Peek("host"))))
	sb.WriteString(fmt.Sprintf("ip=%s\n", ctx.RemoteIP().String()))
	sb.WriteString(fmt.Sprintf("ts=%d\n", time.Now().Unix()))
	sb.WriteString(fmt.Sprintf("uag=%s\n", string(ctx.Request.Header.Peek("user-agent"))))
	sb.WriteString(fmt.Sprintf("colo=%s\n", strings.ToUpper(services.ClientName)))
	sb.WriteString(fmt.Sprintf("http=%s\n", string(ctx.Request.Header.Protocol())))
	sb.WriteString(fmt.Sprintf("loc=%s\n", "UNKNOWN"))
	sb.WriteString(fmt.Sprintf("tls=%s\n", tlsVersionToString(ctx.TLSConnectionState().Version)))

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(sb.String())
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
