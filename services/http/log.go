package http

import (
	"strings"
	"wired/modules/logger"
)

var blockedStrings = []string{
	"no certificate available",
	"connection refused",
	"HTTP request to an HTTPS server",
	"first record does not look like a TLS handshake",
	"client offered only unsupported versions",
	"no cipher suite supported",
	"client requested unsupported",
}

type errorFilter struct{}

// EOF, i/o timeout, connection reset by peer <- TODO: check if the error rate of those gets increased, if so, log warnings about potential issues
func (t *errorFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	for _, blocked := range blockedStrings {
		if strings.Contains(msg, blocked) {
			return len(p), nil
		}
	}

	logger.Print(msg)
	return len(p), nil
}
