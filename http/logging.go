package wiredhttps

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"wiredshield/modules/logging"
	"wiredshield/modules/whois"

	"github.com/valyala/fasthttp"
)

const maxRetries = 3
const retryInterval = 5 * time.Minute

// both methods still inaccurate, will fix at a later time
func getRequestSize(ctx *fasthttp.RequestCtx) int64 {
	totalSize := int64(0)
	totalSize += int64(len(ctx.Method()))
	url := ctx.URI().String()
	totalSize += int64(len(url))

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		totalSize += int64(len(key) + len(value))
	})

	totalSize += int64(len(ctx.Request.Body()))

	return totalSize
}

func getResponseSize(ctx *fasthttp.RequestCtx, resp *fasthttp.Response) int64 {
	totalSize := int64(0)
	totalSize += int64(len(fmt.Sprintf("%d", resp.StatusCode())))
	resp.Header.VisitAll(func(key, value []byte) {
		totalSize += int64(len(key) + len(value))
	})

	totalSize += int64(len(resp.Body()))

	return totalSize
}

func getCountryWithRetry(ip string) (string, error) {
	for attempt := 1; attempt <= maxRetries; attempt++ {
		country, err := whois.GetCountry(ip)
		if err == nil {
			return country, nil
		}

		if strings.Contains(err.Error(), "ARIN: no NET-... found in WHOIS response") {
			if attempt < maxRetries {
				service.ErrorLog(fmt.Sprintf("Retrying to fetch country for IP %s due to error: %v (attempt %d)", ip, err, attempt))
				time.Sleep(retryInterval)
				continue
			} else {
				service.ErrorLog(fmt.Sprintf("Failed to fetch country for IP %s after %d attempts: %v", ip, maxRetries, err))
				return "", err
			}
		}

		// return errors unrelated to "ARIN: no NET-..." instantly
		return "", err
	}

	return "", errors.New("unknown error occurred while fetching country")
}

func logRequest(ctx *fasthttp.RequestCtx, resp *fasthttp.Response, timeStart time.Time, internalCode int, requestSize, responseSize int64) {
	reqHeadersMap := make(map[string]string)
	ctx.Request.Header.VisitAll(func(key, value []byte) {
		reqHeadersMap[string(key)] = string(value)
	})

	reqHeaders, _ := json.Marshal(reqHeadersMap)

	respHeadersMap := make(map[string]string)
	ctx.Response.Header.VisitAll(func(key, value []byte) {
		respHeadersMap[string(key)] = string(value)
	})

	respHeaders, _ := json.Marshal(respHeadersMap)

	responseStatusOrigin := 0
	if resp != nil {
		responseStatusOrigin = resp.StatusCode()
	}

	ip := getIp(ctx)
	country, err := getCountryWithRetry(ip)
	if err != nil {
		service.ErrorLog(fmt.Sprintf("final failure to get country for IP %s: %v", ip, err))
		country = "Unknown"
	}

	logging.RequestLogsChannel <- &logging.HTTPRequestLog{
		RequestTime:          timeStart.UnixMilli(),
		ClientIP:             ip,
		Method:               string(ctx.Method()),
		Host:                 string(ctx.Host()),
		Path:                 string(ctx.Path()),
		QueryParams:          queryParamString(string(ctx.QueryArgs().String())),
		RequestHeaders:       json.RawMessage(reqHeaders),
		ResponseHeaders:      json.RawMessage(respHeaders),
		ResponseStatusOrigin: responseStatusOrigin,
		ResponseStatusProxy: func() int {
			if internalCode != 0 {
				return internalCode
			}

			return resp.StatusCode()
		}(),
		ResponseTime:       time.Since(timeStart).Milliseconds(),
		TLSVersion:         tlsVersionToString(ctx.TLSConnectionState().Version),
		RequestSize:        requestSize,
		ResponseSize:       responseSize,
		RequestHTTPVersion: string(ctx.Request.Header.Protocol()),
		ClientCountry:      country,
	}
}

type QueryParams map[string]string

func queryParamString(query string) json.RawMessage {
	params := make(QueryParams)
	for _, pair := range strings.Split(query, "&") {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			continue
		}

		params[parts[0]] = parts[1]
	}

	data, _ := json.Marshal(params)
	return data
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

func processRequestLogs() {
	logWorkers := 512
	for i := 0; i < logWorkers; i++ {
		go func() {
			for log := range logging.RequestLogsChannel {
				logs := log.CollectAdditionalLogs()
				if len(logs) > 0 {
					if err := log.BatchInsert(logs); err != nil {
						service.ErrorLog(fmt.Sprintf("Failed to insert logs: %v", err))
					}
				}
			}
		}()
	}
}
