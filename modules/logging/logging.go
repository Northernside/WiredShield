package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"wiredshield/modules/db"
)

type RequestLog struct {
	RequestTime          int64           `json:"request_time"`
	ClientIP             string          `json:"client_ip"`
	Method               string          `json:"method"`
	Host                 string          `json:"host"`
	Path                 string          `json:"path"`
	QueryParams          json.RawMessage `json:"query_params"`
	RequestHeaders       json.RawMessage `json:"request_headers"`
	ResponseHeaders      json.RawMessage `json:"response_headers"`
	ResponseStatusOrigin int             `json:"response_status_origin"`
	ResponseStatusProxy  int             `json:"response_status_proxy"`
	ResponseTime         int64           `json:"response_time"`
	TLSVersion           string          `json:"tls_version"`
	RequestSize          int64           `json:"request_size"`
	ResponseSize         int64           `json:"response_size"`
	RequestHTTPVersion   string          `json:"request_http_version"`
	ClientCountry        string          `json:"client_country"`
}

var (
	RequestLogsChannel = make(chan *RequestLog, (1024^2)*8)
)

func CollectAdditionalLogs(initialLog *RequestLog) []*RequestLog {
	logs := []*RequestLog{initialLog}

	for len(logs) < 128 {
		select {
		case log := <-RequestLogsChannel:
			logs = append(logs, log)
		default:
			return logs
		}
	}

	return logs
}

func BatchInsertRequestLogs(logs []*RequestLog) error {
	if len(logs) == 0 {
		return nil
	}

	conn, err := db.PsqlConn.Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %v", err)
	}
	defer conn.Release()

	transaction, err := conn.Begin(context.Background())
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer transaction.Rollback(context.Background())

	placeholders := make([]string, len(logs))
	values := make([]interface{}, 0, len(logs)*16)

	for i, log := range logs {
		placeholders[i] = fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			i*15+1, i*15+2, i*15+3, i*15+4, i*15+5, i*15+6, i*15+7, i*15+8,
			i*15+9, i*15+10, i*15+11, i*15+12, i*15+13, i*15+14, i*15+15, i*15+16,
		)
		values = append(values,
			log.RequestTime,
			log.ClientIP,
			log.Method,
			log.Host,
			log.Path,
			log.QueryParams,
			log.RequestHeaders,
			log.ResponseHeaders,
			log.ResponseStatusOrigin,
			log.ResponseStatusProxy,
			log.ResponseTime,
			log.TLSVersion,
			log.RequestSize,
			log.ResponseSize,
			log.RequestHTTPVersion,
			log.ClientCountry,
		)
	}

	query := fmt.Sprintf(`
        INSERT INTO requests (
            request_time, client_ip, method, host, path, query_params, 
            request_headers, response_headers, response_status_origin, 
            response_status_proxy, response_time, tls_version, 
            request_size, response_size, request_http_version,
			client_country
        ) VALUES %s
    `, strings.Join(placeholders, ","))

	_, err = transaction.Exec(context.Background(), query, values...)
	if err != nil {
		return fmt.Errorf("batch insert failed: %v", err)
	}

	return transaction.Commit(context.Background())
}
