package psql_data

import (
	"encoding/json"
)

type HTTPRequestLog struct {
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

type DNSRequestLog struct {
	QueryTime     int64  `json:"query_time"`
	ClientIP      string `json:"client_ip"`
	QueryName     string `json:"query_name"`
	QueryType     string `json:"query_type"`
	QueryClass    string `json:"query_class"`
	ResponseCode  string `json:"response_code"`
	ResponseTime  int64  `json:"response_time"`
	IsSuccessful  bool   `json:"is_successful"`
	ClientCountry string `json:"client_country"`
}
