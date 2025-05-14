package types

import (
	"time"

	"github.com/miekg/dns"
)

type SSLInfo struct {
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type RecordMetadata struct {
	Id        string `json:"id"`
	Protected bool   `json:"protected"`
	Geo       bool   `json:"geo"`
	IPCompat  bool
	SSLInfo   SSLInfo
}

type DNSRecord struct {
	RR       dns.RR
	Metadata RecordMetadata
}
