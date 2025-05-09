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
	ID         string `json:"id"`
	Protected  bool   `json:"protected"`
	Geo        bool   `json:"geo"`
	Artificial bool   `json:"artificial"`
	SSLInfo    SSLInfo
}

type DNSRecord struct {
	Record   dns.RR
	Metadata RecordMetadata
}
