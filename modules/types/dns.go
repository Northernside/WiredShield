package types

import "github.com/miekg/dns"

type RecordMetadata struct {
	ID        string `json:"id"`
	Protected bool   `json:"protected"`
	Geo       bool   `json:"geo"`
}

type DNSRecord struct {
	Record   dns.RR
	Metadata RecordMetadata
}
