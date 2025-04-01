package event_data

import "github.com/miekg/dns"

type AddRecordData struct {
	Record dns.RR
}
