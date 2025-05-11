package http

import (
	"net"
	wired_dns "wired/services/dns"

	"github.com/miekg/dns"
)

type backendInfo struct {
	recordId string
	addr     net.Addr
}

var (
	hosts = make(map[string]backendInfo)
)

func loadTargets() {
	zones := wired_dns.ListRecords()

	for _, zone := range zones {
		for _, record := range zone {
			if record.Metadata.Protected {
				switch r := record.Record.(type) {
				case *dns.A:
					ip := net.ParseIP(r.A.String())
					if ip != nil {
						addr := &net.TCPAddr{
							IP:   ip,
							Port: 80,
						}

						hosts[r.Header().Name] = backendInfo{
							recordId: record.Metadata.ID,
							addr:     addr,
						}
					}
				case *dns.AAAA:
					ip := net.ParseIP(r.AAAA.String())
					if ip != nil {
						addr := &net.TCPAddr{
							IP:   ip,
							Port: 80,
						}

						hosts[r.Header().Name] = backendInfo{
							recordId: record.Metadata.ID,
							addr:     addr,
						}
					}
				}
			}
		}
	}
}
