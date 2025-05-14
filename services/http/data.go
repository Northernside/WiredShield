package http

import (
	"net"
	wired_dns "wired/services/dns"

	"github.com/miekg/dns"
)

type protectedBackend struct {
	recordId string
	addr     net.Addr
}

var (
	protectedHosts = make(map[string]protectedBackend)
)

func loadProtectedHosts() {
	records := wired_dns.GetAllRecords()
	for _, record := range records {
		if record.Metadata.Protected {
			var ip net.IP
			switch r := record.RR.(type) {
			case *dns.A:
				ip = net.ParseIP(r.A.String())
			case *dns.AAAA:
				ip = net.ParseIP(r.AAAA.String())
			}

			if ip != nil {
				protectedHosts[record.RR.Header().Name] = protectedBackend{
					recordId: record.Metadata.Id,
					addr:     &net.TCPAddr{IP: ip, Port: 80},
				}
			}
		}
	}
}
