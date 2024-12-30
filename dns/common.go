package wireddns

import (
	"fmt"
	"net"
	"wiredshield/modules/db"

	"github.com/miekg/dns"
)

func buildSoaRecord(queryName string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: queryName + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "woof.ns.wired.rip.",
		Mbox:    "info.wired.rip.",
		Serial:  2024122101,
		Refresh: 7200,
		Retry:   2400,
		Expire:  1209600,
		Minttl:  86400,
	}
}

func getResponseIps(_record interface{}, clientIp string, country string) []net.IP {
	var recordType string
	var protected bool
	var targetIp string

	switch r := _record.(type) {
	case db.ARecord:
		recordType = "A"
		protected = r.Protected
		targetIp = r.IP
	case db.AAAARecord:
		recordType = "AAAA"
		protected = r.Protected
		targetIp = r.IP
	default:
		return nil
	}

	var responseIps []net.IP
	if protected {
		responseIps = getOptimalResolvers(recordType, clientIp, country)
	} else {
		responseIps = []net.IP{net.ParseIP(targetIp)}
	}

	return responseIps
}

func getDebugRecord(country string, question dns.Question, w dns.ResponseWriter, m *dns.Msg) error {
	lines := []string{
		"WiredShield DNS Server",
		fmt.Sprintf("DNS Based Geo-Location: " + country),
	}

	for _, line := range lines {
		txt := &dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{line},
		}

		m.Answer = append(m.Answer, txt)
	}

	err := w.WriteMsg(m)
	if err != nil {
		service.ErrorLog(fmt.Sprintf("failed to write message (debug, %s) to client: %s", question.Name, err.Error()))
		return err
	}

	return nil
}
