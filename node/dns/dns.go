package dns

import (
	"net"
	"strings"
	"wired/modules/logger"

	"github.com/miekg/dns"
)

var zones = make(map[string][]dns.RR)

func Run() {
	initZones()

	dns.HandleFunc(".", handleRequest)
	go func() {
		server := &dns.Server{Addr: ":53", Net: "udp"}
		err := server.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	logger.Println("DNS server started on port 53 (UDP)")
	logger.Println("DNS server started on port 53 (TCP)")
	server := &dns.Server{Addr: ":53", Net: "tcp"}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func initZones() {
	zones["example.com."] = []dns.RR{
		// SOA Record (Required)
		&dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "admin.example.com.",
			Serial:  2024010101,
			Refresh: 86400,
			Retry:   7200,
			Expire:  3600000,
			Minttl:  300,
		},

		// NS Records
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: "ns1.example.com.",
		},

		// A Records
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1"),
		},

		// AAAA Records
		&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: net.ParseIP("2001:db8::1"),
		},

		// MX Records
		&dns.MX{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Preference: 10,
			Mx:         "mail.example.com.",
		},

		// TXT Records
		&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{"v=spf1 mx -all"},
		},

		// SRV Records
		&dns.SRV{
			Hdr: dns.RR_Header{
				Name:   "_service._tcp.example.com.",
				Rrtype: dns.TypeSRV,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Priority: 10,
			Weight:   50,
			Port:     5060,
			Target:   "sip.example.com.",
		},

		// CNAME Records
		&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "www.example.com.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: "example.com.",
		},
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		qname := strings.ToLower(q.Name)
		qtype := q.Qtype

		zone := findZone(qname)
		if zone == "" {
			m.SetRcode(r, dns.RcodeRefused)
			continue
		}

		var (
			nameExists    bool
			cnameRecords  []dns.RR
			answerRecords []dns.RR
			authorityRRs  []dns.RR
		)

		for _, rr := range zones[zone] {
			rrName := strings.ToLower(rr.Header().Name)

			if rrName == qname {
				nameExists = true
				if rr.Header().Rrtype == dns.TypeCNAME {
					cnameRecords = append(cnameRecords, rr)
				} else if rr.Header().Rrtype == qtype {
					answerRecords = append(answerRecords, rr)
				}
			}
		}

		// Handle CNAME responses
		if len(cnameRecords) > 0 && qtype != dns.TypeCNAME {
			m.Answer = append(m.Answer, cnameRecords...)
		} else if len(cnameRecords) > 0 && qtype == dns.TypeCNAME {
			m.Answer = append(m.Answer, cnameRecords...)
		} else {
			if len(answerRecords) > 0 {
				m.Answer = append(m.Answer, answerRecords...)
			} else {
				// Handle NXDOMAIN or NOERROR
				if nameExists {
					authorityRRs = getSOA(zone, false)
				} else {
					m.SetRcode(r, dns.RcodeNameError)
					authorityRRs = getSOA(zone, true)
				}
			}
		}

		m.Ns = append(m.Ns, authorityRRs...)
	}

	w.WriteMsg(m)
}

func findZone(qname string) string {
	qname = dns.CanonicalName(qname)
	var maxZone string
	maxLen := 0

	for zone := range zones {
		if dns.IsSubDomain(zone, qname) && len(zone) > maxLen {
			maxLen = len(zone)
			maxZone = zone
		}
	}

	return maxZone
}

func getSOA(zone string, nxdomain bool) []dns.RR {
	for _, rr := range zones[zone] {
		if soa, ok := rr.(*dns.SOA); ok {
			soaCopy := *soa
			soaCopy.Hdr = dns.RR_Header{
				Name:   soa.Hdr.Name,
				Rrtype: soa.Hdr.Rrtype,
				Class:  soa.Hdr.Class,
				Ttl:    soa.Hdr.Ttl,
			}

			if nxdomain {
				soaCopy.Hdr.Ttl = soaCopy.Minttl
			} else {
				if soaCopy.Hdr.Ttl > soaCopy.Minttl {
					soaCopy.Hdr.Ttl = soaCopy.Minttl
				}
			}

			return []dns.RR{&soaCopy}
		}
	}

	return nil
}
