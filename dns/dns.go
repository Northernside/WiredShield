package wireddns

import (
	"fmt"
	"net"
	"strings"
	"time"
	"wiredshield/modules/db"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var (
	service  *services.Service
	shieldIp *net.IP
)

var recordTypeMap = map[uint16]string{
	dns.TypeA:     "A",
	dns.TypeAAAA:  "AAAA",
	dns.TypeCNAME: "CNAME",
	dns.TypeNS:    "NS",
	dns.TypeMX:    "MX",
	dns.TypeTXT:   "TXT",
	dns.TypeCAA:   "CAA",
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)

	if len(r.Question) > 0 {
		question := r.Question[0]
		name := strings.ToLower(question.Name)
		lookupName := name[:len(name)-1]

		// if A, then check if protected, if protected, return shield ip, else return result and if not A, return result
		var responseIp net.IP
		var stringResult string
		if question.Qtype == dns.TypeA {
			result, protected, err := db.GetRecord("A", lookupName)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to get %d record for %s: %s", question.Qtype, lookupName, err.Error()))
			}

			if protected {
				responseIp = *shieldIp
			} else {
				responseIp = net.ParseIP(result)
			}
		} else if question.Qtype == dns.TypeAAAA {
			result, _, err := db.GetRecord("AAAA", lookupName)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to get %d record for %s: %s", question.Qtype, lookupName, err.Error()))
			}

			responseIp = net.ParseIP(result)
		} else {
			var err error
			stringResult, _, err = db.GetRecord(recordTypeMap[question.Qtype], lookupName)
			if question.Qtype != dns.TypeSOA {
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to get %d record for %s: %s", question.Qtype, lookupName, err.Error()))
				}
			}
		}

		var rr dns.RR
		switch question.Qtype {
		case dns.TypeA:
			rr = &dns.A{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   responseIp,
			}
		case dns.TypeAAAA:
			rr = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: responseIp,
			}
		case dns.TypeCNAME:
			rr = &dns.CNAME{
				Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: stringResult,
			}
		case dns.TypeNS:
			rr = &dns.NS{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  stringResult,
			}
		case dns.TypeTXT:
			rr = &dns.TXT{
				Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{stringResult},
			}
		case dns.TypeCAA:
			rr = &dns.CAA{
				Hdr:   dns.RR_Header{Name: name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 300},
				Flag:  0,
				Tag:   "issue",
				Value: stringResult,
			}
		case dns.TypeSOA:
			rr = &dns.SOA{
				Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      "woof.ns.wired.rip",
				Mbox:    "ssl.northernsi.de",
				Serial:  1111111111,
				Refresh: 86400,
				Retry:   7200,
				Expire:  4000000,
				Minttl:  11200,
			}
		default:
			service.WarnLog("unsupported record: " + question.String())
			rr = &dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}
		}

		m.Answer = append(m.Answer, rr)
	}

	err := w.WriteMsg(&m)
	if err != nil {
		service.ErrorLog("failed to write message: " + err.Error())
	}
}

func Prepare(_service *services.Service) func() {
	service = _service

	// get shield ipv4 from main ipv4 in network interface
	ifaces, err := net.Interfaces()
	if err != nil {
		service.FatalLog("failed to get network interfaces: " + err.Error())
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			service.ErrorLog("failed to get addresses: " + err.Error())
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					shieldIp = &ipnet.IP
					break
				}
			}
		}
	}

	return func() {
		addr := "0.0.0.0:53"
		server := &dns.Server{Addr: addr, Net: "udp"}

		dns.HandleFunc(".", handleRequest)

		service.InfoLog("Starting DNS server on " + addr)
		service.OnlineSince = time.Now().Unix()
		err := server.ListenAndServe()
		if err != nil {
			service.ErrorLog("Failed to start DNS server: " + err.Error())
		}
	}
}
