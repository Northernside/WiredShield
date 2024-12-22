package wireddns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var (
	service  *services.Service
	shieldIp *net.IP
	cache    = make(map[string]cacheEntry)
	cacheMux sync.RWMutex
)

type cacheEntry struct {
	records    []dns.RR
	expiration time.Time
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) > 0 {
		for _, question := range r.Question {
			// prepare
			lookupName := strings.TrimSuffix(strings.ToLower(question.Name), ".")

			service.InfoLog(fmt.Sprintf("query: %s %s", dns.TypeToString[question.Qtype], lookupName))

			// check if record is supported
			var supported bool = false
			for _, recordType := range db.SupportedRecordTypes {
				if dns.TypeToString[question.Qtype] == string(recordType) {
					supported = true
					break
				}
			}

			if !supported {
				service.WarnLog(fmt.Sprintf("unsupported record type: %s", dns.TypeToString[question.Qtype]))
				emptyReply(w, &m)
				return
			}

			// check cache
			cacheKey := fmt.Sprintf("%s:%s", dns.TypeToString[question.Qtype], lookupName)
			cacheMux.RLock()
			entry, found := cache[cacheKey]
			cacheMux.RUnlock()

			if found && time.Now().Before(entry.expiration) {
				m.Answer = append(m.Answer, entry.records...)
				err := w.WriteMsg(&m)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to write message to client: %s", err.Error()))
				}

				return
			}

			// get record(s) from db
			records, err := db.GetRecords(dns.TypeToString[question.Qtype], lookupName)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to get records: %s", err.Error()))
				emptyReply(w, &m)
				return
			}

			// append records to response and cache
			var rrList []dns.RR
			for _, record := range records {
				var rr dns.RR
				switch r := record.(type) {
				case db.ARecord:
					var ip net.IP
					if r.Protected {
						ip = net.ParseIP("45.157.11.82")
					} else {
						ip = net.ParseIP(r.IP)
					}

					rr = &dns.A{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   ip,
					}
				case db.AAAARecord:
					var ip net.IP
					if r.Protected {
						ip = net.ParseIP("45.157.11.82")
					} else {
						ip = net.ParseIP(r.IP)
					}

					rr = &dns.AAAA{
						Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
						AAAA: ip,
					}
				case db.SOARecord:
					rr = &dns.SOA{
						Hdr:     dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
						Ns:      "woof.ns.wired.rip.",
						Mbox:    "info.wired.rip.",
						Serial:  2024122101,
						Refresh: 7200,
						Retry:   2400,
						Expire:  1209600,
						Minttl:  86400,
					}
				case db.CNAMERecord:
					service.InfoLog(fmt.Sprintf("cname record: %v", r))
					rr = &dns.CNAME{
						Hdr:    dns.RR_Header{Name: question.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: r.Target + ".",
					}
				case db.NSRecord:
					rr = &dns.NS{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
						Ns:  r.NS + ".",
					}
				case db.MXRecord:
					rr = &dns.MX{
						Hdr:        dns.RR_Header{Name: question.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
						Preference: r.Priority,
						Mx:         r.Target + ".",
					}
				case db.TXTRecord:
					rr = &dns.TXT{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
						Txt: []string{r.Text},
					}
				case db.SRVRecord:
					rr = &dns.SRV{
						Hdr:      dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300},
						Priority: uint16(r.Priority),
						Weight:   uint16(r.Weight),
						Port:     uint16(r.Port),
						Target:   r.Target,
					}
				}

				if rr != nil {
					m.Answer = append(m.Answer, rr)
					rrList = append(rrList, rr)
				}
			}

			if len(records) == 0 {
				rr := &dns.SOA{
					Hdr:     dns.RR_Header{Name: question.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
					Ns:      "woof.ns.wired.rip.",
					Mbox:    "info.wired.rip.",
					Serial:  2024122101,
					Refresh: 7200,
					Retry:   2400,
					Expire:  1209600,
					Minttl:  86400,
				}

				m.Answer = append(m.Answer, rr)
				rrList = append(rrList, rr)
			}

			if len(m.Answer) == 0 {
				emptyReply(w, &m)
				return
			}

			// update cache
			cacheMux.Lock()
			cache[cacheKey] = cacheEntry{
				records:    rrList,
				expiration: time.Now().Add(1 * time.Hour),
			}
			cacheMux.Unlock()

			err = w.WriteMsg(&m)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to write message to client: %s", err.Error()))
			}
		}
	}
}

func emptyReply(w dns.ResponseWriter, m *dns.Msg) {
	m.SetReply(m)
	m.Rcode = dns.RcodeNameError
	w.WriteMsg(m)
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

		dns.HandleFunc(".", handleRequest)

		udpServer := &dns.Server{Addr: addr, Net: "udp"}
		tcpServer := &dns.Server{Addr: addr, Net: "tcp"}

		go func() {
			err := udpServer.ListenAndServe()
			if err != nil {
				service.FatalLog("failed to start udp server: " + err.Error())
			}
		}()

		go func() {
			err := tcpServer.ListenAndServe()
			if err != nil {
				service.FatalLog("failed to start tcp server: " + err.Error())
			}
		}()

		service.InfoLog("Starting DNS server on " + addr)
		service.OnlineSince = time.Now().Unix()
	}
}
