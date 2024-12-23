package wireddns

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/logging"
	"wiredshield/modules/whois"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var (
	service     *services.Service
	cache       = make(map[string]dnsCacheEntry)
	geoLocCache = make(map[string]geoLocCacheEntry)
	Resolvers   = map[string][]net.IP{}
	processIp   string
	cacheMux    sync.RWMutex
)

type dnsCacheEntry struct {
	records    []dns.RR
	expiration time.Time
}

type geoLocCacheEntry struct {
	country    string
	expiration time.Time
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)
	m.Authoritative = true

	clientIp := strings.Split(w.RemoteAddr().String(), ":")[0]
	dnsLog := &logging.DNSRequestLog{
		QueryTime:     time.Now().Unix(),
		ClientIP:      clientIp,
		QueryName:     "",
		QueryType:     "",
		QueryClass:    "",
		ResponseCode:  "",
		ResponseTime:  0,
		IsSuccessful:  false,
		ClientCountry: "",
	}

	startTime := time.Now()

	if len(r.Question) > 0 {
		for _, question := range r.Question {
			// prepare
			lookupName := strings.TrimSuffix(strings.ToLower(question.Name), ".")
			dnsLog.QueryName = lookupName
			dnsLog.QueryType = dns.TypeToString[question.Qtype]
			dnsLog.QueryClass = dns.ClassToString[question.Qclass]

			country, err := whois.GetCountry(clientIp)
			dnsLog.ClientCountry = country

			if lookupName == "wiredshield_info" && dns.TypeToString[question.Qtype] == "TXT" {
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", clientIp, err))
					country = "Unknown (Error)"
				}

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

				err = w.WriteMsg(&m)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to write message to client: %s", err.Error()))
				}

				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				dnsLog.IsSuccessful = true
				logDNSRequest(dnsLog)

				return
			}

			// check if record is supported
			var supported bool = false
			for _, recordType := range db.SupportedRecordTypes {
				if dns.TypeToString[question.Qtype] == string(recordType) {
					supported = true
					break
				}
			}

			if !supported {
				emptyReply(w, &m)
				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				logDNSRequest(dnsLog)
				return
			}

			// check cache
			cacheKey := fmt.Sprintf("%s:%s:%s", dns.TypeToString[question.Qtype], lookupName, clientIp)
			cacheMux.RLock()
			entry, found := cache[cacheKey]
			cacheMux.RUnlock()

			if found && time.Now().Before(entry.expiration) {
				m.Answer = append(m.Answer, entry.records...)
				err := w.WriteMsg(&m)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to write message to client: %s", err.Error()))
				}

				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				dnsLog.IsSuccessful = true
				logDNSRequest(dnsLog)

				return
			}

			// get record(s) from db
			records, err := db.GetRecords(dns.TypeToString[question.Qtype], lookupName)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to get records: %s", err.Error()))
				emptyReply(w, &m)
				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				logDNSRequest(dnsLog)
				return
			}

			// append records to response and cache
			var rrList []dns.RR
			for _, record := range records {
				var rr dns.RR
				switch r := record.(type) {
				case db.ARecord:
					var responseIps []net.IP

					if r.Protected {
						responseIps = getOptimalResolvers(clientIp)
					} else {
						responseIps = []net.IP{net.ParseIP(r.IP)}
					}

					for _, ip := range responseIps {
						rr = &dns.A{
							Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
							A:   ip,
						}
					}
				case db.AAAARecord:
					var responseIps []net.IP
					if r.Protected {
						responseIps = getOptimalResolvers(clientIp)
					} else {
						responseIps = []net.IP{net.ParseIP(r.IP)}
					}

					for _, ip := range responseIps {
						rr = &dns.AAAA{
							Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
							AAAA: ip,
						}
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
				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				logDNSRequest(dnsLog)
				return
			}

			// update cache
			cacheMux.Lock()
			cache[cacheKey] = dnsCacheEntry{
				records:    rrList,
				expiration: time.Now().Add(1 * time.Hour),
			}
			cacheMux.Unlock()

			err = w.WriteMsg(&m)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to write message to client: %s", err.Error()))
			}

			dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
			dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
			dnsLog.IsSuccessful = true
			logDNSRequest(dnsLog)
		}
	}
}

func logDNSRequest(log *logging.DNSRequestLog) {
	logging.DNSLogsChannel <- log
}

func processRequestLogs() {
	logWorkers := 512
	for i := 0; i < logWorkers; i++ {
		go func() {
			for log := range logging.DNSLogsChannel {
				logs := log.CollectAdditionalLogs()
				if len(logs) > 0 {
					if err := log.BatchInsert(logs); err != nil {
						service.ErrorLog(fmt.Sprintf("Failed to insert logs: %v", err))
					}
				}
			}
		}()
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
					service.InfoLog("Primary IPv4 address: " + ipnet.IP.String())

					country, err := whois.GetCountry(ipnet.IP.String())
					if err != nil {
						service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", ipnet.IP.String(), err))
					} else {
						service.InfoLog("Primary IPv4 country: " + country)
					}

					Resolvers[country] = []net.IP{ipnet.IP}
					processIp = ipnet.IP.String()

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

		go processRequestLogs()

		service.InfoLog("Starting DNS server on " + addr)
		service.OnlineSince = time.Now().Unix()
	}
}

func getOptimalResolvers(userIp string) []net.IP {
	cacheMux.RLock()
	geoEntry, found := geoLocCache[userIp]
	cacheMux.RUnlock()

	if found && time.Now().Before(geoEntry.expiration) {
		if resolvers, ok := Resolvers[geoEntry.country]; ok {
			return resolvers
		}
	}

	country, err := whois.GetCountry(userIp)
	if err != nil {
		service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", userIp, err))
		return []net.IP{net.ParseIP(processIp)}
	}

	cacheMux.Lock()
	geoLocCache[userIp] = geoLocCacheEntry{
		country:    country,
		expiration: time.Now().Add(24 * time.Hour),
	}
	cacheMux.Unlock()

	if resolvers, ok := Resolvers[country]; ok {
		return resolvers
	}

	return []net.IP{net.ParseIP(processIp)}
}
