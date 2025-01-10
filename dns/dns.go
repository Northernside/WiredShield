package wireddns

import (
	"fmt"
	"net"
	"strings"
	"time"
	"wiredshield/modules/db"
	"wiredshield/modules/whois"
	"wiredshield/services"

	"github.com/miekg/dns"
)

var (
	service     *services.Service
	ResolversV4 = map[string][]net.IP{}
	ResolversV6 = map[string][]net.IP{}
	processIPv4 string
	processIPv6 string
)

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := dns.Msg{}
	m.SetReply(r)
	m.Authoritative = true

	clientIp := strings.Split(w.RemoteAddr().String(), ":")[0]
	dnsLog := newLog()

	startTime := time.Now()

	if len(r.Question) > 0 {
		for _, question := range r.Question {
			// prepare
			questionName := question.Name
			lookupName := strings.TrimSuffix(strings.ToLower(questionName), ".")
			if !strings.HasSuffix(questionName, ".") {
				questionName = questionName + "."
			}

			country, err := whois.GetCountry(clientIp)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", clientIp, err))
				country = "Unknown (Error)"
			}

			dnsLog.ClientIP = clientIp
			dnsLog.QueryName = lookupName
			dnsLog.QueryType = dns.TypeToString[question.Qtype]
			dnsLog.QueryClass = dns.ClassToString[question.Qclass]
			dnsLog.ClientCountry = country

			// debug record
			if lookupName == "wiredshield_info" && dns.TypeToString[question.Qtype] == "TXT" {
				err := getDebugRecord(country, question, w, &m)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to get debug record: %s", err.Error()))
					emptyReply(w, &m)
					logDNSRequest(dnsLog)
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
				if dns.TypeToString[question.Qtype] == recordType {
					supported = true
					break
				}
			}

			if !supported {
				// service.ErrorLog(fmt.Sprintf("unsupported record type: %s", dns.TypeToString[question.Qtype]))
				emptyReply(w, &m)
				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				logDNSRequest(dnsLog)
				return
			}

			// check cache
			cacheKey := fmt.Sprintf("%s:%s:%s", dns.TypeToString[question.Qtype], lookupName, clientIp)
			entry, found := getCache(cacheKey)
			if found {
				m.Answer = entry
				err := w.WriteMsg(&m)
				if err != nil {
					service.ErrorLog(fmt.Sprintf("failed to write message (cache, %s) to client: %s", cacheKey, err.Error()))
				}

				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				dnsLog.IsSuccessful = true
			}

			// get record(s) from db
			records, err := db.GetRecords(dns.TypeToString[question.Qtype], lookupName)
			if err != nil {
				// service.ErrorLog(fmt.Sprintf("failed to get records: %s", err.Error()))
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
				switch record.GetType() {
				case "A":
					r := record.(*db.ARecord)
					var responseIps = getResponseIps(r, clientIp, country)
					for _, ip := range responseIps {
						rr = &dns.A{
							Hdr: dns.RR_Header{Name: questionName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
							A:   ip,
						}
					}
				case "AAAA":
					r := record.(*db.AAAARecord)
					var responseIps = getResponseIps(r, clientIp, country)
					for _, ip := range responseIps {
						rr = &dns.AAAA{
							Hdr:  dns.RR_Header{Name: questionName, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
							AAAA: ip,
						}
					}
				case "SOA":
					rr = buildSoaRecord(lookupName)
				case "CNAME":
					r := record.(*db.CNAMERecord)
					rr = &dns.CNAME{
						Hdr:    dns.RR_Header{Name: questionName, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
						Target: r.Target + ".",
					}
				case "NS":
					r := record.(*db.NSRecord)
					rr = &dns.NS{
						Hdr: dns.RR_Header{Name: questionName, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
						Ns:  r.NS + ".",
					}
				case "MX":
					r := record.(*db.MXRecord)
					rr = &dns.MX{
						Hdr:        dns.RR_Header{Name: questionName, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
						Preference: r.Priority,
						Mx:         r.Target + ".",
					}
				case "TXT":
					r := record.(*db.TXTRecord)
					rr = &dns.TXT{
						Hdr: dns.RR_Header{Name: questionName, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
						Txt: []string{r.Text},
					}
				case "SRV":
					r := record.(*db.SRVRecord)
					rr = &dns.SRV{
						Hdr:      dns.RR_Header{Name: questionName, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300},
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

			// always attach a SOA record if no records found
			if len(records) == 0 {
				rr := buildSoaRecord(lookupName) // default SOA record
				m.Answer = append(m.Answer, rr)
				rrList = append(rrList, rr)
			}

			// empty reply
			if len(m.Answer) == 0 {
				emptyReply(w, &m)

				dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
				dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
				logDNSRequest(dnsLog)
				return
			}

			// update, send to client, and log
			updateCache(cacheKey, rrList)
			err = w.WriteMsg(&m)
			if err != nil {
				service.ErrorLog(fmt.Sprintf("failed to write message (response, %s) to client: %s", cacheKey, err.Error()))
			}

			dnsLog.ResponseCode = dns.RcodeToString[m.Rcode]
			dnsLog.ResponseTime = time.Since(startTime).Milliseconds()
			dnsLog.IsSuccessful = true
			logDNSRequest(dnsLog)
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

	// get shield ips from main ips in network interface
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
			if ipnet, ok := addr.(*net.IPNet); ok {
				// skip loobacks & link-local (fe80::/10)
				if !ipnet.IP.IsLoopback() && !ipnet.IP.IsLinkLocalUnicast() {

					// ipv4
					if ipnet.IP.To4() != nil && processIPv4 == "" {
						service.InfoLog("Primary IPv4 address: " + ipnet.IP.String())

						country, err := whois.GetCountry(ipnet.IP.String())
						if err != nil {
							service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", ipnet.IP.String(), err))
						} else {
							service.InfoLog("Primary IPv4 country: " + country)
						}

						ResolversV4[country] = []net.IP{ipnet.IP}
						processIPv4 = ipnet.IP.String()
					}

					// ipv6
					if ipnet.IP.To16() != nil && ipnet.IP.To4() == nil && processIPv6 == "" {
						service.InfoLog("Primary IPv6 address: " + ipnet.IP.String())

						country, err := whois.GetCountry(ipnet.IP.String())
						if err != nil {
							service.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", ipnet.IP.String(), err))
						} else {
							service.InfoLog("Primary IPv6 country: " + country)
						}

						ResolversV6[country] = []net.IP{ipnet.IP}
						processIPv6 = ipnet.IP.String()
					}
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

func getOptimalResolvers(recordType, userIp string, country string) []net.IP {
	cacheMux.RLock()
	geoEntry, found := geoLocCache[userIp]
	cacheMux.RUnlock()

	if found && time.Now().Before(geoEntry.expiration) {
		if recordType == "A" {
			if resolvers, ok := ResolversV4[geoEntry.country]; ok {
				return resolvers
			}
		} else if recordType == "AAAA" {
			if resolvers, ok := ResolversV6[geoEntry.country]; ok {
				return resolvers
			}
		}
	}

	if len(country) != 2 {
		if recordType == "A" {
			return []net.IP{net.ParseIP(processIPv4)}
		} else if recordType == "AAAA" {
			return []net.IP{net.ParseIP(processIPv6)}
		}
	}

	cacheMux.Lock()
	geoLocCache[userIp] = geoLocCacheEntry{
		country:    country,
		expiration: time.Now().Add(24 * time.Hour),
	}
	cacheMux.Unlock()

	if recordType == "A" {
		if resolvers, ok := ResolversV4[country]; ok {
			return resolvers
		}

		return []net.IP{net.ParseIP(processIPv4)}
	} else if recordType == "AAAA" {
		if resolvers, ok := ResolversV6[country]; ok {
			return resolvers
		}

		return []net.IP{net.ParseIP(processIPv6)}
	}

	return nil
}
