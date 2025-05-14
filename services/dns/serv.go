package dns

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/geo"
	"wired/modules/logger"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var (
	udpServer *dns.Server
	tcpServer *dns.Server
)

func init() {
	if _, err := os.Stat("zonefile.txt"); os.IsNotExist(err) {
		file, err := os.Create("zonefile.txt")
		if err != nil {
			logger.Println("Error creating zone file:", err)
			return
		}
		defer file.Close()
	}
}

func Start(ctx context.Context) {
	dns.HandleFunc(".", handleRequest)

	go func() {
		udpServer = &dns.Server{Addr: ":53", Net: "udp"}
		err := udpServer.ListenAndServe()
		if err != nil {
			logger.Fatal("Failed to start DNS (UDP) server: ", err)
		}
	}()

	logger.Println("DNS server started on port 53 (UDP)")

	go func() {
		tcpServer = &dns.Server{Addr: ":53", Net: "tcp"}
		err := tcpServer.ListenAndServe()
		if err != nil {
			logger.Fatal("Failed to start DNS (TCP) server: ", err)
		}
	}()

	logger.Println("DNS server started on port 53 (TCP)")

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_DNSServiceInitialized,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.DNSServiceInitializedData{},
	})

	<-ctx.Done()
	logger.Println("Shutting down DNS servers...")

	if udpServer != nil {
		if err := udpServer.Shutdown(); err != nil {
			logger.Println("Error shutting down DNS (UDP) server:", err)
		}
	}

	if tcpServer != nil {
		if err := tcpServer.Shutdown(); err != nil {
			logger.Println("Error shutting down DNS (TCP) server:", err)
		}
	}
}

func getECS(r *dns.Msg) *dns.EDNS0_SUBNET {
	for _, extra := range r.Extra {
		if opt, ok := extra.(*dns.OPT); ok {
			for _, option := range opt.Option {
				if subnet, ok := option.(*dns.EDNS0_SUBNET); ok {
					return subnet
				}
			}
		}
	}

	return nil
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	var userIP net.IP
	ecsSubnet := getECS(r)
	if ecsSubnet != nil {
		userIP = ecsSubnet.Address
	} else {
		if udpConn, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			userIP = udpConn.IP
		} else if tcpConn, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			userIP = tcpConn.IP
		}
	}

	userLoc, err := geo.GetLocation(userIP)
	if err != nil {
		logger.Println("Error getting user location:", err)
		return
	}

	for _, q := range r.Question {
		qname := strings.ToLower(q.Name)
		qtype := q.Qtype

		var (
			nameExists    bool
			cnameRecords  []dns.RR
			answerRecords []dns.RR
			authorityRRs  []dns.RR
		)

		zoneRecords := findZone(qname)
		for _, record := range zoneRecords {
			rrName := strings.ToLower(record.RR.Header().Name)
			if rrName == qname && record.RR.Header().Rrtype == qtype {
				nameExists = true
				clonedRecord := dns.Copy(record.RR)
				if record.Metadata.Protected {
					ipVersion := map[bool]int{true: 6, false: 4}[record.RR.Header().Rrtype == dns.TypeAAAA]
					loc, err := geo.FindNearestLocation(geo.GeoInfo{
						IP:         userIP,
						MMLocation: userLoc,
					}, ipVersion)

					if err != nil {
						logger.Printf("Error finding nearest location for IPv%s %s: %v\n", ipVersion, userIP, err)
						logger.Println("userLoc: ", userLoc)
						m.Extra = append(m.Extra, makeErrorTxt(qname, err.Error()))
						continue
					}

					switch cRecord := clonedRecord.(type) {
					case *dns.AAAA:
						cRecord.AAAA = loc.IP
					case *dns.A:
						cRecord.A = loc.IP

						//logger.Println(record
					}
				}

				answerRecords = append(answerRecords, clonedRecord)
			} else if record.RR.Header().Rrtype == dns.TypeCNAME {
				cnameRecords = append(cnameRecords, record.RR)
			}
		}

		// CNAME handling
		if len(cnameRecords) > 0 && qtype != dns.TypeCNAME {
			for _, cname := range cnameRecords {
				cname.Header().Name = q.Name
			}

			m.Answer = append(m.Answer, cnameRecords...)

			// Resolve CNAME targets
			for _, cname := range cnameRecords {
				cnameRecord, ok := cname.(*dns.CNAME)
				if !ok {
					continue
				}

				target := dns.CanonicalName(cnameRecord.Target)
				targetRecs := findZone(target)
				if len(targetRecs) == 0 {
					continue
				}

				var targetAnswers []dns.RR
				for _, record := range targetRecs {
					rrName := strings.ToLower(record.RR.Header().Name)
					if rrName == target && (record.RR.Header().Rrtype == qtype) {
						clonedRecord := dns.Copy(record.RR)
						if record.Metadata.Protected {
							ipVersion := map[bool]int{true: 6, false: 4}[record.RR.Header().Rrtype == dns.TypeAAAA]
							loc, err := geo.FindNearestLocation(geo.GeoInfo{
								IP:         userIP,
								MMLocation: userLoc,
							}, ipVersion)

							if err != nil {
								logger.Printf("Error finding nearest location for IPv%s %s: %v\n", ipVersion, userIP, err)
								logger.Println("userLoc: ", userLoc)
								m.Extra = append(m.Extra, makeErrorTxt(qname, err.Error()))
								continue
							}

							switch record := clonedRecord.(type) {
							case *dns.AAAA:
								record.AAAA = loc.IP
							case *dns.A:
								record.A = loc.IP
							}
						}

						targetAnswers = append(targetAnswers, clonedRecord)
					}
				}

				if len(targetAnswers) > 0 {
					m.Answer = append(m.Answer, targetAnswers...)
				}
			}
		} else if len(cnameRecords) > 0 && qtype == dns.TypeCNAME {
			for _, cname := range cnameRecords {
				cname.Header().Name = q.Name
			}

			m.Answer = append(m.Answer, cnameRecords...)
		} else {
			if len(answerRecords) > 0 {
				for _, answer := range answerRecords {
					answer.Header().Name = q.Name
				}

				m.Answer = append(m.Answer, answerRecords...)
			} else {
				// NXDOMAIN, NOERROR
				if nameExists {
					authorityRRs = getSOA(qname, false)
				} else {
					m.SetRcode(r, dns.RcodeNameError)
					authorityRRs = getSOA(qname, true)
				}
			}
		}

		for _, authority := range authorityRRs {
			authority.Header().Name = q.Name
		}

		m.Ns = append(m.Ns, authorityRRs...)
	}

	if ecsSubnet != nil {
		var opt *dns.OPT
		for _, ex := range m.Extra {
			if o, ok := ex.(*dns.OPT); ok {
				opt = o
				break
			}
		}

		if opt == nil {
			opt = &dns.OPT{
				Hdr: dns.RR_Header{
					Name:   ".",
					Rrtype: dns.TypeOPT,
				},
			}

			m.Extra = append(m.Extra, opt)
		}

		responseSubnet := &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        ecsSubnet.Family,
			SourceNetmask: ecsSubnet.SourceNetmask,
			SourceScope:   ecsSubnet.SourceNetmask,
			Address:       ecsSubnet.Address,
		}

		opt.Option = append(opt.Option, responseSubnet)
	}

	w.WriteMsg(m)
}

func makeErrorTxt(qname string, text string) *dns.TXT {
	return &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		Txt: []string{
			"Debug info due to error",
			"Error: " + text,
			"Time: " + time.Now().Format(time.RFC3339),
			"Node: " + env.GetEnv("NODE_KEY", "node-key"),
		},
	}
}

func getSOA(zone string, nxdomain bool) []dns.RR {
	recs := findZone(zone)
	if len(recs) == 0 {
		return nil
	}

	for _, record := range recs {
		if soa, ok := record.RR.(*dns.SOA); ok {
			soaCopy := *soa
			soaCopy.Hdr = dns.RR_Header{
				Name:   soa.Hdr.Name,
				Rrtype: soa.Hdr.Rrtype,
				Class:  soa.Hdr.Class,
				Ttl:    soa.Hdr.Ttl,
			}

			if nxdomain {
				soaCopy.Hdr.Ttl = soaCopy.Minttl
			} else if soaCopy.Hdr.Ttl > soaCopy.Minttl {
				soaCopy.Hdr.Ttl = soaCopy.Minttl
			}

			return []dns.RR{&soaCopy}
		}
	}

	return nil
}

func findZone(qname string) []*types.DNSRecord {
	return HeaderNameIndex[qname]
}
