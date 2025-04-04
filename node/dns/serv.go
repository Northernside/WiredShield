package dns

import (
	"net"
	"os"
	"strings"
	"wired/modules/geo"
	"wired/modules/logger"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var zones = make(map[string][]types.DNSRecord)

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

func Start() {
	loadZonefile()

	dns.HandleFunc(".", handleRequest)
	go func() {
		logger.Println("DNS server started on port 53 (UDP)")
		server := &dns.Server{Addr: ":53", Net: "udp"}
		err := server.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	logger.Println("DNS server started on port 53 (TCP)")
	server := &dns.Server{Addr: ":53", Net: "tcp"}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	var userIP net.IP
	if udpConn, ok := w.LocalAddr().(*net.UDPAddr); ok {
		userIP = udpConn.IP
	} else if tcpConn, ok := w.LocalAddr().(*net.TCPAddr); ok {
		userIP = tcpConn.IP
	}

	userLoc, err := geo.GetLocation(userIP)
	if err != nil {
		logger.Println("Error getting user location:", err)
		return
	}

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
			rrName := strings.ToLower(rr.Record.Header().Name)
			if rrName == qname {
				nameExists = true
				if rr.Record.Header().Rrtype == dns.TypeCNAME {
					cnameRecords = append(cnameRecords, rr.Record)
				} else if rr.Record.Header().Rrtype == qtype {
					if rr.Metadata.Protected {
						if _, ok := rr.Record.(*dns.AAAA); ok {
							loc, err := geo.FindNearestLocation(geo.GeoInfo{
								IP:         userIP,
								MMLocation: userLoc,
							}, 6)
							if err != nil {
								logger.Println("Error finding nearest location:", err)
								continue
							}

							rr.Record.(*dns.AAAA).AAAA = loc.IP
						} else if _, ok := rr.Record.(*dns.A); ok {
							loc, err := geo.FindNearestLocation(geo.GeoInfo{
								IP:         userIP,
								MMLocation: userLoc,
							}, 4)
							if err != nil {
								logger.Println("Error finding nearest location:", err)
								continue
							}

							rr.Record.(*dns.A).A = loc.IP
						}
					}

					answerRecords = append(answerRecords, rr.Record)
				}
			}
		}

		// CNAME
		if len(cnameRecords) > 0 && qtype != dns.TypeCNAME {
			for _, cname := range cnameRecords {
				cname.Header().Name = q.Name
			}

			m.Answer = append(m.Answer, cnameRecords...)
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
					authorityRRs = getSOA(zone, false)
				} else {
					m.SetRcode(r, dns.RcodeNameError)
					authorityRRs = getSOA(zone, true)
				}
			}
		}

		for _, authority := range authorityRRs {
			authority.Header().Name = q.Name
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
		if soa, ok := rr.Record.(*dns.SOA); ok {
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
