package dns

import (
	"fmt"
	"strings"
	"wired/modules/types"

	"github.com/miekg/dns"
)

func RecordToZoneFile(rr dns.RR) string {
	hdr := rr.Header()
	name := hdr.Name
	ttl := hdr.Ttl
	class := dns.ClassToString[hdr.Class]
	rtype := dns.TypeToString[hdr.Rrtype]

	switch r := rr.(type) {
	case *dns.A:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, r.A.String())
	case *dns.AAAA:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, r.AAAA.String())
	case *dns.CNAME:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, r.Target)
	case *dns.MX:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%d %s", name, ttl, class, rtype, r.Preference, r.Mx)
	case *dns.NS:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, r.Ns)
	case *dns.SOA:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s %s %d %d %d %d %d",
			name, ttl, class, rtype,
			r.Ns, r.Mbox, r.Serial, r.Refresh, r.Retry, r.Expire, r.Minttl)
	case *dns.SRV:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%d %d %d %s",
			name, ttl, class, rtype,
			r.Priority, r.Weight, r.Port, r.Target)
	case *dns.TXT:
		escaped := make([]string, len(r.Txt))
		for i, txt := range r.Txt {
			if strings.Contains(txt, " ") || strings.Contains(txt, "\"") {
				escaped[i] = fmt.Sprintf("\"%s\"", strings.ReplaceAll(txt, "\"", "\\\""))
			} else {
				escaped[i] = txt
			}
		}

		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, strings.Join(escaped, " "))
	case *dns.PTR:
		return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", name, ttl, class, rtype, r.Ptr)
	default:
		return fmt.Sprintf("; unsupported record type: %T", rr)
	}
}

func CreateIPCompatibility() {
	for id, records := range DomainRecordIndexId {
		if records == nil {
			continue
		}

		for _, record := range records {
			if record == nil || !record.Metadata.Protected {
				continue
			}

			var existingType uint16
			var newRR dns.RR

			switch record.RR.Header().Rrtype {
			case dns.TypeA:
				existingType = dns.TypeAAAA
				a := record.RR.(*dns.A)
				newRR = &dns.AAAA{
					Hdr:  dns.RR_Header{Name: a.Header().Name, Rrtype: existingType, Class: a.Header().Class, Ttl: a.Header().Ttl},
					AAAA: record.RR.(*dns.A).A,
				}
			case dns.TypeAAAA:
				existingType = dns.TypeA
				aaaa := record.RR.(*dns.AAAA)
				newRR = &dns.A{
					Hdr: dns.RR_Header{Name: aaaa.Header().Name, Rrtype: existingType, Class: aaaa.Header().Class, Ttl: aaaa.Header().Ttl},
					A:   record.RR.(*dns.AAAA).AAAA,
				}
			default:
				continue
			}

			InsertRecord(&DomainData{
				Id:     id,
				Domain: DomainIndexId[id].Domain,
				Owner:  DomainIndexId[id].Owner,
			}, &types.DNSRecord{
				Metadata: types.RecordMetadata{
					Id:        "",
					Protected: true,
					IPCompat:  true,
					SSLInfo:   types.SSLInfo{},
				},
				RR: newRR,
			})
		}
	}
}
