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

func zoneFileToRecord(zoneLine string) (dns.RR, error) {
	if strings.HasPrefix(zoneLine, ";") || strings.TrimSpace(zoneLine) == "" {
		return nil, types.ErrUnusableLine
	}

	rr, err := dns.NewRR(zoneLine)
	if err != nil {
		return nil, fmt.Errorf("failed to parse record: %v", err)
	}

	return rr, nil
}

func createIPCompatibility() {
	Zones.mu.Lock()
	defer Zones.mu.Unlock()

	var walk func(node *trieNode, path []string)
	walk = func(node *trieNode, path []string) {
		if len(node.records) > 0 {
			reversedPath := reverse(path)
			domain := dns.Fqdn(strings.Join(reversedPath, "."))

			for _, record := range node.records {
				if !record.Metadata.Protected {
					continue
				}

				var existingType uint16
				var newRR dns.RR

				switch record.Record.Header().Rrtype {
				case dns.TypeA:
					existingType = dns.TypeAAAA
					a := record.Record.(*dns.A)
					newRR = &dns.AAAA{
						Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: a.Hdr.Ttl},
						AAAA: record.Record.(*dns.A).A,
					}
				case dns.TypeAAAA:
					existingType = dns.TypeA
					aaaa := record.Record.(*dns.AAAA)
					newRR = &dns.A{
						Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: aaaa.Hdr.Ttl},
						A:   record.Record.(*dns.AAAA).AAAA,
					}
				default:
					continue
				}

				exists := false
				for _, r := range node.records {
					if r.Record.Header().Rrtype == existingType {
						exists = true
						break
					}
				}

				if !exists {
					node.records = append(node.records, &types.DNSRecord{
						Record: newRR,
						Metadata: types.RecordMetadata{
							ID:         record.Metadata.ID,
							Protected:  true,
							Artificial: true,
						},
					})
				}
			}
		}

		for label, child := range node.children {
			walk(child, append(path, label))
		}
	}

	walk(Zones.root, []string{})
}
