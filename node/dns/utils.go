package dns

import (
	"fmt"
	"strings"
	"wired/modules/types"

	"github.com/miekg/dns"
)

func recordToZoneFile(rr dns.RR) string {
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
