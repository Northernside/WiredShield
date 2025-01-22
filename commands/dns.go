package commands

import (
	"fmt"
	"strconv"
	"strings"
	ssl "wiredshield/commands/libs"
	"wiredshield/modules/db"
	"wiredshield/modules/epoch"
	"wiredshield/services"

	"github.com/miekg/dns"
)

func Dns(model *Model) {
	var sb strings.Builder

	split := strings.Split(model.TextInput.Value(), " ")
	if len(split) < 2 {
		sb.WriteString("Usage: dns <list|set|del> [host] [target]\n")
		return
	}

	switch split[1] {
	case "domains":
		sb.WriteString("List DNS domains\n")
		domains, _ := db.GetAllDomains()

		if len(domains) == 0 {
			sb.WriteString("No domains found\n")
		} else {
			for _, domain := range domains {
				sb.WriteString(domain + "\n")
			}
		}
	case "list":
		sb.WriteString("List DNS records\n")
		if len(split) < 3 {
			sb.WriteString("Usage: dns list <host>\n")
			break
		}

		list, err := db.GetRecordsByDomain(split[2])
		if err != nil {
			sb.WriteString("Failed to get records: " + err.Error() + "\n")
			sb.WriteString("Domain not found\n")
			break
		}

		if len(list) == 0 {
			sb.WriteString("No records found for " + split[2] + "\n")
		} else {
			for _, record := range list {
				// use GetType()
				switch record.GetType() {
				case "A":
					r := record.(*db.ARecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" A %s %s\n", r.ID, r.Domain, r.IP))
				case "AAAA":
					r := record.(*db.AAAARecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" AAAA %s %s\n", r.ID, r.Domain, r.IP))
				case "SOA":
					r := record.(*db.SOARecord)
					sb.WriteString(fmt.Sprintf("[%d] SOA %s %s %s %d %d %d %d %d\n",
						r.ID, r.Domain, r.PrimaryNS, r.AdminEmail, r.Serial, r.Refresh, r.Retry, r.Expire, r.MinimumTTL))
				case "TXT":
					r := record.(*db.TXTRecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" TXT %s \"%s\"\n", r.ID, r.Domain, r.Text))
				case "NS":
					r := record.(*db.NSRecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" NS %s %s\n", r.ID, r.Domain, r.NS))
				case "MX":
					r := record.(*db.MXRecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" MX %s %s %d\n", r.ID, r.Domain, r.Target, r.Priority))
				case "CNAME":
					r := record.(*db.CNAMERecord)
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" CNAME %s %s\n", r.ID, r.Domain, r.Target))
				default:
					sb.WriteString("Unknown record type " + record.GetType() + "\n")
					sb.WriteString(fmt.Sprintf("%+v\n", record))
				}
			}
		}
	case "set":
		sb.WriteString("Set DNS record\n")
		if len(split) < 5 {
			sb.WriteString("Usage: dns set <recordtype> <host> <...>\n")
			break
		}

		split[2] = strings.ToUpper(split[2])

		// check via dns if NS of split[3] is woof.ns.wired.rip and meow.ns.wired.rip
		dnsClient := dns.Client{}
		msg := dns.Msg{}

		msg.SetQuestion(dns.Fqdn(split[3]), dns.TypeNS)
		resp, _, err := dnsClient.Exchange(&msg, "1.1.1.1:53")
		if err != nil {
			sb.WriteString("Failed to resolve NS: " + err.Error() + " - Seems like the domain is not delegated to us\n")
			break
		}

		if len(resp.Answer) == 0 {
			sb.WriteString("Failed to resolve NS: no answer - Seems like the domain is not delegated to us\n")
			break
		}

		if resp.Answer[0].(*dns.NS).Ns != "woof.ns.wired.rip." && resp.Answer[0].(*dns.NS).Ns != "meow.ns.wired.rip." {
			sb.WriteString("Failed to resolve NS: not delegated to us\n")
			break
		}

		var protected bool
		if len(split) > 5 {
			protected = split[5] == "true"
		}

		var record db.DNSRecord
		var id uint64
		snowflake, err := epoch.NewSnowflake(512)
		if err != nil {
			sb.WriteString("Failed to create snowflake: " + err.Error() + "\n")
			break
		}

		id = snowflake.GenerateID()

		switch split[2] {
		case "A":
			record = db.ARecord{
				ID:        id,
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}

			if protected {
				ssl.GenSSL(split[3])
			}
		case "AAAA":
			record = db.AAAARecord{
				ID:        id,
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}
		case "SOA":
			if len(split) < 11 {
				sb.WriteString("Usage: dns set SOA <host> <primary> <admin> <serial>" +
					"<refresh> <retry> <expire> <minimum> <protected>\n")
				break
			}

			serial, err := strconv.Atoi(split[6])
			if err != nil {
				sb.WriteString("Failed to parse serial: " + err.Error() + "\n")
				break
			}

			refresh, err := strconv.Atoi(split[7])
			if err != nil {
				sb.WriteString("Failed to parse refresh: " + err.Error() + "\n")
				break
			}

			retry, err := strconv.Atoi(split[8])
			if err != nil {
				sb.WriteString("Failed to parse retry: " + err.Error() + "\n")
				break
			}

			expire, err := strconv.Atoi(split[9])
			if err != nil {
				sb.WriteString("Failed to parse expire: " + err.Error() + "\n")
				break
			}

			minimum, err := strconv.Atoi(split[10])
			if err != nil {
				sb.WriteString("Failed to parse minimum: " + err.Error() + "\n")
				break
			}

			record = db.SOARecord{
				ID:         id,
				Domain:     split[3],
				PrimaryNS:  split[4],
				AdminEmail: split[5],
				Serial:     uint32(serial),
				Refresh:    uint32(refresh),
				Retry:      uint32(retry),
				Expire:     uint32(expire),
				MinimumTTL: uint32(minimum),
			}
		case "TXT":
			text := strings.Join(split[4:], " ")[1 : len(strings.Join(split[4:], " "))-1]
			record = db.TXTRecord{
				ID:        id,
				Domain:    split[3],
				Text:      text,
				Protected: protected,
			}
		case "NS":
			record = db.NSRecord{
				ID:        id,
				Domain:    split[3],
				NS:        split[4],
				Protected: protected,
			}
		case "MX":
			if len(split) < 6 {
				sb.WriteString("Usage: dns set MX <host> <target> <priority> <protected>\n")
				break
			}

			prio, err := strconv.Atoi(split[5])
			if err != nil {
				sb.WriteString("Failed to parse priority: " + err.Error() + "\n")
				break
			}

			record = db.MXRecord{
				ID:        id,
				Domain:    split[3],
				Target:    split[4],
				Priority:  uint16(prio),
				Protected: protected,
			}
		case "CNAME":
			record = db.CNAMERecord{
				ID:        id,
				Domain:    split[3],
				Target:    split[4],
				Protected: protected,
			}
		default:
			sb.WriteString("Unsupported record type: " + split[2] + "\n")
		}

		if record != nil {
			err = db.InsertRecord(record, false)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		}

		sb.WriteString("Record updated. ID: " + strconv.Itoa(int(id)) + "\n")
	case "del":
		sb.WriteString("Delete DNS record\n")

		if len(split) < 3 {
			sb.WriteString("Usage: dns del <id> <host>\n")
			break
		}

		sb.WriteString("Deleting record with id " + split[2] + "\n")
		id, err := strconv.ParseUint(split[2], 10, 64)
		if err != nil {
			sb.WriteString("Failed to parse id: " + err.Error() + "\n")
			break
		}

		err = db.DeleteRecord(id, split[3], false)
		if err != nil {
			sb.WriteString("Failed to delete record: " + err.Error() + "\n")
		}
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	// model.Output += sb.String()
	services.ProcessService.InfoLog(sb.String())
}
