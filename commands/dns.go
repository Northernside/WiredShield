package commands

import (
	"fmt"
	"strconv"
	"strings"
	"wiredshield/modules/db"
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
		domains, err := db.GetAllDomains()
		if err != nil {
			sb.WriteString("failed to get domains: " + err.Error() + "\n")
			break
		}

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

		list, err := db.GetAllRecords(split[2])
		if err != nil {
			sb.WriteString("failed to get (meow) records: " + err.Error() + "\n")
			break
		}

		if len(list) == 0 {
			sb.WriteString("No records found for " + split[2] + "\n")
		} else {
			var index int = 0
			for _, record := range list {
				switch r := record.(type) {
				case db.ARecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" A %s %s\n", index, r.Domain, r.IP))
					index++
				case db.AAAARecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" AAAA %s %s\n", index, r.Domain, r.IP))
					index++
				case db.SOARecord:
					sb.WriteString(fmt.Sprintf("[%d] SOA %s %s %s %d %d %d %d %d\n", index, r.Domain, r.PrimaryNS, r.AdminEmail, r.Serial, r.Refresh, r.Retry, r.Expire, r.MinimumTTL))
				case db.TXTRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" TXT %s \"%s\"\n", index, r.Domain, r.Text))
					index++
				case db.NSRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" NS %s %s\n", index, r.Domain, r.NS))
					index++
				case db.MXRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" MX %s %s %d\n", index, r.Domain, r.Target, r.Priority))
				case db.CNAMERecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" CNAME %s %s\n", index, r.Domain, r.Target))
				default:
					sb.WriteString("Unknown record type\n")
				}
			}
		}
	case "set":
		sb.WriteString("Set DNS record\n")
		if len(split) < 6 {
			sb.WriteString("Usage: dns set <recordtype> <host> <target> <protected>\n")
			break
		}

		split[2] = strings.ToUpper(split[2])

		protected := split[5] == "true"
		var err error
		var record any

		switch split[2] {
		case "A":
			record = db.ARecord{
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}
		case "AAAA":
			record = db.AAAARecord{
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}
		case "SOA":
			if len(split) < 11 {
				sb.WriteString("Usage: dns set SOA <host> <primary> <admin> <serial> <refresh> <retry> <expire> <minimum> <protected>\n")
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
			text := strings.Join(split[4:], " ")
			record = db.TXTRecord{
				Domain:    split[3],
				Text:      text,
				Protected: protected,
			}
		case "NS":
			record = db.NSRecord{
				Domain:    split[3],
				NS:        split[4],
				Protected: protected,
			}
		case "MX":
			prio, err := strconv.Atoi(split[5])
			if err != nil {
				sb.WriteString("Failed to parse priority: " + err.Error() + "\n")
				break
			}

			record = db.MXRecord{
				Domain:    split[3],
				Target:    split[4],
				Priority:  uint16(prio),
				Protected: protected,
			}
		case "CNAME":
			record = db.CNAMERecord{
				Domain:    split[3],
				Target:    split[4],
				Protected: protected,
			}
		default:
			sb.WriteString("Unsupported record type: " + split[2] + "\n")
		}

		if record != nil {
			err = db.UpdateRecord(split[2], split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		}
	case "get":
		sb.WriteString("Get DNS record\n")
		if len(split) < 3 {
			sb.WriteString("Usage: dns get <host>\n")
			break
		}

	case "del":
		sb.WriteString("Delete DNS record\n")

		if len(split) < 4 {
			sb.WriteString("Usage: dns del <domain> <index>\n")
			break
		}

		list, err := db.GetAllRecords(split[2])
		if err != nil {
			sb.WriteString("failed to get records: " + err.Error() + "\n")
			break
		}

		if len(list) == 0 {
			sb.WriteString("No records found for " + split[2] + "\n")
			break
		}

		index, err := strconv.Atoi(split[3])
		if err != nil {
			sb.WriteString("Failed to parse index: " + err.Error() + "\n")
			break
		}

		if index < 0 || index >= len(list) {
			sb.WriteString("Index out of range\n")
			break
		}

		err = db.DeleteRecord(split[2], split[2], list[index])
		if err != nil {
			sb.WriteString("Failed to delete record: " + err.Error() + "\n")
		}

		sb.WriteString("Record deleted\n")
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	model.Output += sb.String()
}
