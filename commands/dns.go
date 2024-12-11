package commands

import (
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
			for _, record := range list {
				switch record.(type) {
				case db.ARecord:
					r := record.(db.ARecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " A " + r.Domain + " " + r.IP + "\n")
				case db.AAAARecord:
					r := record.(db.AAAARecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " AAAA " + r.Domain + " " + r.IP + "\n")
				case db.SOARecord:
					r := record.(db.SOARecord)
					sb.WriteString("SOA " + r.Domain + " " + r.PrimaryNS + " " + r.AdminEmail + " " + strconv.Itoa(int(r.Serial)) + " " + strconv.Itoa(int(r.Refresh)) + " " + strconv.Itoa(int(r.Retry)) + " " + strconv.Itoa(int(r.Expire)) + " " + strconv.FormatUint(uint64(r.MinimumTTL), 10) + "\n")
				case db.TXTRecord:
					r := record.(db.TXTRecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " TXT " + r.Domain + " " + r.Text + "\n")
				case db.NSRecord:
					r := record.(db.NSRecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " NS " + r.Domain + " " + r.NS + "\n")
				case db.MXRecord:
					r := record.(db.MXRecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " MX " + r.Domain + " " + r.Target + " " + strconv.Itoa(int(r.Priority)) + "\n")
				case db.CNAMERecord:
					r := record.(db.CNAMERecord)
					sb.WriteString(func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}() + " CNAME " + r.Domain + " " + r.Target + "\n")
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
		switch split[2] {
		case "A":
			record := db.ARecord{
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}

			err := db.UpdateRecord("A", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		case "AAAA":
			record := db.AAAARecord{
				Domain:    split[3],
				IP:        split[4],
				Protected: protected,
			}

			err := db.UpdateRecord("AAAA", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
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

			record := db.SOARecord{
				Domain:     split[3],
				PrimaryNS:  split[4],
				AdminEmail: split[5],
				Serial:     uint32(serial),
				Refresh:    uint32(refresh),
				Retry:      uint32(retry),
				Expire:     uint32(expire),
				MinimumTTL: uint32(minimum),
			}

			err = db.UpdateRecord("SOA", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		case "TXT":
			text := strings.Join(split[4:], " ")
			record := db.TXTRecord{
				Domain:    split[3],
				Text:      text,
				Protected: protected,
			}

			err := db.UpdateRecord("TXT", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		case "NS":
			record := db.NSRecord{
				Domain:    split[3],
				NS:        split[4],
				Protected: protected,
			}

			err := db.UpdateRecord("NS", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		case "MX":
			prio, err := strconv.Atoi(split[5])
			if err != nil {
				sb.WriteString("Failed to parse priority: " + err.Error() + "\n")
				break
			}

			record := db.MXRecord{
				Domain:    split[3],
				Target:    split[4],
				Priority:  uint16(prio),
				Protected: protected,
			}

			err = db.UpdateRecord("MX", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		case "CNAME":
			record := db.CNAMERecord{
				Domain:    split[3],
				Target:    split[4],
				Protected: protected,
			}

			err := db.UpdateRecord("CNAME", split[3], record)
			if err != nil {
				sb.WriteString("Failed to update record: " + err.Error() + "\n")
			}
		default:
			sb.WriteString("Unsupported record type: " + split[2] + "\n")
		}
	case "get":
		sb.WriteString("Get DNS record\n")
		if len(split) < 3 {
			sb.WriteString("Usage: dns get <host>\n")
			break
		}

	case "del":
		sb.WriteString("Delete DNS record\n")
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	model.Output += sb.String()
}
