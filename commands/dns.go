package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	ssl "wiredshield/commands/libs"
	"wiredshield/modules/db"
	"wiredshield/modules/epoch"
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

		list, err := db.GetRecordsByDomain(split[2])
		if err != nil {
			sb.WriteString("failed to get (meow) records: " + err.Error() + "\n")
			break
		}

		if len(list) == 0 {
			sb.WriteString("No records found for " + split[2] + "\n")
		} else {
			for _, record := range list {
				switch r := record.(type) {
				case db.ARecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" A %s %s\n", r.ID, r.Domain, r.IP))
				case db.AAAARecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" AAAA %s %s\n", r.ID, r.Domain, r.IP))
				case db.SOARecord:
					sb.WriteString(fmt.Sprintf("[%d] SOA %s %s %s %d %d %d %d %d\n", r.ID, r.Domain, r.PrimaryNS, r.AdminEmail, r.Serial, r.Refresh, r.Retry, r.Expire, r.MinimumTTL))
				case db.TXTRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" TXT %s \"%s\"\n", r.ID, r.Domain, r.Text))
				case db.NSRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" NS %s %s\n", r.ID, r.Domain, r.NS))
				case db.MXRecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" MX %s %s %d\n", r.ID, r.Domain, r.Target, r.Priority))
				case db.CNAMERecord:
					sb.WriteString(fmt.Sprintf("[%d] "+func() string {
						if r.Protected {
							return "🔒"
						}
						return "🔓"
					}()+" CNAME %s %s\n", r.ID, r.Domain, r.Target))
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
				model.Output += "Generating SSL certificate for " + split[3] + "\n"
				certPEM, keyPEM, err := ssl.GenerateCertificate(split[3])
				if err != nil {
					model.Output += "Failed to generate certificate: " + err.Error() + "\n"
					return
				}

				// save to certs/<domain>
				certFile := fmt.Sprintf("certs/%s.crt", split[3])
				keyFile := fmt.Sprintf("certs/%s.key", split[3])

				writer, err := os.Create(certFile)
				if err != nil {
					model.Output += "failed to create cert file: " + err.Error() + "\n"
					return
				}
				defer writer.Close()
				writer.Write(certPEM)

				writer, err = os.Create(keyFile)
				if err != nil {
					fmt.Printf("failed to create key file: %v", err)
					return
				}
				defer writer.Close()
				writer.Write(keyPEM)

				model.Output += "SSL certificate for " + split[3] + " generated\n"
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
			text := strings.Join(split[4:], " ")
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
			err = db.InsertRecord(record)
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

		err = db.DeleteRecord(id, split[3])
		if err != nil {
			sb.WriteString("Failed to delete record: " + err.Error() + "\n")
		}
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	model.Output += sb.String()
}
