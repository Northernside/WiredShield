package commands

import (
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
			sb.WriteString("Failed to get records: " + err.Error() + "\n")
			break
		}

		if len(list) == 0 {
			sb.WriteString("No records found for " + split[2] + "\n")
		} else {
			for key, record := range list {
				// 🔒 & 🔓
				sb.WriteString(func() string {
					if record.Protected {
						return "🔒"
					}

					return "🔓"
				}() + key + " => " + record.Target + "\n")
			}
		}
	case "set":
		sb.WriteString("Set DNS record\n")
		if len(split) < 6 {
			sb.WriteString("Usage: dns set <recordtype> <host> <target> <protected>\n")
			break
		}

		split[2] = strings.ToUpper(split[2])
		err := db.SetRecord(split[2], split[3], split[4], split[5] == "true")
		if err != nil {
			sb.WriteString("Failed to set target: " + err.Error() + "\n")
		} else {
			sb.WriteString("Successfully set DNS record for " + split[3] + " to " + split[4] + "\n")
		}
	case "get":
		sb.WriteString("Get DNS record\n")
		if len(split) < 3 {
			sb.WriteString("Usage: dns get <host>\n")
			break
		}

		target, protected, err := db.GetRecord("A", split[2])
		if err != nil {
			sb.WriteString("Failed to get target: " + err.Error() + "\n")
		} else {
			sb.WriteString("Target for " + split[2] + " is " + target + " " + func() string {
				if protected {
					return "🔒"
				}

				return "🔓"
			}())
		}
	case "del":
		sb.WriteString("Delete DNS record\n")
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	model.Output += sb.String()
}
