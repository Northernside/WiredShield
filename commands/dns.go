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
			for k, v := range list {
				sb.WriteString(k + " => " + v + "\n")
			}
		}
	case "set":
		sb.WriteString("Set DNS record\n")
		if len(split) < 4 {
			sb.WriteString("Usage: dns set <host> <target>\n")
			break
		}

		err := db.SetRecord("A", split[2], split[3])
		if err != nil {
			sb.WriteString("Failed to set target: " + err.Error() + "\n")
		} else {
			sb.WriteString("Successfully set DNS record for " + split[2] + " to " + split[3] + "\n")
		}
	case "get":
		sb.WriteString("Get DNS record\n")
		if len(split) < 3 {
			sb.WriteString("Usage: dns get <host>\n")
			break
		}

		target, err := db.GetRecord("A", split[2])
		if err != nil {
			sb.WriteString("Failed to get target: " + err.Error() + "\n")
		} else {
			sb.WriteString("Target for " + split[2] + " is " + target + "\n")
		}
	case "del":
		sb.WriteString("Delete DNS record\n")
	default:
		sb.WriteString("Unknown command: " + split[1] + "\n")
	}

	model.Output += sb.String()
}
