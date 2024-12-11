package commands

import (
	"strings"
)

func Ssl(model *Model) {
	split := strings.Split(model.TextInput.Value(), " ")
	if len(split) < 3 {
		model.Output += "Usage: ssl <generate|renew> <domain>\n"
		return
	}

	action := split[1]
	if len(split) < 3 && action == "generate" {
		model.Output += "Usage: ssl generate <domain>\n"
		return
	}

	switch action {
	case "generate":
		model.Output += "Generating certificate for " + split[2] + "...\n"

	case "renew":
		model.Output += "Renew certificate\n"
		model.Output += "Not implemented yet.\n"

	default:
		model.Output += "Invalid command.\n"
	}
}
