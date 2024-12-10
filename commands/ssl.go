package commands

import (
	"fmt"
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

		resultCh := make(chan string)
		go func() {
			err := generateCertWithDNS(split[2], model)
			if err != nil {
				resultCh <- fmt.Sprintf("Failed to generate certificate: %s", err.Error())
			} else {
				resultCh <- "Certificate generated successfully."
			}
		}()

		model.Output += <-resultCh

	case "renew":
		model.Output += "Renew certificate\n"
		model.Output += "Not implemented yet.\n"

	default:
		model.Output += "Invalid command.\n"
	}
}

func generateCertWithDNS(domain string, model *Model) error {
	return nil
}
