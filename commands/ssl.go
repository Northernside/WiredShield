package commands

import (
	fmtfmt "fmt"
	"os"
	"strings"
	ssl "wiredshield/commands/libs"
	"wiredshield/commands/libs/fmt"
)

func Ssl(model *Model) {
	//split := strings.Split(model.TextInput.Value(), " ")
	split := strings.Split("ssl generate dawg.pics", " ")
	if len(split) < 3 {
		// model.Output += "Usage: ssl <generate|renew> <domain>\n"
		return
	}

	action := split[1]
	if len(split) < 3 && action == "generate" {
		// model.Output += "Usage: ssl generate <domain>\n"
		return
	}

	switch action {
	case "generate":
		///model.Output += "Generating certificate for " + split[2] + "...\n"
		fmt.Printf("Generating certificate for %s...\n", split[2])

		certPEM, keyPEM, err := ssl.GenerateCertificate("dawg.pics")
		if err != nil {
			fmt.Printf("failed to generate certificate: %v", err)
			return
		}

		//s ave to certs/<domain>
		certFile := fmtfmt.Sprintf("certs/%s.crt", split[2])
		keyFile := fmtfmt.Sprintf("certs/%s.key", split[2])

		writer, err := os.Create(certFile)
		if err != nil {
			fmt.Printf("failed to create cert file: %v", err)
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

		//model.Output += "Certificate generated.\n"

	case "renew":
		//model.Output += "Renew certificate\n"
		//model.Output += "Not implemented yet.\n"

	default:
		//model.Output += "Invalid command.\n"
	}
}
