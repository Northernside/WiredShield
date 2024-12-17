package commands

import (
	"fmt"
	"os"
	"strings"
	"time"
	ssl "wiredshield/commands/libs"
	"wiredshield/services"
)

var service *services.Service

func init() {
	service = services.RegisterService("ssl", "SSL Service")
	service.Boot = func() {
		service.InfoLog("AutoSSL service booted.\n")
		service.OnlineSince = time.Now().Unix()
	}

	service.Boot()
}

func Ssl(model *Model) {
	split := strings.Split(model.TextInput.Value(), " ")
	if len(split) < 3 {
		service.InfoLog("Usage: ssl <generate|renew|info> <domain>\n")
		return
	}

	action := split[1]
	switch action {
	case "generate":
		if len(split) < 3 {
			service.InfoLog("Usage: ssl generate <domain>\n")
			return
		}
    
		service.InfoLog("Generating certificate for " + split[2] + "...\n")
		certPEM, keyPEM, err := ssl.GenerateCertificate(split[2])
		if err != nil {
			model.Output += "Failed to generate certificate: " + err.Error() + "\n"
			return
		}

		// save to certs/<domain>
		certFile := fmt.Sprintf("certs/%s.crt", split[2])
		keyFile := fmt.Sprintf("certs/%s.key", split[2])

		writer, err := os.Create(certFile)
		if err != nil {
			service.ErrorLog(fmt.Sprintf("Failed to create cert file: %v", err))
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

		service.InfoLog("Certificate for " + split[2] + " generated successfully.\n")
	case "renew":
		service.InfoLog("Renewing certificate not implemented yet.\n")
	case "info":
		service.InfoLog("Certificate info not implemented yet.\n")
	default:
		service.InfoLog("Usage: ssl <generate|renew|info> <domain>\n")
	}
}
