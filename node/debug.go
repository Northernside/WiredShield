package main

import (
	"os"
	"strings"
	"wired/modules/logger"
	"wired/modules/ssl"
)

func convertSingleCertToSAN() {
	// get all certs/*.crt/key that do not start with "san_" and combine the domain names into one san

	files, err := os.ReadDir("certs")
	if err != nil {
		logger.Println("Failed to read certs directory:", err)
		return
	}

	domainList := make([]string, 0)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".crt") || strings.HasPrefix(file.Name(), "san_") {
			continue
		}

		domain := strings.TrimSuffix(file.Name(), ".crt")
		domainList = append(domainList, domain)
	}

	if len(domainList) == 0 {
		logger.Println("No certificates found to convert to SAN")
		return
	}

	_, _, err = ssl.GenerateSANCertificate(domainList)
	if err != nil {
		logger.Println("Failed to generate SAN certificate:", err)
		return
	}

	logger.Println("SAN certificate generated and saved for domains:", domainList)
}
