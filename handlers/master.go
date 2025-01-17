package handlers

import (
	"fmt"
	"os"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/services"
)

func MasterHandling() {
	services.ProcessService.InfoLog("Running as master")
	handleKeys("master")
}

func handleKeys(clientName string) {
	publicKeyPath := fmt.Sprintf("certs/%s-public.asc", clientName)
	privateKeyPath := fmt.Sprintf("certs/%s-private.asc", clientName)

	// gen keys if not found
	if !fileExists(publicKeyPath) || !fileExists(privateKeyPath) {
		services.ProcessService.InfoLog("Keys not found, generating new keypair")
		if err := pgp.GenerateKeyPair(clientName); err != nil {
			services.ProcessService.FatalLog(fmt.Sprintf("Failed to generate keypair -> %s", err.Error()))
		}
	}

	// load server private key for master
	if env.GetEnv("MASTER", "false") == "true" {
		privateKey, err := pgp.LoadPrivateKey(privateKeyPath, "")
		if err != nil {
			services.ProcessService.FatalLog(fmt.Sprintf("Failed to load private key -> %s", err.Error()))
		}

		services.ServerPrivateKey = privateKey
	}
}

func fileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}

	return true
}
