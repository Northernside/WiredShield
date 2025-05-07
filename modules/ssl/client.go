package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"wired/modules/logger"

	"golang.org/x/crypto/acme"
)

func getClient() *acme.Client {
	sslClient := &SSLClient{}

	if _, err := os.Stat("ssl_client_key.json"); err == nil {
		sslClient.loadKey()
	} else {
		accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Fatal("Failed to generate account key: ", err)
		}

		sslClient.Key = accountKey
		sslClient.DirectoryURL = acme.LetsEncryptURL
		sslClient.saveKey()
	}

	client := &acme.Client{
		Key:          sslClient.Key,
		DirectoryURL: sslClient.DirectoryURL,
	}

	_, err := client.Register(context.Background(), &acme.Account{
		Contact: []string{"mailto:ssl@wired.rip"},
	}, func(tosURL string) bool {
		return true
	})
	if err != nil && err != acme.ErrAccountAlreadyExists {
		logger.Fatal("Failed to register account: ", err)
	}

	return client
}
