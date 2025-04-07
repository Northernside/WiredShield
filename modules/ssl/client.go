package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"golang.org/x/crypto/acme"
)

func getClient() *acme.Client {
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate account key: %v", err)
		return nil
	}

	_client := &acme.Client{
		Key:          accountKey,
		DirectoryURL: acme.LetsEncryptURL,
	}

	_, err = _client.Register(context.Background(), &acme.Account{
		Contact: []string{"mailto:ssl@wired.rip"},
	}, func(tosURL string) bool {
		return true
	})
	if err != nil {
		log.Fatalf("Failed to register account: %v", err)
	}

	return _client
}
