package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"wiredshield/modules/db"

	"golang.org/x/crypto/acme"
)

func Ssl(model *Model) {
	split := strings.Split(model.TextInput.Value(), " ")
	if len(split) < 3 {
		model.Output += "Usage: ssl <generate|renew> <domain>\n"
		return
	}

	switch split[1] {
	case "generate":
		if len(split) < 3 {
			model.Output += "Usage: ssl generate <domain>\n"
			break
		}

		func() {
			model.Output += "Generating certificate for " + split[2] + "...\n"
			err := GenerateCertWithDNS(split[2], model)
			if err != nil {
				model.Output += "Failed to generate certificate: " + err.Error() + "\n"
			} else {
				model.Output += "Certificate generated successfully.\n"
			}
		}()
	case "renew":
		model.Output += "Renew certificate\n"
		model.Output += "Not implemented yet.\n"
	default:
		model.Output += "Invalid command.\n"
	}
}

func GenerateCertWithDNS(domain string, model *Model) error {
	if domain == "" {
		return fmt.Errorf("domain name cannot be empty")
	}

	certDir := "./certs"
	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
	}

	// start the ACME order for the domain
	model.Output += fmt.Sprintf("Starting ACME authorization for %s...\n", domain)
	ctx := context.Background()
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{
		{Type: "dns", Value: domain},
	})
	if err != nil {
		return fmt.Errorf("failed to start ACME authorization: %v", err)
	}

	// process DNS challenges
	model.Output += fmt.Sprintf("Processing DNS challenges for %s...\n", domain)
	for _, authzURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("failed to get authorization: %v", err)
		}

		if auth.Status == acme.StatusValid {
			continue // already valid
		}

		// grab the dns01 challenge
		model.Output += fmt.Sprintf("Processing DNS challenge for %s...\n", domain)
		var challenge *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				challenge = c
				break
			}
		}

		if challenge == nil {
			return fmt.Errorf("no DNS-01 challenge found for %s", domain)
		}

		// prepare the TXT record
		txtRecord := challenge.Token
		txtDomain := "_acme-challenge." + domain

		// set the DNS TXT record
		model.Output += fmt.Sprintf("Setting DNS TXT record for validation: %s -> %s\n", txtDomain, txtRecord)
		err = db.SetRecord("TXT", txtDomain, txtRecord, false)
		if err != nil {
			return fmt.Errorf("failed to set TXT record: %v", err)
		}

		// DNS propagation
		model.Output += fmt.Sprintf("Waiting for DNS propagation for %s...\n", txtDomain)
		time.Sleep(30 * time.Second)
		model.Output += "DNS propagated.\n"

		// notify LE to validate the challenge
		_, err = client.Accept(ctx, challenge)
		if err != nil {
			return fmt.Errorf("failed to accept challenge: %v", err)
		}

		// poll the auth status
		model.Output += fmt.Sprintf("Polling authorization status for %s...\n", domain)
		for {
			auth, err := client.GetAuthorization(ctx, auth.URI)
			if err != nil {
				return fmt.Errorf("failed to get authorization status: %v", err)
			}

			if auth.Status == acme.StatusValid {
				log.Printf("Authorization for %s completed successfully.\n", domain)
				break
			} else if auth.Status == acme.StatusInvalid {
				return fmt.Errorf("authorization failed for %s", domain)
			}

			model.Output += "Waiting for authorization...\n"
			time.Sleep(5 * time.Second)
		}

		// clean up the TXT record
		model.Output += fmt.Sprintf("Deleting DNS TXT record: %s\n", txtDomain)
		err = db.DeleteRecord("TXT", txtDomain)
		if err != nil {
			return fmt.Errorf("failed to delete TXT record: %v", err)
		}
	}

	// finalize the order
	model.Output += fmt.Sprintf("Finalizing certificate order for %s...\n", domain)
	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, nil, true)
	if err != nil {
		return fmt.Errorf("failed to finalize certificate order: %v", err)
	}

	// save the certificate
	certFile := fmt.Sprintf("%s/%s.crt", certDir, domain)
	keyFile := fmt.Sprintf("%s/%s.key", certDir, domain)
	err = saveCertAndKey(certFile, keyFile, certDER)
	if err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	log.Printf("Certificate for %s successfully created and stored at %s and %s.\n", domain, certFile, keyFile)
	return nil
}

func saveCertAndKey(certFile, keyFile string, certDER [][]byte) error {
	cert, err := x509.ParseCertificate(certDER[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	privateKey, err := generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate to PEM: %v", err)
	}

	// -> pem format
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	err = pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKey,
	})
	if err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %v", err)
	}

	return nil
}

func generatePrivateKey() ([]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC private key: %v", err)
	}

	privateKeyPEM, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %v", err)
	}

	return privateKeyPEM, nil
}
