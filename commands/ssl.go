package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"wiredshield/modules/db"

	"golang.org/x/crypto/acme"
)

var (
	accountKey *ecdsa.PrivateKey
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

		model.Output += "Generating certificate for " + split[2] + "...\n"
		if err := generateCertWithDNS(split[2], model); err != nil {
			model.Output += "Failed to generate certificate: " + err.Error() + "\n"
		} else {
			model.Output += "Certificate generated successfully.\n"
		}

	case "renew":
		model.Output += "Renew certificate\n"
		model.Output += "Not implemented yet.\n"

	default:
		model.Output += "Invalid command.\n"
	}
}

// generateCertWithDNS handles the ACME certificate generation process with DNS validation
func generateCertWithDNS(domain string, model *Model) error {
	// check if the cert already exists
	model.Output += fmt.Sprintf("Generating certificate for %s...\n", domain)

	privateKey, err := getDomainPrivateKey(domain)
	if err != nil {
		return fmt.Errorf("failed to get domain private key: %v", err)
	}

	accountKey, err := getAccountKey()
	if err != nil {
		return fmt.Errorf("failed to retrieve account key: %v", err)
	}

	client := &acme.Client{
		DirectoryURL: acme.LetsEncryptURL,
		Key:          accountKey,
	}

	// register acme account
	if err := registerACMEAccount(client); err != nil {
		// skip err for now
	}

	// start the ACME order
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
			continue
		}

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

		// prepare TXT record
		txtRecord, err := computeDNS01Response(challenge.Token, privateKey)
		if err != nil {
			return fmt.Errorf("failed to compute DNS-01 challenge response: %v", err)
		}
		txtDomain := "_acme-challenge." + domain

		// set DNS TXT record
		model.Output += fmt.Sprintf("Setting DNS TXT record for validation: %s -> %s\n", txtDomain, txtRecord)
		if err := db.SetRecord("TXT", txtDomain, txtRecord, false); err != nil {
			return fmt.Errorf("failed to set TXT record: %v", err)
		}

		// wait for DNS propagation
		model.Output += fmt.Sprintf("Waiting for DNS propagation for %s...\n", txtDomain)
		time.Sleep(2 * time.Second)
		model.Output += "DNS propagated.\n"

		// notify LE to validate the challenge
		if _, err := client.Accept(ctx, challenge); err != nil {
			return fmt.Errorf("failed to accept challenge: %v", err)
		}

		// poll authorization status
		model.Output += fmt.Sprintf("Polling authorization status for %s...\n", domain)
		for {
			auth, err := client.GetAuthorization(ctx, auth.URI)
			if err != nil {
				return fmt.Errorf("failed to retrieve failed authorization: %v", err)
			}

			// check for invalid challenges
			for _, challenge := range auth.Challenges {
				if challenge.Status == acme.StatusInvalid {
					return fmt.Errorf("challenge failed for %s: %s", challenge.Type, challenge.Error.Error())
				}
			}

			if auth.Status == acme.StatusValid {
				model.Output += fmt.Sprintf("Authorization for %s completed successfully.\n", domain)
				break
			} else if auth.Status == acme.StatusInvalid {
				return fmt.Errorf("authorization failed for %s. Status: %s", domain, auth.Status)
			}

			model.Output += "Waiting for authorization...\n"
			time.Sleep(5 * time.Second)
		}

		// clean up TXT record
		model.Output += fmt.Sprintf("Deleting DNS TXT record: %s\n", txtDomain)
		if err := db.DeleteRecord("TXT", txtDomain); err != nil {
			return fmt.Errorf("failed to delete TXT record: %v", err)
		}
	}

	// generate and save the certificate
	model.Output += fmt.Sprintf("Finalizing certificate order for %s...\n", domain)
	csrKey, err := generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key for CSR: %v", err)
	}

	csrDER, err := generateCSR(domain, csrKey)
	if err != nil {
		return fmt.Errorf("failed to generate CSR: %v", err)
	}

	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("failed to finalize certificate order: %v", err)
	}

	// save certificate and key
	certFile := fmt.Sprintf("./certs/%s.crt", domain)
	if err := saveCert(certFile, certDER); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	keyFile := fmt.Sprintf("./certs/%s.key", domain)
	if err := saveCertAndKey(certFile, keyFile, certDER, csrKey); err != nil {
		return fmt.Errorf("failed to save certificate and key: %v", err)
	}

	model.Output += fmt.Sprintf("Certificate for %s successfully created and stored at %s and %s.\n", domain, certFile, keyFile)
	return nil
}

// registerACMEAccount ensures the account is registered with the ACME provider
func registerACMEAccount(client *acme.Client) error {
	account := &acme.Account{
		Contact: []string{"mailto:ssl@northernsi.de"}, // update with the actual contact email
	}

	if _, err := client.Register(context.Background(), account, acme.AcceptTOS); err != nil {
		return fmt.Errorf("failed to register ACME account: %v", err)
	}

	return nil
}

// generatePrivateKey creates a new ECDSA private key
func generatePrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// generateCSR generates a CSR (Certificate Signing Request)
func generateCSR(domain string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	return x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
}

// saveCert saves the certificate in PEM format
func saveCert(certFile string, certDER [][]byte) error {
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER[0],
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate to PEM: %v", err)
	}

	return nil
}

// saveCertAndKey saves both the certificate and private key
func saveCertAndKey(certFile, keyFile string, certDER [][]byte, privateKey *ecdsa.PrivateKey) error {
	// save certificate
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER[0],
	})
	if err != nil {
		return fmt.Errorf("failed to encode certificate to PEM: %v", err)
	}

	// save private key
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %v", err)
	}

	err = pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %v", err)
	}

	return nil
}

// getAccountKey retrieves or generates the account key
func getAccountKey() (*ecdsa.PrivateKey, error) {
	if accountKey != nil {
		return accountKey, nil
	}

	const keyFile = "./certs/account.key"
	if _, err := os.Stat(keyFile); err == nil {
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read account key file: %v", err)
		}

		block, _ := pem.Decode(keyPEM)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("invalid PEM block in account key file")
		}

		accountKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v", err)
		}

		return accountKey, nil
	}

	// generate new key if not exists
	accountKey, err := generatePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate account key: %v", err)
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(accountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EC private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save account key: %v", err)
	}

	return accountKey, nil
}

// getDomainPrivateKey retrieves the domain private key, creating one if it doesn't exist
func getDomainPrivateKey(domain string) (*ecdsa.PrivateKey, error) {
	keyFile := fmt.Sprintf("./certs/%s.key", domain)

	// check if key exists
	if _, err := os.Stat(keyFile); err == nil {
		// use existing key
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read domain private key file: %v", err)
		}

		block, _ := pem.Decode(keyPEM)
		if block == nil || block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("invalid PEM block in domain private key file")
		}

		privateKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse domain private key: %v", err)
		}

		return privateKey, nil
	}

	// gen new key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate domain private key: %v", err)
	}

	// save the new key
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal domain private key: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// save to disk
	if err := os.MkdirAll("./certs", 0755); err != nil {
		return nil, fmt.Errorf("failed to create certs directory: %v", err)
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to save domain private key: %v", err)
	}

	return privateKey, nil
}

// computeDNS01Response computes the DNS-01 challenge response based on the token
func computeDNS01Response(token string, privateKey *ecdsa.PrivateKey) (string, error) {
	keyAuthorization := token + "." + base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.X.Bytes())
	digest := sha256.Sum256([]byte(keyAuthorization))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign DNS-01 challenge: %v", err)
	}

	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	return encodedSignature, nil
}
