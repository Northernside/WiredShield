package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"wiredshield/modules/db"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

func main() {
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate account key: %v", err)
		return
	}

	dnsProvider := &ExampleDNSProvider{}
	domain := "dawg.pics"

	err = GenerateCertificate(dnsProvider, domain, accountKey)
	if err != nil {
		fmt.Printf("failed to generate certificate: %v", err)
		return
	}
}

type DNSProvider interface {
	SetTXTRecord(ctx context.Context, domain, value string) error
	DeleteTXTRecord(ctx context.Context, domain string) error
}

type ExampleDNSProvider struct{}

func (e *ExampleDNSProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	fmt.Printf("Setting TXT record: %s -> %s\n", domain, value)
	db.SetRecord("TXT", domain, value, false)
	return nil
}

func (e *ExampleDNSProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	fmt.Printf("Deleting TXT record: %s\n", domain)
	//db.DeleteRecord("TXT", domain)
	return nil
}

func GenerateCertificate(dnsProvider DNSProvider, domain string, accountKey *rsa.PrivateKey) error {
	ctx := context.Background()
	client := &acme.Client{
		DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		Key:          accountKey,
	}

	account := &acme.Account{
		Contact: []string{"mailto:ssl@northernsi.de"},
	}

	_, err := client.Register(ctx, account, acme.AcceptTOS)
	if err != nil {
		if err != acme.ErrAccountAlreadyExists {
			return errors.Errorf("failed to register account: %v", err)
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return errors.Errorf("failed to authorize order: %v", err)
	}

	if order.Status != acme.StatusPending {
		return fmt.Errorf("authorize order status '%s' not pending", order.Status)
	}

	authzURLs := order.AuthzURLs
	for _, authzURL := range authzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return errors.Errorf("failed to get authorization: %v", err)
		}

		if authz.Status != acme.StatusPending {
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}

		if chal == nil {
			return fmt.Errorf("authorization challenge not available")
		}

		txtRecord, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return errors.Errorf("failed to get DNS-01 challenge record: %v", err)
		}

		err = dnsProvider.SetTXTRecord(ctx, "_acme-challenge."+domain, txtRecord)
		if err != nil {
			return errors.Errorf("failed to set TXT record: %v", err)
		}

		defer func() {
			_ = dnsProvider.DeleteTXTRecord(ctx, "_acme-challenge."+domain)
		}()

		_, err = client.Accept(ctx, chal)
		if err != nil {
			return errors.Errorf("failed to accept challenge: %v", err)
		}

		_, err = client.WaitAuthorization(ctx, chal.URI)
		if err != nil {
			return errors.Errorf("failed to wait for authorization: %v", err)
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return errors.Errorf("failed to wait for order: %v", err)
	}

	if order.Status != acme.StatusReady {
		return fmt.Errorf("order status '%s' not ready", order.Status)
	}

	csr, err := createCSR(domain, accountKey)
	if err != nil {
		return errors.Errorf("failed to create CSR: %v", err)
	}

	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return errors.Errorf("failed to create certificate: %v", err)
	}

	certPem := ""
	for _, der := range certDER {
		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}
		certPem += string(pem.EncodeToMemory(certBlock))
	}

	err = os.WriteFile("cert.pem", []byte(certPem), 0644)
	if err != nil {
		return errors.Errorf("failed to save certificate: %v", err)
	}

	fmt.Println("Certificate obtained and saved to cert.pem")
	return nil
}

func createCSR(domain string, privKey crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
	}

	return x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
}
