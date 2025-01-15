package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"wiredshield/modules/db"
	"wiredshield/modules/epoch"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

var client *acme.Client
var ctx = context.Background()

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

func GenerateCertificate(domain string) ([]byte, []byte, error) {
	client = getClient()
	if client == nil {
		return nil, nil, fmt.Errorf("failed to get ACME client")
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to authorize order: %v", err)
	}

	if order.Status != acme.StatusPending {
		return nil, nil, fmt.Errorf("authorize order status '%s' not pending", order.Status)
	}

	authzURLs := order.AuthzURLs
	for _, authzURL := range authzURLs {
		err = dns01Handling(domain, authzURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to handle DNS-01 challenge: %v", err)
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to wait for order: %v", err)
	}

	if order.Status != acme.StatusReady {
		return nil, nil, fmt.Errorf("order status '%s' not ready", order.Status)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate certificate key: %v", err)
	}

	csr, err := createCSR(domain, certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %v", err)
	}

	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %v", err)
	}

	var certPEM []byte
	for _, cert := range certDER {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})...)
	}

	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})
	if privKeyPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode private key to PEM")
	}

	return certPEM, privKeyPEM, nil
}

func dns01Handling(domain string, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return errors.Errorf("failed to get authorization: %v", err)
	}

	if authz.Status != acme.StatusPending {
		return fmt.Errorf("authorization status '%s' not pending", authz.Status)
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

	challengeText, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return errors.Errorf("failed to get DNS-01 challenge record: %v", err)
	}

	var id uint64
	snowflake, err := epoch.NewSnowflake(512)
	if err != nil {
		return errors.Errorf("failed to create snowflake: %v", err)
	}

	id = snowflake.GenerateID()
	txtRecord := db.TXTRecord{
		ID:        id,
		Domain:    "_acme-challenge." + domain,
		Text:      challengeText,
		Protected: false,
	}

	err = db.InsertRecord(txtRecord, false)
	if err != nil {
		return errors.Errorf("failed to update TXT record: %v", err)
	}

	defer func() {
		err = db.DeleteRecord(id, "_acme-challenge."+domain, false)
		if err != nil {
			fmt.Printf("failed to delete TXT record: %v", err)
		}
	}()

	_, err = client.Accept(ctx, chal)
	if err != nil {
		return errors.Errorf("failed to accept challenge: %v", err)
	}

	_, err = client.WaitAuthorization(ctx, chal.URI)
	if err != nil {
		return errors.Errorf("failed to wait for authorization: %v", err)
	}

	return nil
}

func createCSR(domain string, key *rsa.PrivateKey) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		DNSNames: []string{domain},
		Subject:  pkix.Name{CommonName: domain},
	}

	return x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
}
