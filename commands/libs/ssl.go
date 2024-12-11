package ssl

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"wiredshield/commands/libs/fmt"
	"wiredshield/modules/db"

	"github.com/pkg/errors"
	"golang.org/x/crypto/acme"
)

var client *acme.Client
var account *acme.Account
var ctx = context.Background()

func init() {
	client = getClient()
	if client == nil {
		fmt.Println("Failed to initialize ACME client")
		return
	}

	account = getAccount(client)
	if account == nil {
		fmt.Println("Failed to initialize ACME account")
	}
}

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

	return _client
}

func getAccount(_client *acme.Client) *acme.Account {
	_account := &acme.Account{
		Contact: []string{"mailto:ssl@northernsi.de"},
	}

	_, err := _client.Register(ctx, _account, acme.AcceptTOS)
	if err != nil {
		if err != acme.ErrAccountAlreadyExists {
			fmt.Printf("failed to register account: %v", err)
			return nil
		}
	}

	return _account
}

func GenerateCertificate(domain string) ([]byte, []byte, error) {
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

	certBytes := []byte{}
	for _, b := range certDER {
		certBytes = append(certBytes, b...)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if certPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode certificate to PEM")
	}

	privKeyBytes := x509.MarshalPKCS1PrivateKey(certKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privKeyBytes})
	if keyPEM == nil {
		return nil, nil, fmt.Errorf("failed to encode private key to PEM")
	}

	fmt.Println(string(certPEM))
	fmt.Println()
	fmt.Println()
	fmt.Println()
	fmt.Println(string(keyPEM))

	return certPEM, keyPEM, nil
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

	txtRecord, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return errors.Errorf("failed to get DNS-01 challenge record: %v", err)
	}

	db.SetRecord("TXT", "_acme-challenge."+domain, txtRecord, false)

	defer func() {
		db.DeleteRecord("TXT", "_acme-challenge."+domain)
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

func createCSR(domain string, privKey crypto.Signer) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
	}

	return x509.CreateCertificateRequest(rand.Reader, tmpl, privKey)
}
