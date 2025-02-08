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
	"os"
	"strings"
	"wiredshield/modules/db"
	acme_http "wiredshield/modules/db/acme"
	"wiredshield/modules/epoch"
	"wiredshield/services"

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

func GenerateCertificate(domain string, dnsChal bool) ([]byte, []byte, error) {
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
		err = challengeHandling(domain, authzURL, dnsChal)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to handle challenge: %v", err)
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

	go syncSet(domain, string(certPEM), string(privKeyPEM))
	return certPEM, privKeyPEM, nil
}

func challengeHandling(domain string, authzURL string, dnsChal bool) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return errors.Errorf("failed to get authorization: %v", err)
	}

	if authz.Status != acme.StatusPending {
		return fmt.Errorf("authorization status '%s' not pending", authz.Status)
	}

	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if dnsChal && c.Type == "dns-01" {
			chal = c
			break
		} else if !dnsChal && c.Type == "http-01" {
			chal = c
			break
		}
	}

	if chal == nil {
		return fmt.Errorf("authorization challenge not available")
	}

	if dnsChal {
		return handleDNSChallenge(domain, chal)
	} else {
		return handleHTTPChallenge(domain, chal)
	}
}

func handleDNSChallenge(domain string, chal *acme.Challenge) error {
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

	_, err = client.Accept(ctx, chal)
	if err != nil {
		return errors.Errorf("failed to accept challenge: %v", err)
	}

	_, err = client.WaitAuthorization(ctx, chal.URI)
	if err != nil {
		return errors.Errorf("failed to wait for authorization: %v", err)
	}

	defer func() {
		err = db.DeleteRecord(id, "_acme-challenge."+domain, false)
		if err != nil {
			fmt.Printf("failed to delete TXT record: %v", err)
		}
	}()

	return nil
}

func handleHTTPChallenge(domain string, chal *acme.Challenge) error {
	token, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return errors.Errorf("failed to get HTTP-01 challenge response: %v", err)
	}

	// split by ".", then grab [0]
	var _token string = strings.Split(token, ".")[0]

	var httpChallenge acme_http.HttpChallenge = acme_http.HttpChallenge{
		PublicToken: _token,
		FullToken:   token,
		Domain:      domain,
	}

	err = acme_http.InsertHttpChallenge(httpChallenge, false)
	if err != nil {
		return errors.Errorf("failed to insert HTTP challenge: %v", err)
	}

	_, err = client.Accept(ctx, chal)
	if err != nil {
		return errors.Errorf("failed to accept challenge: %v", err)
	}

	_, err = client.WaitAuthorization(ctx, chal.URI)
	if err != nil {
		return errors.Errorf("failed to wait for authorization: %v", err)
	}

	defer func() {
		err = acme_http.DeleteHttpChallenge(_token, false)
		if err != nil {
			fmt.Printf("failed to delete HTTP challenge: %v", err)
		}
	}()

	return nil
}

func createCSR(domain string, key *rsa.PrivateKey) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		DNSNames: []string{domain},
		Subject:  pkix.Name{CommonName: domain},
	}

	return x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
}

func GenSSL(domain string, dnsChal bool) {
	services.ProcessService.InfoLog("Generating SSL certificate for " + domain)
	go func() {
		certPEM, keyPEM, err := GenerateCertificate(domain, dnsChal)
		if err != nil {
			services.ProcessService.ErrorLog("Failed to generate certificate: " + err.Error())
			return
		}

		// save to certs/<domain>
		certFile := fmt.Sprintf("certs/%s.crt", domain)
		keyFile := fmt.Sprintf("certs/%s.key", domain)

		writer, err := os.Create(certFile)
		if err != nil {
			services.ProcessService.ErrorLog("failed to create cert file: " + err.Error())
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

		services.ProcessService.InfoLog("SSL certificate for " + domain + " generated")
	}()
}
