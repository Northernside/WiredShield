package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"wired/modules/logger"

	"golang.org/x/crypto/acme"
)

var (
	client *acme.Client
	ctx    = context.Background()
)

func GenerateCertificate(domain string) {
	logger.Println("Generating SSL certificate for ", domain)

	go func() {
		certPEM, keyPEM, err := prepareCertificate(domain)
		if err != nil {
			logger.Println("Failed to generate certificate: ", err.Error())
			return
		}

		// save to certs/<domain>
		certFile := fmt.Sprintf("certs/%s.crt", domain)
		keyFile := fmt.Sprintf("certs/%s.key", domain)

		writer, err := os.Create(certFile)
		if err != nil {
			logger.Println("Failed to create cert file: ", err)
			return
		}
		defer writer.Close()
		writer.Write(certPEM)

		writer, err = os.Create(keyFile)
		if err != nil {
			logger.Println("failed to create key file: ", err)
			return
		}
		defer writer.Close()
		writer.Write(keyPEM)

		logger.Println("Generated a SSL certificate for ", domain)
	}()
}

func prepareCertificate(domain string) ([]byte, []byte, error) {
	client = getClient()
	if client == nil {
		return nil, nil, errors.New("failed to get ACME client")
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, nil, err
	}

	if order.Status != acme.StatusPending {
		return nil, nil, errors.New(fmt.Sprintf("order status '%s' not pending", order.Status))
	}

	authzURLs := order.AuthzURLs
	for _, authzURL := range authzURLs {
		err = dns01Handling(domain, authzURL)
		if err != nil {
			return nil, nil, err
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, err
	}

	if order.Status != acme.StatusReady {
		return nil, nil, errors.New(fmt.Sprintf("order status '%s' not ready", order.Status))
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	csr, err := createCSR(domain, certKey)
	if err != nil {
		return nil, nil, err
	}

	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, err
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
		return nil, nil, errors.New("failed to encode private key to PEM")
	}

	// syncSet(domain, string(certPEM), string(privKeyPEM))
	return certPEM, privKeyPEM, nil
}

func createCSR(domain string, key *rsa.PrivateKey) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		DNSNames: []string{domain},
		Subject:  pkix.Name{CommonName: domain},
	}

	return x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
}
