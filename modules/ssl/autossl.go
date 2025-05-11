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
	"time"
	"wired/modules/logger"

	"golang.org/x/crypto/acme"
)

var (
	client *acme.Client
	ctx    = context.Background()
)

func init() {
	client = getClient()
	if client == nil {
		logger.Println("Failed to initialize ACME client")
		return
	}
}

func GenerateSANCertificate(domains map[string]string) (time.Time, time.Time, error) {
	logger.Printf("Generating SAN certificate for %v\n", domains)

	certPEM, keyPEM, err := prepareCertificate(domains)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	domainList := make([]string, 0, len(domains))
	for _, domain := range domains {
		domainList = append(domainList, domain)
	}

	batchID := generateBatchID(domainList)
	certFile := fmt.Sprintf("certs/san_%s.crt", batchID)
	keyFile := fmt.Sprintf("certs/san_%s.key", batchID)

	if err := os.MkdirAll("certs", 0755); err != nil {
		return time.Time{}, time.Time{}, err
	}

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return time.Time{}, time.Time{}, err
	}

	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		os.Remove(certFile)
		return time.Time{}, time.Time{}, err
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}

	for _, domain := range domains {
		oldCert := fmt.Sprintf("certs/%s.crt", domain)
		oldKey := fmt.Sprintf("certs/%s.key", domain)
		os.Remove(oldCert)
		os.Remove(oldKey)
	}

	return cert.NotBefore, cert.NotAfter, nil
}

func GenerateCertificate(domains map[string]string) (time.Time, time.Time, error) {
	logger.Println("Generating SSL certificate for ", domains)

	certPEM, keyPEM, err := prepareCertificate(domains)
	if err != nil {
		logger.Println("Failed to generate certificate: ", err.Error())
		return time.Time{}, time.Time{}, err
	}

	domainList := make([]string, 0, len(domains))
	for _, domain := range domains {
		domainList = append(domainList, domain)
	}

	batchID := generateBatchID(domainList)
	certFile := fmt.Sprintf("certs/%s.crt", batchID)
	keyFile := fmt.Sprintf("certs/%s.key", batchID)

	if _, err := os.Stat("certs"); os.IsNotExist(err) {
		err := os.Mkdir("certs", 0755)
		if err != nil {
			logger.Println("Failed to create certs directory: ", err)
			return time.Time{}, time.Time{}, err
		}
	}

	writer, err := os.Create(certFile)
	if err != nil {
		logger.Println("Failed to create cert file: ", err)
		return time.Time{}, time.Time{}, err
	}
	defer writer.Close()
	writer.Write(certPEM)

	writer, err = os.Create(keyFile)
	if err != nil {
		logger.Println("failed to create key file: ", err)
		return time.Time{}, time.Time{}, err
	}
	defer writer.Close()
	writer.Write(keyPEM)

	block, _ := pem.Decode(certPEM)
	if block == nil {
		logger.Println("Failed to decode PEM block for certificate")
		return time.Time{}, time.Time{}, errors.New("failed to decode PEM block for certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		logger.Println("Failed to parse certificate:", err)
		return time.Time{}, time.Time{}, err
	}

	expirationTime := cert.NotAfter
	issuedAt := cert.NotBefore
	renewalTime := expirationTime.Add(-7 * 24 * time.Hour)

	for _, domain := range domains {
		logger.Printf("Certificate for %s expires on %s. Renewal scheduled in %v.\n",
			domain,
			expirationTime.Format("2006-01-02 15:04:05"),
			time.Until(renewalTime).Round(time.Minute),
		)
	}

	logger.Println("Generated a SSL certificate for ", domains)
	return issuedAt, expirationTime, nil
}

func prepareCertificate(domains map[string]string) ([]byte, []byte, error) {
	if client == nil {
		return nil, nil, errors.New("failed to get ACME client")
	}

	domainList := make([]string, 0, len(domains))
	for _, domain := range domains {
		domainList = append(domainList, domain)
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domainList...))
	if err != nil {
		return nil, nil, fmt.Errorf("authorization failed: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return nil, nil, err
		}

		domain := authz.Identifier.Value
		if err := dns01Handling(domains, authzURL); err != nil {
			return nil, nil, fmt.Errorf("DNS challenge failed for %s: %w", domain, err)
		}
	}

	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, nil, err
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	csr, err := createCSR(domainList, certKey)
	if err != nil {
		return nil, nil, err
	}

	certDER, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, err
	}

	var certPEM []byte
	for _, der := range certDER {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		})...)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certKey),
	})

	return certPEM, keyPEM, nil
}

func createCSR(domains []string, key *rsa.PrivateKey) ([]byte, error) {
	tmpl := x509.CertificateRequest{
		DNSNames: domains,
		Subject:  pkix.Name{CommonName: domains[0]},
	}

	return x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
}
