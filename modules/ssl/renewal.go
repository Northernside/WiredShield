package ssl

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
	"wired/modules/logger"
	"wired/services/http"
)

func StartRenewalChecker(ctx context.Context) {
	ticker := time.NewTicker(48 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Println("Stopping SSL renewal checker...")
			return
		case <-ticker.C:
			domains := []string{}
			logger.Println("Checking for certificates to renew...")
			for domain, sslEntry := range http.CertMap {
				if sslEntry.Cert.Leaf == nil {
					if len(sslEntry.Cert.Certificate) == 0 {
						logger.Printf("No certificate data for %s\n", domain)
						continue
					}

					leaf, err := x509.ParseCertificate(sslEntry.Cert.Certificate[0])
					if err != nil {
						logger.Printf("Error parsing leaf cert for %s: %v\n", domain, err)
						continue
					}

					sslEntry.Cert.Leaf = leaf
					http.CertMap[domain] = sslEntry
				}

				if time.Until(sslEntry.Cert.Leaf.NotAfter) <= 90*24*time.Hour {
					domains = append(domains, domain)
				}
			}

			if len(domains) == 0 {
				logger.Println("No certificates to renew")
				return
			} else {
				logger.Printf("Renewing %d certificates: %s\n", len(domains), domains)
			}

			batchSize := 100
			for i := 0; i < len(domains); i += batchSize {
				end := i + batchSize
				if end > len(domains) {
					end = len(domains)
				}

				batch := domains[i:end]
				logger.Printf("Renewing batch %d-%d: %s\n", i, end, batch)

				certPEM, keyPEM, err := prepareCertificate(batch)
				if err != nil {
					logger.Printf("Failed to renew batch %d-%d: %v\n", i, end, err)
					continue
				}

				block, _ := pem.Decode(certPEM)
				if block == nil {
					logger.Println("Failed to decode new certificate PEM")
					continue
				}

				newCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					logger.Printf("Failed to parse new certificate: %v\n", err)
					continue
				}

				tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					logger.Printf("Failed to create TLS cert: %v\n", err)
					continue
				}

				tlsCert.Leaf = newCert

				http.CertMapLock.Lock()
				for _, dnsName := range newCert.DNSNames {
					http.CertMap[dnsName].Cert = &tlsCert

					os.Remove(fmt.Sprintf("certs/%s.crt", dnsName))
					os.Remove(fmt.Sprintf("certs/%s.key", dnsName))
				}
				http.CertMapLock.Unlock()

				domainList := make([]string, 0, len(batch))
				for _, domain := range batch {
					domainList = append(domainList, domain)
				}

				batchID := generateBatchID(domainList)
				certFile := fmt.Sprintf("certs/san_%s.crt", batchID)
				keyFile := fmt.Sprintf("certs/san_%s.key", batchID)
				os.WriteFile(certFile, certPEM, 0644)
				os.WriteFile(keyFile, keyPEM, 0600)

				logger.Printf("Renewed batch of %d domains (expires %s)\n",
					len(batch), newCert.NotAfter.Format("2006-01-02"))

				// (300 orders / 3h = 1 order / 36s)
				time.Sleep(36 * time.Second)
			}
		}
	}
}
