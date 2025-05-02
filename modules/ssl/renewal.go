package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"
	"wired/modules/logger"
	"wired/services/http"
)

func StartRenewalChecker() {
	ticker := time.NewTicker(48 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		var domains []string
		logger.Println("Checking for certificates to renew...")
		for domain, cert := range http.CertMap {
			if cert.Leaf == nil {
				if len(cert.Certificate) == 0 {
					logger.Println(fmt.Sprintf("No certificate data for %s", domain))
					continue
				}

				leaf, err := x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					logger.Println(fmt.Sprintf("Error parsing leaf cert for %s: %v", domain, err))
					continue
				}

				cert.Leaf = leaf
				http.CertMap[domain] = cert
			}

			if time.Until(cert.Leaf.NotAfter) <= 90*24*time.Hour {
				domains = append(domains, domain)
			}
		}

		if len(domains) == 0 {
			logger.Println("No certificates to renew")
			return
		} else {
			logger.Println(fmt.Sprintf("Renewing %d certificates: %s", len(domains), domains))
		}

		batchSize := 100
		for i := 0; i < len(domains); i += batchSize {
			end := min(i+batchSize, len(domains))
			batch := domains[i:end]

			certPEM, keyPEM, err := prepareCertificate(batch)
			if err != nil {
				logger.Println(fmt.Sprintf("Failed to renew batch %d-%d: %v", i, end, err))
				continue
			}

			block, _ := pem.Decode(certPEM)
			if block == nil {
				logger.Println("Failed to decode new certificate PEM")
				continue
			}

			newCert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Println(fmt.Sprintf("Failed to parse new certificate: %v", err))
				continue
			}

			tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				logger.Println(fmt.Sprintf("Failed to create TLS cert: %v", err))
				continue
			}

			tlsCert.Leaf = newCert

			http.CertMapLock.Lock()
			for _, dnsName := range newCert.DNSNames {
				http.CertMap[dnsName] = tlsCert
				os.Remove(fmt.Sprintf("certs/%s.crt", dnsName))
				os.Remove(fmt.Sprintf("certs/%s.key", dnsName))
			}
			http.CertMapLock.Unlock()

			batchID := generateBatchID(batch)
			certFile := fmt.Sprintf("certs/san_%s.crt", batchID)
			keyFile := fmt.Sprintf("certs/san_%s.key", batchID)
			os.WriteFile(certFile, certPEM, 0644)
			os.WriteFile(keyFile, keyPEM, 0600)

			logger.Println(fmt.Sprintf("Renewed batch of %d domains (expires %s)",
				len(batch), newCert.NotAfter.Format("2006-01-02")))

			// (300 orders / 3h = 1 order / 36s)
			time.Sleep(36 * time.Second)
		}
	}
}
