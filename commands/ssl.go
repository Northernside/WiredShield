package commands

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"
	"wiredshield/modules/db"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type DNSProvider struct{}

func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	txtRecord := keyAuth
	txtDomain := "_acme-challenge." + domain

	return db.SetRecord("TXT", txtDomain, txtRecord, false)
}

func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	txtDomain := "_acme-challenge." + domain
	return db.DeleteRecord("TXT", txtDomain)
}

func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 10 * time.Minute, 15 * time.Second
}

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

func generateCertWithDNS(domain string, model *Model) error {
	// key gen
	if err := os.MkdirAll("./certs", 0755); err != nil {
		return fmt.Errorf("failed to create certs directory: %v", err)
	}

	privateKey, err := generatePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	user := User{
		Email: "ssl@northernsi.de",
		Key:   privateKey,
	}

	// lego init
	config := lego.NewConfig(&user)
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %v", err)
	}

	// dns prov handling
	provider := &DNSProvider{}
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return fmt.Errorf("failed to set DNS-01 challenge provider: %v", err)
	}

	// acc handling
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register account: %v", err)
	}

	user.Registration = reg
	model.Output += fmt.Sprintf("Registered with ACME server, URI: %s\n", reg.URI)

	// prepare cert req
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	// obtain cert
	model.Output += fmt.Sprintf("Obtaining certificate for %s...\n", domain)
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %v", err)
	}

	// save info
	certFile := fmt.Sprintf("./certs/%s.crt", domain)
	keyFile := fmt.Sprintf("./certs/%s.key", domain)

	if err := os.WriteFile(certFile, certificates.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	if err := os.WriteFile(keyFile, certificates.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	model.Output += fmt.Sprintf("Certificate for %s successfully created and stored at %s and %s.\n", domain, certFile, keyFile)
	return nil
}

func generatePrivateKey() (crypto.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}
