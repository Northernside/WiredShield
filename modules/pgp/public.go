package pgp

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(file)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	switch block.Type {
	case "RSA PUBLIC KEY":
		// PKCS#1 Format
		pubKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return pubKey, nil
	case "PUBLIC KEY":
		// PKCS#8 Format
		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		rsaPubKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("failed to assert public key as RSA")
		}

		return rsaPubKey, nil
	default:
		return nil, errors.New("unsupported key type: " + block.Type)
	}
}

func VerifySignature(message string, signature []byte, key *rsa.PublicKey) error {
	hashed := sha256.Sum256([]byte(message))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
}
