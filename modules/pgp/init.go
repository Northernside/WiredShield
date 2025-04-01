package pgp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"wired/modules/env"
	"wired/modules/logger"
)

var (
	PrivateKey          *rsa.PrivateKey
	PublicKey           *rsa.PublicKey
	MarshalledPublicKey []byte
)

func init() {
	env.LoadEnvFile()
}

func InitKeys() {
	nodeName := env.GetEnv("NODE_KEY", "master")
	privateKeyFileName := "keys/" + nodeName + "-private.pem"
	publicKeyFileName := "keys/" + nodeName + "-public.pem"

	if privateKeyFileName == "" || publicKeyFileName == "" {
		logger.Fatal("NODE_KEY environment variable is not set")
		os.Exit(1)
	}

	_ = os.MkdirAll("keys", 0755)
	if _, err := os.Stat(privateKeyFileName); os.IsNotExist(err) {
		logger.Println("Key files do not exist, generating new key pair")

		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Fatal("Failed to generate private key:", err)
		}

		privateKeyFile, err := os.Create(privateKeyFileName)
		if err != nil {
			logger.Fatal("Failed to create private key file:", err)
		}
		defer privateKeyFile.Close()

		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		if err := pem.Encode(privateKeyFile, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}); err != nil {
			log.Fatalln("failed to encode private key:", err)
		}

		publicKeyFile, err := os.Create(publicKeyFileName)
		if err != nil {
			logger.Fatal("Failed to create public key file:", err)
		}
		defer publicKeyFile.Close()

		pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			logger.Fatal("Failed to marshal public key:", err)
		}
		if err := pem.Encode(publicKeyFile, &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}); err != nil {
			log.Fatalln("failed to encode public key:", err)
		}

		PrivateKey = priv
		PublicKey = &priv.PublicKey
		return
	}

	privateKeyFile, err := os.Open(privateKeyFileName)
	if err != nil {
		logger.Fatal("Failed to open private key file:", err)
		os.Exit(1)
	}
	defer privateKeyFile.Close()

	privateKeyBytes, err := io.ReadAll(privateKeyFile)
	if err != nil {
		logger.Fatal("Failed to read private key file:", err)
		os.Exit(1)
	}

	privateBlock, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		os.Exit(1)
	}

	publicKeyFile, err := os.Open(publicKeyFileName)
	if err != nil {
		logger.Fatal("Failed to open public key file:", err)
		os.Exit(1)
	}
	defer publicKeyFile.Close()

	publicKeyBytes, err := io.ReadAll(publicKeyFile)
	if err != nil {
		logger.Fatal("Failed to read public key file:", err)
		os.Exit(1)
	}

	publicBlock, _ := pem.Decode(publicKeyBytes)
	publicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		fmt.Println("Error parsing public key:", err)
		os.Exit(1)
	}

	PrivateKey = privateKey
	PublicKey = publicKey.(*rsa.PublicKey)
}
