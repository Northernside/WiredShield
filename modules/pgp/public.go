package pgp

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
)

func LoadPublicKey(filename string) (*openpgp.Entity, error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}

	keyring, err := openpgp.ReadArmoredKeyRing(file)
	if err != nil {
		return nil, err
	}

	if len(keyring) == 0 {
		return nil, fmt.Errorf("no public key found in %s", filename)
	}

	return keyring[0], nil
}

func VerifySignature(message, signature string, key *openpgp.Entity) error {
	messageReader := bytes.NewReader([]byte(message))
	signatureReader := bytes.NewReader([]byte(signature))

	keyRing := openpgp.EntityList{key}
	_, err := openpgp.CheckArmoredDetachedSignature(keyRing, messageReader, signatureReader)
	if err != nil {
		return err
	}

	return nil
}
