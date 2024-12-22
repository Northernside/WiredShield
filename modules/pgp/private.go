package pgp

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/crypto/openpgp"
)

func LoadPrivateKey(filename string, passphrase string) (*openpgp.Entity, error) {
	file, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	keyring, err := openpgp.ReadArmoredKeyRing(file)
	if err != nil {
		return nil, err
	}

	if len(keyring) == 0 {
		return nil, fmt.Errorf("no private key found in %s", filename)
	}

	for _, entity := range keyring {
		if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
			if passphrase == "" {
				return nil, fmt.Errorf("private key is encrypted, but no passphrase provided")
			}

			bytePassword := []byte(passphrase)
			err = entity.PrivateKey.Decrypt(bytePassword)
			if err != nil {
				return nil, err
			}

			for _, subkey := range entity.Subkeys {
				if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
					err = subkey.PrivateKey.Decrypt([]byte(bytePassword))
					if err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return keyring[0], nil
}

func SignMessage(message string, key *openpgp.Entity) (string, error) {
	messageReader := bytes.NewReader([]byte(message))
	signatureWriter := new(bytes.Buffer)

	err := openpgp.ArmoredDetachSign(signatureWriter, key, messageReader, nil)
	if err != nil {
		return "", err
	}

	return signatureWriter.String(), nil
}
