package pgp

import (
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func GenerateKeyPair(name string) error {
	entity, err := openpgp.NewEntity(name, "", "", nil)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create("./certs/" + name + "-private.asc")
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	privateKeyArmorWriter, err := armor.Encode(privateKeyFile, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	defer privateKeyArmorWriter.Close()

	err = entity.SerializePrivate(privateKeyArmorWriter, nil)
	if err != nil {
		return err
	}

	// Save the public key in ASCII-armored format
	publicKeyFile, err := os.Create("./certs/" + name + "-public.asc")
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	publicKeyArmorWriter, err := armor.Encode(publicKeyFile, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	defer publicKeyArmorWriter.Close()

	err = entity.Serialize(publicKeyArmorWriter)
	if err != nil {
		return err
	}

	return nil
}
