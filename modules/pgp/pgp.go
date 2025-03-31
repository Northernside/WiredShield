package pgp

import (
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func GenerateKeyPair(name string, publicKeys map[string]*openpgp.Entity, serverPrivateKey **openpgp.Entity) error {
	entity, err := openpgp.NewEntity(name, "", "", nil)
	if err != nil {
		return err
	}

	privateKeyFile, err := os.Create("./keys/" + name + "-private.pem")
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
	publicKeyFile, err := os.Create("./keys/" + name + "-public.pem")
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

	// Store the public key in the map and the private key in the serverPrivateKey
	publicKeys[name+"-public.pem"] = entity

	*serverPrivateKey = entity // Update the value pointed to by the original pointer

	return nil
}
