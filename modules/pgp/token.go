package pgp

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
)

type Token struct {
	Message        string
	SigningDate    time.Time
	ExpirationDate time.Time
}

func GenerateToken(signingKey *openpgp.Entity, message string) (string, error) {
	token := Token{
		Message:        message,
		SigningDate:    time.Now(),
		ExpirationDate: time.Now().Add(time.Hour),
	}

	jsonMessage, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	signedMessage, err := SignMessage(string(jsonMessage), signingKey)
	if err != nil {
		return "", err
	}

	b64Message := base64.StdEncoding.EncodeToString([]byte(string(jsonMessage)))
	b64Signature := base64.StdEncoding.EncodeToString([]byte(signedMessage))

	return b64Message + "." + b64Signature, nil
}

func VerifyToken(token string, verificationKey *openpgp.Entity) (*Token, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("invalid token format")
	}

	decodedMessage, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	if err := VerifySignature(string(decodedMessage), string(decodedSignature), verificationKey); err != nil {
		return nil, err
	}

	var t Token
	if err := json.Unmarshal(decodedMessage, &t); err != nil {
		return nil, err
	}

	if t.ExpirationDate.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	return &t, nil
}
