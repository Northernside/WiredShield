package b64

import "encoding/base64"

func Encode(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

func Decode(data string) (string, error) {
	decodedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	return string(decodedData), nil
}
