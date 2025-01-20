package signing

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
	"wiredshield/modules/pgp"
)

func SignHTTPRequest(req *http.Request) error {
	/*
		logic:
			- send a signature (headers: signature and auth_message)
			-> auth message should be current timestamp in seconds
	*/

	timestamp := time.Now().Unix()
	req.Header.Set("auth_message", fmt.Sprintf("%d", timestamp))
	instanceKey, err := pgp.LoadPrivateKey("certs/master-private.asc", "")
	if err != nil {
		return err
	}

	signature, err := pgp.SignMessage(fmt.Sprintf("%d", timestamp), instanceKey)
	if err != nil {
		return err
	}

	b64Sig := base64.StdEncoding.EncodeToString([]byte(signature))
	req.Header.Set("signature", b64Sig)

	return nil
}
