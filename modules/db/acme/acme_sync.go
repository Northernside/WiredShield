package acme_http

import (
	"fmt"
	"io"
	"net/http"
	"wiredshield/modules/env"
	"wiredshield/services"
	"wiredshield/utils/signing"
)

func syncSet(httpChallenge HttpChallenge) error {
	var partnerMaster string
	if env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/acme-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "SET")
	req.Header.Set("domain", httpChallenge.Domain)
	req.Header.Set("public_token", httpChallenge.PublicToken)
	req.Header.Set("full_token", httpChallenge.FullToken)

	signing.SignHTTPRequest(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		services.ProcessService.ErrorLog(fmt.Sprintf("failed to send request: %v", err))
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	services.ProcessService.InfoLog(fmt.Sprintf("response (x): %s", string(bodyBytes)))

	return err
}

func syncDel(token string) error {
	var partnerMaster string
	if env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/ssl-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "DEL")
	req.Header.Set("public_token", token)

	signing.SignHTTPRequest(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		services.ProcessService.ErrorLog(fmt.Sprintf("failed to send request: %v", err))
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	services.ProcessService.InfoLog(fmt.Sprintf("response: %s", string(bodyBytes)))

	return err
}
