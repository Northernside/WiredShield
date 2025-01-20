package ssl

import (
	"fmt"
	"io"
	"net/http"
	"wiredshield/modules/env"
	"wiredshield/services"
	"wiredshield/utils/b64"
	"wiredshield/utils/signing"
)

func syncSet(domain, certContent, keyContent string) error {
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

	req.Header.Set("change_action", "SET")
	req.Header.Set("domain", domain)
	req.Header.Set("cert", b64.Encode(certContent))
	req.Header.Set("key", b64.Encode(keyContent))

	signing.SignHTTPRequest(req, env.GetEnv("CLIENT_NAME", ""))
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

func syncDel(domain string) error {
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
	req.Header.Set("domain", domain)

	signing.SignHTTPRequest(req, env.GetEnv("CLIENT_NAME", ""))
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
