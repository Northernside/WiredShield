package ssl

import (
	"fmt"
	"io"
	"net/http"
	"wiredshield/services"
	"wiredshield/utils/signing"
)

func syncSet(domain, certContent, keyContent string) error {
	req, err := http.NewRequest("GET", "https://meow.wired.rip/.wiredshield/dns-update", nil) // TODO: load urls by nodes
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "SET")
	req.Header.Set("domain", domain)
	req.Header.Set("cert", certContent)
	req.Header.Set("key", keyContent)

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

func syncDel(domain string) error {
	req, err := http.NewRequest("GET", "https://meow.wired.rip/.wiredshield/dns-update", nil) // TODO: load urls by nodes
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "DEL")
	req.Header.Set("domain", domain)

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
