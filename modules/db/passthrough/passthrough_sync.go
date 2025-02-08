package passthrough

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"wiredshield/modules/env"
	"wiredshield/services"
	"wiredshield/utils/signing"
)

func syncSet(passthrough Passthrough) error {
	var partnerMaster string
	if env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/passthrough-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "SET")

	req.Header.Set("id", strconv.Itoa(int(passthrough.Id)))
	req.Header.Set("domain", passthrough.Domain)
	req.Header.Set("path", passthrough.Path)
	req.Header.Set("target_addr", passthrough.TargetAddr)
	req.Header.Set("target_port", strconv.Itoa(int(passthrough.TargetPort)))
	req.Header.Set("target_path", passthrough.TargetPath)
	req.Header.Set("ssl", strconv.FormatBool(passthrough.Ssl))

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

func syncDel(id uint64) error {
	var partnerMaster string
	if env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/passthrough-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "DEL")
	req.Header.Set("id", fmt.Sprintf("%d", id))

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
