package db

import (
	"fmt"
	"io"
	"net/http"
	_env "wiredshield/modules/env"
	"wiredshield/services"
	"wiredshield/utils/signing"
)

func syncSet(record DNSRecord) error {
	var partnerMaster string
	if _env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	services.ProcessService.InfoLog(fmt.Sprintf("partner master: %s", partnerMaster))

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/dns-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	services.ProcessService.InfoLog(fmt.Sprintf("req url: %s", req.URL.String()))

	req.Header.Set("change_action", "SET")
	req.Header.Set("change_record_type", record.GetType())
	req.Header.Set("id", fmt.Sprintf("%d", record.GetID()))
	req.Header.Set("dns_domain", record.GetDomain())

	// now check the type of record and set the appropriate fields
	switch record := record.(type) {
	case ARecord:
		req.Header.Set("dns_ip", record.IP)
		req.Header.Set("protected", fmt.Sprintf("%t", record.Protected))
	case AAAARecord:
		req.Header.Set("dns_ip", record.IP)
		req.Header.Set("protected", fmt.Sprintf("%t", record.Protected))
	case TXTRecord:
		req.Header.Set("dns_text", record.Text)
	case CNAMERecord:
		req.Header.Set("target", record.Target)
	case CAARecord:
		req.Header.Set("flag", fmt.Sprintf("%d", record.Flag))
	case MXRecord:
		req.Header.Set("priority", fmt.Sprintf("%d", record.Priority))
		req.Header.Set("target", record.Target)
	case SRVRecord:
		req.Header.Set("priority", fmt.Sprintf("%d", record.Priority))
		req.Header.Set("weight", fmt.Sprintf("%d", record.Weight))
		req.Header.Set("port", fmt.Sprintf("%d", record.Port))
	case SOARecord:
		req.Header.Set("dns_domain", record.Domain)
		req.Header.Set("primary_ns", record.PrimaryNS)
		req.Header.Set("admin_email", record.AdminEmail)
		req.Header.Set("serial", fmt.Sprintf("%d", record.Serial))
		req.Header.Set("refresh", fmt.Sprintf("%d", record.Refresh))
		req.Header.Set("retry", fmt.Sprintf("%d", record.Retry))
		req.Header.Set("expire", fmt.Sprintf("%d", record.Expire))
		req.Header.Set("minimum_ttl", fmt.Sprintf("%d", record.MinimumTTL))
	case NSRecord:
		req.Header.Set("ns", record.NS)
	default:
		services.ProcessService.ErrorLog(fmt.Sprintf("unknown record type: %T", record))
	}

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

	return nil
}

func syncDel(id uint64, domain string) error {
	var partnerMaster string
	if _env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s.wired.rip/.wiredshield/dns-update", partnerMaster), nil)
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "DEL")
	req.Header.Set("id", fmt.Sprintf("%d", id))
	req.Header.Set("dns_domain", domain)

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
