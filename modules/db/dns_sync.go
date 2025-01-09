package db

import (
	"fmt"
	"io"
	"net/http"
	"time"
	"wiredshield/modules/pgp"
	"wiredshield/services"
)

func syncSet(record DNSRecord) error {
	req, err := http.NewRequest("GET", "https://meow.wired.rip/.wiredshield/dns-update", nil) // TODO: load urls by nodes
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "SET")
	req.Header.Set("change_record_type", GetRecordType(record))
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
		req.Header.Set("text", record.Text)
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
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		services.ProcessService.ErrorLog(fmt.Sprintf("failed to send request: %v", err))
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
	req, err := http.NewRequest("GET", "https://meow.wired.rip/.wiredshield/dns-update", nil) // TODO: load urls by nodes
	if err != nil {
		return err
	}

	req.Header.Set("change_action", "DEL")
	req.Header.Set("id", fmt.Sprintf("%d", id))
	req.Header.Set("dns_domain", domain)

	/*
		logic:
			- send a signature (headers: signature and auth_message)
			-> auth message should be current timestamp in seconds
	*/

	timestamp := time.Now().Unix()
	req.Header.Set("auth_message", fmt.Sprintf("%d", timestamp))
	meowKey, err := pgp.LoadPrivateKey("certs/master-private.asc", "")
	if err != nil {
		return err
	}

	signature, err := pgp.SignMessage(fmt.Sprintf("%d", timestamp), meowKey)
	if err != nil {
		return err
	}

	req.Header.Set("signature", signature)

	_, err = http.DefaultClient.Do(req)
	if err != nil {
		services.ProcessService.ErrorLog(fmt.Sprintf("failed to send request: %v", err))
	}

	return err
}
