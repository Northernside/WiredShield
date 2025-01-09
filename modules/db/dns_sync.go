package db

import (
	"fmt"
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
	switch record.(type) {
	case ARecord:
		aRecord := record.(ARecord)
		req.Header.Set("dns_ip", aRecord.IP)
		req.Header.Set("protected", fmt.Sprintf("%t", aRecord.Protected))
	case AAAARecord:
		aaaaRecord := record.(AAAARecord)
		req.Header.Set("dns_ip", aaaaRecord.IP)
		req.Header.Set("protected", fmt.Sprintf("%t", aaaaRecord.Protected))
	case TXTRecord:
		txtRecord := record.(TXTRecord)
		req.Header.Set("text", txtRecord.Text)
	case CNAMERecord:
		cnameRecord := record.(CNAMERecord)
		req.Header.Set("target", cnameRecord.Target)
	case CAARecord:
		caaRecord := record.(CAARecord)
		req.Header.Set("flag", fmt.Sprintf("%d", caaRecord.Flag))
	case MXRecord:
		mxRecord := record.(MXRecord)
		req.Header.Set("priority", fmt.Sprintf("%d", mxRecord.Priority))
		req.Header.Set("target", mxRecord.Target)
	case SRVRecord:
		srvRecord := record.(SRVRecord)
		req.Header.Set("priority", fmt.Sprintf("%d", srvRecord.Priority))
		req.Header.Set("weight", fmt.Sprintf("%d", srvRecord.Weight))
		req.Header.Set("port", fmt.Sprintf("%d", srvRecord.Port))
	case SOARecord:
		soaRecord := record.(SOARecord)
		req.Header.Set("dns_domain", soaRecord.Domain)
		req.Header.Set("primary_ns", soaRecord.PrimaryNS)
		req.Header.Set("admin_email", soaRecord.AdminEmail)
		req.Header.Set("serial", fmt.Sprintf("%d", soaRecord.Serial))
		req.Header.Set("refresh", fmt.Sprintf("%d", soaRecord.Refresh))
		req.Header.Set("retry", fmt.Sprintf("%d", soaRecord.Retry))
		req.Header.Set("expire", fmt.Sprintf("%d", soaRecord.Expire))
		req.Header.Set("minimum_ttl", fmt.Sprintf("%d", soaRecord.MinimumTTL))
	case NSRecord:
		nsRecord := record.(NSRecord)
		req.Header.Set("ns", nsRecord.NS)
	}

	_, err = http.DefaultClient.Do(req)
	if err != nil {
		services.ProcessService.ErrorLog(fmt.Sprintf("failed to send request: %v", err))
	}

	return err
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
