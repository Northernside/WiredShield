package db

import (
	"encoding/json"
)

type DNSRecordType string

const (
	A     DNSRecordType = "A"
	AAAA  DNSRecordType = "AAAA"
	SOA   DNSRecordType = "SOA"
	CNAME DNSRecordType = "CNAME"
	NS    DNSRecordType = "NS"
	MX    DNSRecordType = "MX"
	TXT   DNSRecordType = "TXT"
	CAA   DNSRecordType = "CAA"
	SRV   DNSRecordType = "SRV"
)

// list of supported DNS record types
var SupportedRecordTypes = []DNSRecordType{A, AAAA, SOA, CNAME, NS, MX, TXT, CAA, SRV}

type DNSRecord interface {
	Type() DNSRecordType
	GetID() uint64
	Serialize() (string, error)
}

type ARecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Protected bool   `json:"protected"`
}

func (r ARecord) Type() DNSRecordType { return A }
func (r ARecord) GetID() uint64       { return r.ID }
func (r ARecord) Serialize() (ARecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return ARecord{}, err
	}

	var record ARecord
	if err := json.Unmarshal(data, &record); err != nil {
		return ARecord{}, err
	}

	return record, nil
}

type AAAARecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Protected bool   `json:"protected"`
}

func (r AAAARecord) Type() DNSRecordType { return AAAA }
func (r AAAARecord) GetID() uint64       { return r.ID }
func (r AAAARecord) Serialize() (AAAARecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return AAAARecord{}, err
	}

	var record AAAARecord
	if err := json.Unmarshal(data, &record); err != nil {
		return AAAARecord{}, err
	}

	return record, nil
}

type SRVRecord struct {
	ID       uint64 `json:"id"`
	Domain   string `json:"domain"`
	Priority int    `json:"priority"`
	Weight   int    `json:"weight"`
	Port     int    `json:"port"`
	Target   string `json:"target"`
}

func (r SRVRecord) Type() DNSRecordType { return SRV }
func (r SRVRecord) GetID() uint64       { return r.ID }
func (r SRVRecord) Serialize() (SRVRecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return SRVRecord{}, err
	}

	var record SRVRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return SRVRecord{}, err
	}

	return record, nil
}

type SOARecord struct {
	ID         uint64 `json:"id"`
	Domain     string `json:"domain"`
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimum_ttl"`
}

func (r SOARecord) Type() DNSRecordType { return SOA }
func (r SOARecord) GetID() uint64       { return r.ID }
func (r SOARecord) Serialize() (SOARecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return SOARecord{}, err
	}

	var record SOARecord
	if err := json.Unmarshal(data, &record); err != nil {
		return SOARecord{}, err
	}

	return record, nil
}

type CNAMERecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Target    string `json:"target"`
	Protected bool   `json:"protected"`
}

func (r CNAMERecord) Type() DNSRecordType { return CNAME }
func (r CNAMERecord) GetID() uint64       { return r.ID }
func (r CNAMERecord) Serialize() (CNAMERecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return CNAMERecord{}, err
	}

	var record CNAMERecord
	if err := json.Unmarshal(data, &record); err != nil {
		return CNAMERecord{}, err
	}

	return record, nil
}

type NSRecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	NS        string `json:"ns"`
	Protected bool   `json:"protected"`
}

func (r NSRecord) Type() DNSRecordType { return NS }
func (r NSRecord) GetID() uint64       { return r.ID }
func (r NSRecord) Serialize() (NSRecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return NSRecord{}, err
	}

	var record NSRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return NSRecord{}, err
	}

	return record, nil
}

type MXRecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Priority  uint16 `json:"priority"`
	Target    string `json:"target"`
	Protected bool   `json:"protected"`
}

func (r MXRecord) Type() DNSRecordType { return MX }
func (r MXRecord) GetID() uint64       { return r.ID }
func (r MXRecord) Serialize() (MXRecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return MXRecord{}, err
	}

	var record MXRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return MXRecord{}, err
	}

	return record, nil
}

type TXTRecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Text      string `json:"text"`
	Protected bool   `json:"protected"`
}

func (r TXTRecord) Type() DNSRecordType { return TXT }
func (r TXTRecord) GetID() uint64       { return r.ID }
func (r TXTRecord) Serialize() (TXTRecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return TXTRecord{}, err
	}

	var record TXTRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return TXTRecord{}, err
	}

	return record, nil
}

type CAARecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Flag      int    `json:"flag"`
	Tag       string `json:"tag"`
	Value     string `json:"value"`
	Protected bool   `json:"protected"`
}

func (r CAARecord) Type() DNSRecordType { return CAA }
func (r CAARecord) GetID() uint64       { return r.ID }
func (r CAARecord) Serialize() (CAARecord, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return CAARecord{}, err
	}

	var record CAARecord
	if err := json.Unmarshal(data, &record); err != nil {
		return CAARecord{}, err
	}

	return record, nil
}
