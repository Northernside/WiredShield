package db

import (
	"encoding/json"
	"strconv"
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
	GetType() string
	GetDomain() string
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
func (r ARecord) GetType() string     { return "A" }
func (r ARecord) GetDomain() string   { return r.Domain }
func (r ARecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r ARecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

type AAAARecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	IP        string `json:"ip"`
	Protected bool   `json:"protected"`
}

func (r AAAARecord) Type() DNSRecordType { return AAAA }
func (r AAAARecord) GetID() uint64       { return r.ID }
func (r AAAARecord) GetType() string     { return "AAAA" }
func (r AAAARecord) GetDomain() string   { return r.Domain }
func (r AAAARecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r AAAARecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
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
func (r SRVRecord) GetType() string     { return "SRV" }
func (r SRVRecord) GetDomain() string   { return r.Domain }
func (r SRVRecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r SRVRecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
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
func (r SOARecord) GetType() string     { return "SOA" }
func (r SOARecord) GetDomain() string   { return r.Domain }
func (r SOARecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r SOARecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

type CNAMERecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Target    string `json:"target"`
	Protected bool   `json:"protected"`
}

func (r CNAMERecord) Type() DNSRecordType { return CNAME }
func (r CNAMERecord) GetID() uint64       { return r.ID }
func (r CNAMERecord) GetType() string     { return "CNAME" }
func (r CNAMERecord) GetDomain() string   { return r.Domain }
func (r CNAMERecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r CNAMERecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

type NSRecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	NS        string `json:"ns"`
	Protected bool   `json:"protected"`
}

func (r NSRecord) Type() DNSRecordType { return NS }
func (r NSRecord) GetID() uint64       { return r.ID }
func (r NSRecord) GetType() string     { return "NS" }
func (r NSRecord) GetDomain() string   { return r.Domain }
func (r NSRecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r NSRecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
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
func (r MXRecord) GetType() string     { return "MX" }
func (r MXRecord) GetDomain() string   { return r.Domain }
func (r MXRecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r MXRecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

type TXTRecord struct {
	ID        uint64 `json:"id"`
	Domain    string `json:"domain"`
	Text      string `json:"text"`
	Protected bool   `json:"protected"`
}

func (r TXTRecord) Type() DNSRecordType { return TXT }
func (r TXTRecord) GetID() uint64       { return r.ID }
func (r TXTRecord) GetType() string     { return "TXT" }
func (r TXTRecord) GetDomain() string   { return r.Domain }
func (r *TXTRecord) GetKey() string     { return r.Domain + ":" + strconv.Itoa(int(r.ID)) }
func (r TXTRecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
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
func (r CAARecord) GetType() string     { return "CAA" }
func (r CAARecord) GetDomain() string   { return r.Domain }
func (r CAARecord) GetKey() string      { return r.Domain + strconv.Itoa(int(r.ID)) }
func (r CAARecord) Serialize() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}

	return string(data), nil
}
