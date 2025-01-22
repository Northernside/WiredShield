package whois

import (
	"log"
	"net/netip"
	"wiredshield/modules/env"

	"github.com/oschwald/maxminddb-golang/v2"
)

var (
	mmdbCountry *maxminddb.Reader
	mmdbASN     *maxminddb.Reader
)

func init() {
	var err error
	mmdbCountry, err = maxminddb.Open(env.GetEnv("MAXMIND_COUNTRY_DB_PATH", "country.mmdb"))
	if err != nil {
		log.Fatal(err)
	}

	mmdbASN, err = maxminddb.Open(env.GetEnv("MAXMIND_ASN_DB_PATH", "asn.mmdb"))
	if err != nil {
		log.Fatal(err)
	}
}

func GetCountry(ip string) (string, error) {
	addr := netip.MustParseAddr(ip)

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	err := mmdbCountry.Lookup(addr).Decode(&record)
	if err != nil {
		return "", err
	}

	return record.Country.ISOCode, nil
}

func GetASN(ip string) (int, error) {
	addr := netip.MustParseAddr(ip)

	var record struct {
		AutonomousSystemNumber int `maxminddb:"autonomous_system_number"`
	}

	err := mmdbASN.Lookup(addr).Decode(&record)
	if err != nil {
		return 0, err
	}

	return record.AutonomousSystemNumber, nil
}
