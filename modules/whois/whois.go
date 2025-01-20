package whois

import (
	"log"
	"net/netip"
	"wiredshield/modules/env"

	"github.com/oschwald/maxminddb-golang/v2"
)

var (
	mmdb *maxminddb.Reader
)

func init() {
	var err error
	mmdb, err = maxminddb.Open(env.GetEnv("MAXMIND_DB_PATH", "database.mmdb"))
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

	err := mmdb.Lookup(addr).Decode(&record)
	if err != nil {
		return "", err
	}

	return record.Country.ISOCode, nil
}
