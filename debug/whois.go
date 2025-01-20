package main

import (
	"log"
	"net/netip"

	"github.com/oschwald/maxminddb-golang/v2"
)

var (
	db *maxminddb.Reader
)

func init() {
	var err error
	db, err = maxminddb.Open("../database.mmdb")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	addr := netip.MustParseAddr("81.2.69.142")

	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}

	err := db.Lookup(addr).Decode(&record)
	if err != nil {
		log.Panic(err)
	}
}
