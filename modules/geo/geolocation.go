package geo

import (
	"fmt"
	"math"
	"net"
	"wired/modules/logger"
	"wired/modules/utils"

	"github.com/oschwald/maxminddb-golang"
)

type MMLocation struct {
	City        string  `maxminddb:"city"`
	CountryCode string  `maxminddb:"country_code"`
	Lat         float64 `maxminddb:"latitude"`
	Lon         float64 `maxminddb:"longitude"`
}

var (
	v4DB *maxminddb.Reader
	v6DB *maxminddb.Reader
)

const R = 6371              // earth radius in km
const D2R = math.Pi / 180.0 // degrees to radians

func init() {
	var err error
	v4DB, err = loadMaxMindDB("geolite2-city-ipv4.mmdb")
	if err != nil {
		fmt.Println("Error loading IPv4 database: ", err)
		return
	}

	v6DB, err = loadMaxMindDB("geolite2-city-ipv6.mmdb")
	if err != nil {
		fmt.Println("Error loading IPv6 database: ", err)
		return
	}

	logger.Println("loaded geo loc dbs")
}

func GetLocation(ip net.IP) (*MMLocation, error) {
	if utils.IsIPv4(ip) {
		return lookupV4(ip)
	} else if utils.IsIPv6(ip) {
		return lookupV6(ip)
	}

	return nil, fmt.Errorf("could not determine ip version: %s", ip.String())
}

// haversine https://en.wikipedia.org/wiki/Haversine_formula
func GetLocationDistance(loc1, loc2 *MMLocation) float64 {
	lat1 := loc1.Lat
	lat2 := loc2.Lat

	lon1 := loc1.Lon
	lon2 := loc2.Lon

	// Δ = delta
	// φ = breitengrad
	// λ = längengrad

	// dLat = Δφ * π / 180°
	// dLon = Δλ * π / 180°

	// a = sin(Δφ)² + cos(φ₁) * cos(φ₂) * sin(Δλ)²
	// c = 2 * atan2(√a, √(1−a))
	// d = R * c

	// a = sin(dLat/2)^2 + cos(lat1) * cos(lat2) * sin(dLon/2)^2
	// c = 2 * atan2(sqrt(a), sqrt(1-a))
	// d = R * c

	dLon := (lon2 - lon1) * D2R
	dLat := (lat2 - lat1) * D2R

	a := math.Pow(math.Sin(dLat/2), 2) + math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(dLon/2), 2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}

func lookupV4(ip net.IP) (*MMLocation, error) {
	var loc MMLocation
	err := v4DB.Lookup(ip, &loc)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPv4 address: %w", err)
	}

	return &loc, nil
}

func lookupV6(ip net.IP) (*MMLocation, error) {
	var loc MMLocation
	err := v6DB.Lookup(ip, &loc)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup IPv6 address: %w", err)
	}

	return &loc, nil
}

func loadMaxMindDB(dbPath string) (*maxminddb.Reader, error) {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open MaxMind DB: %w", err)
	}

	return db, nil
}
