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

type GeoInfo struct {
	IP         net.IP
	MMLocation *MMLocation
}

var NodeListeners = make(map[string][]GeoInfo)

var (
	v4DB  *maxminddb.Reader
	v6DB  *maxminddb.Reader
	v4URL string = "https://github.com/sapics/ip-location-db/raw/refs/heads/main/geolite2-city-mmdb/geolite2-city-ipv4.mmdb"
	v6URL string = "https://github.com/sapics/ip-location-db/raw/refs/heads/main/geolite2-city-mmdb/geolite2-city-ipv6.mmdb"
)

const R = 6371              // earth radius in km
const D2R = math.Pi / 180.0 // degrees to radians

func init() {
	var err error
	v4DB, err = loadMaxMindDB("geolite2-city-ipv4.mmdb")
	if err != nil {
		logger.Println("Error loading IPv4 database: ", err)
		downloadDB(v4URL, "geolite2-city-ipv4.mmdb")
	}

	v6DB, err = loadMaxMindDB("geolite2-city-ipv6.mmdb")
	if err != nil {
		logger.Println("Error loading IPv6 database: ", err)
		downloadDB(v6URL, "geolite2-city-ipv6.mmdb")
	}

	logger.Println("Loaded GeoLocation databases successfully")
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
	lat1 := loc1.Lat * D2R
	lon1 := loc1.Lon * D2R

	lat2 := loc2.Lat * D2R
	lon2 := loc2.Lon * D2R

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

	dLon := lon2 - lon1
	dLat := lat2 - lat1

	a := math.Pow(math.Sin(dLat/2), 2) + math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(dLon/2), 2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}

func FindNearestLocation(origin GeoInfo, ipVersion int) (GeoInfo, error) {
	var nearest GeoInfo
	minDistance := math.MaxFloat64

	for _, listeners := range NodeListeners {
		for _, geoInfo := range listeners {
			if ipVersion == 4 && !utils.IsIPv4(geoInfo.IP) {
				continue
			} else if ipVersion == 6 && !utils.IsIPv6(geoInfo.IP) {
				continue
			}

			distance := GetLocationDistance(origin.MMLocation, geoInfo.MMLocation)
			if distance < minDistance {
				minDistance = distance
				nearest = geoInfo
			}
		}
	}

	if minDistance == math.MaxFloat64 {
		return GeoInfo{}, fmt.Errorf("no nearby locations found")
	}

	return nearest, nil
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

func downloadDB(url, filename string) {
	logger.Println("Starting download of geolite2-city-ipv4.mmdb")
	err := utils.DownloadFile(url, filename)
	if err != nil {
		logger.Fatal("Error downloading geolite2-city-ipv4.mmdb: ", err)
	}

	logger.Println("Download complete, loading geolite2-city-ipv4.mmdb")
	v4DB, err = loadMaxMindDB(filename)
	if err != nil {
		logger.Fatal("Error loading geolite2-city-ipv4.mmdb: ", err)
	}

	logger.Println("Loaded geolite2-city-ipv4.mmdb")
}
