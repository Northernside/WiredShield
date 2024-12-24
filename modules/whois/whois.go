package whois

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
)

var (
	IPToGeoloc = make(map[string]string)
	cacheMu    sync.RWMutex
)

func GetCountry(ip string) (string, error) {
	cacheMu.RLock()
	country, found := IPToGeoloc[ip]
	cacheMu.RUnlock()
	if found {
		return country, nil
	}

	country, err := getCountryFromWhois("whois.arin.net", ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return "", err
	}

	cacheMu.Lock()
	IPToGeoloc[ip] = country
	cacheMu.Unlock()

	return country, nil
}

func getCountryFromWhois(server string, ip string) (string, error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(ip + "\r\n"))
	if err != nil {
		return "", fmt.Errorf("failed to write to WHOIS server: %v", err)
	}

	scanner := bufio.NewScanner(conn)
	var whoisResponse strings.Builder
	for scanner.Scan() {
		whoisResponse.WriteString(scanner.Text() + "\n")
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read from WHOIS server: %v", err)
	}

	if strings.Contains(strings.ToLower(whoisResponse.String()), "resourcelink:") {

		// check if theres a ResourceLink:
		/*
			Ref:            https://rdap.arin.net/registry/ip/1.0.0.0

			ResourceLink:  http://wq.apnic.net/whois-search/static/search.html
			ResourceLink:  whois.apnic.net
		*/

		// there may be two ResourceLink: in the response, we need to get the second one
		// get all resourcelink lines and then use the last one from the array
		var resourceLinks []string
		for _, line := range strings.Split(whoisResponse.String(), "\n") {
			if strings.Contains(strings.ToLower(line), "resourcelink:") {
				resourceLinks = append(resourceLinks, strings.TrimSpace(strings.Split(strings.ToLower(line), "resourcelink:")[1]))
			}
		}

		var nextServer string
		if len(resourceLinks) > 0 {
			nextServer = strings.Replace(resourceLinks[1], "whois://", "", 1)
		} else {
			return "", fmt.Errorf("no ResourceLink found in WHOIS response")
		}

		if nextServer != "" {
			return getCountryFromWhois(nextServer, ip)
		}
	}

	for _, line := range strings.Split(whoisResponse.String(), "\n") {
		if strings.Contains(strings.ToLower(line), "country:") {
			return strings.TrimSpace(strings.Split(line, ":")[1]), nil
		}
	}

	return "", fmt.Errorf("country not found in WHOIS response")
}
