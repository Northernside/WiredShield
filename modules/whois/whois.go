package whois

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"wiredshield/services"
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

	loweredContent := strings.ToLower(whoisResponse.String())
	// check if theres a ResourceLink:
	/*
		Ref:            https://rdap.arin.net/registry/ip/1.0.0.0

		ResourceLink:  http://wq.apnic.net/whois-search/static/search.html
		ResourceLink:  whois.apnic.net
	*/

	// suggests that the ip is in another whois server
	if strings.Contains(loweredContent, "netrange:") && strings.Contains(loweredContent, "resourcelink:") {
		if strings.Contains(loweredContent, "referralserver:") {
			referralServer := strings.TrimSpace(strings.Split(strings.Split(loweredContent, "referralserver:")[1], "\n")[0])
			referralServer = strings.Replace(referralServer, "whois://", "", 1)
			return getCountryFromWhois(referralServer, ip)
		}

		// there may be more than one ResourceLink: in the response, we need to get the second one
		// get all resourcelink lines and then use the last one from the array
		var resourceLinks []string
		for _, line := range strings.Split(loweredContent, "\n") {
			if strings.Contains(line, "resourcelink:") {
				services.ProcessService.InfoLog("ResourceLink found: " + line + " for " + ip)
				resourceLinks = append(resourceLinks, strings.TrimSpace(strings.Split(line, "resourcelink:")[1]))
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

	if strings.Contains(loweredContent, "netname:") {
		for _, line := range strings.Split(loweredContent, "\n") {
			if strings.Contains(strings.ToLower(line), "country:") {
				return strings.ToUpper(strings.TrimSpace(strings.Split(line, ":")[1])), nil
			}
		}
	}

	/*
		....
		Comcast Cable Communications, LLC JUMPSTART-4 (NET-69-240-0-0-1) 69.240.0.0 - 69.255.255.255
		Comcast Cable Communications, Inc. PA-WEST-22 (NET-69-244-96-0-1) 69.244.96.0 - 69.244.127.255
		....
	*/

	// check if theres a (NET-X-X-X-X-X) by regex
	// if there is, connect to arin again with the input being "NET-X-X-X-X-X"

	netRegex := regexp.MustCompile(`net-\d+-\d+-\d+-\d+-\d+`)
	netMatch := netRegex.FindStringSubmatch(loweredContent)
	if len(netMatch) > 0 {
		arinResult, err := getArinByNet(netMatch[0])
		if err != nil {
			return "", err
		}

		return strings.ToUpper(arinResult), nil
	} else {
		return "", fmt.Errorf("ARIN: no NET-... found in WHOIS response")
	}
}

func getArinByNet(netStr string) (string, error) {
	conn, err := net.Dial("tcp", "whois.arin.net:43")
	if err != nil {
		return "", fmt.Errorf("failed to connect to WHOIS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(netStr + "\r\n"))
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

	loweredContent := strings.ToLower(whoisResponse.String())
	for _, line := range strings.Split(loweredContent, "\n") {
		if strings.Contains(strings.ToLower(line), "country:") {
			return strings.TrimSpace(strings.Split(line, ":")[1]), nil
		}
	}

	return "", fmt.Errorf("country not found in WHOIS response")
}
