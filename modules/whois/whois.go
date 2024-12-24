package whois

import (
	"bufio"
	"fmt"
	"net"
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

	country, err := getCountryFromWhois(ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return "", err
	}

	cacheMu.Lock()
	IPToGeoloc[ip] = country
	cacheMu.Unlock()

	return country, nil
}

func getCountryFromWhois(ip string) (string, error) {
	conn, err := net.Dial("tcp", "whois.iana.org:43")
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

	server := findReferWhoisServer(whoisResponse.String())
	if server == "" {
		services.ProcessService.ErrorLog(whoisResponse.String())
		return "", fmt.Errorf("no referral WHOIS server found")
	}

	return queryRegionalWhoisServer(server, ip, false)
}

func findReferWhoisServer(whoisData string) string {
	for _, line := range strings.Split(whoisData, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			return strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	return ""
}

func queryRegionalWhoisServer(server, ip string, arinIssue bool) (string, error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("failed to connect to regional WHOIS server (%s): %v", server, err)
	}
	defer conn.Close()

	var query string
	if arinIssue && strings.Contains(server, "arin") {
		query = "z + " + ip + "+\r\n"
	} else {
		query = ip + "\r\n"
	}

	_, err = conn.Write([]byte(query))
	if err != nil {
		return "", fmt.Errorf("failed to write to regional WHOIS server: %v", err)
	}

	scanner := bufio.NewScanner(conn)
	var whoisResponse strings.Builder
	for scanner.Scan() {
		whoisResponse.WriteString(scanner.Text() + "\n")
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read from regional WHOIS server: %v", err)
	}

	for _, line := range strings.Split(whoisResponse.String(), "\n") {
		if strings.HasPrefix(strings.ToLower(line), "resourcelink:") {
			if strings.HasPrefix(strings.TrimSpace(strings.Split(line, ":")[1]), "whois") {
				return queryRegionalWhoisServer(strings.TrimSpace(strings.Split(line, ":")[1]), ip, false)
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "country:") {
			return strings.TrimSpace(strings.Split(line, ":")[1]), nil
		}
	}

	if !arinIssue {
		return queryRegionalWhoisServer(server, ip, true)
	}

	return "", fmt.Errorf("country not found in WHOIS response")
}
