package whois

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"wiredshield/services"
)

func GetCountry(ip string) (string, error) {
	country, err := getCountryFromWhois(ip)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return "", err
	}

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

	return queryRegionalWhoisServer(server, ip)
}

func findReferWhoisServer(whoisData string) string {
	for _, line := range strings.Split(whoisData, "\n") {
		if strings.HasPrefix(strings.ToLower(line), "refer:") {
			return strings.TrimSpace(strings.Split(line, ":")[1])
		}
	}

	return ""
}

func queryRegionalWhoisServer(server, ip string) (string, error) {
	conn, err := net.Dial("tcp", server+":43")
	if err != nil {
		return "", fmt.Errorf("failed to connect to regional WHOIS server (%s): %v", server, err)
	}
	defer conn.Close()

	if strings.Contains(server, "whois.arin.net") {
		_, err = conn.Write([]byte("z + " + ip + " +\r\n"))
	} else {
		_, err = conn.Write([]byte(ip + "\r\n"))
	}

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
			if strings.HasPrefix(strings.TrimSpace(strings.Split(line, ":")[1]), "whois.") {
				return queryRegionalWhoisServer(strings.TrimSpace(strings.Split(line, ":")[1]), ip)
			}
		}

		if strings.HasPrefix(strings.ToLower(line), "country:") {
			return strings.TrimSpace(strings.Split(line, ":")[1]), nil
		}
	}

	return "", fmt.Errorf("country not found in WHOIS response")
}
