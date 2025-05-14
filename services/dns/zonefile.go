package dns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"wired/modules/types"

	"github.com/miekg/dns"
)

func SplitZonefile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var (
		currentDomain string
		currentHeader string
		domainData    []string
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, ";") {
			if currentDomain != "" && len(domainData) > 0 {
				fullData := append([]string{currentHeader}, domainData...)
				err := WriteToDomainFile(currentDomain, fullData)
				if err != nil {
					return err
				}
			}

			// new domain group header
			var data DomainData
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, ";")), &data); err != nil {
				continue // skip invalid JSON
			}

			currentDomain = data.Domain
			currentHeader = line
			domainData = nil
			continue
		}

		domainData = append(domainData, line)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scanner error: %w", err)
	}

	if currentDomain != "" && len(domainData) > 0 {
		fullData := append([]string{currentHeader}, domainData...)
		err := WriteToDomainFile(currentDomain, fullData)
		if err != nil {
			return err
		}
	}

	return nil
}

func WriteToDomainFile(domain string, lines []string) error {
	fileName := filepath.Join("zonefiles", strings.TrimSuffix(domain, ".")+".txt")
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}

func RemoveRecordFromZoneFile(zone string, recordId string) error {
	filePath := filepath.Join("zonefiles", zone+".txt")

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lines := []string{}
	found := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, ";") {
			lines = append(lines, line)
			continue
		}

		parts := strings.SplitN(line, ";", 2)
		if len(parts) == 2 {
			var meta types.RecordMetadata
			if err := json.Unmarshal([]byte(strings.TrimSpace(parts[1])), &meta); err == nil {
				if meta.Id == recordId {
					found = true
					continue
				}
			}
		}

		lines = append(lines, line)
	}

	if !found {
		return fmt.Errorf("record not found in zonefile")
	}

	return os.WriteFile(filePath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func LoadZonefile() {
	os.MkdirAll("zonefiles", os.ModePerm)
	files, err := os.ReadDir("zonefiles")
	if err != nil {
		panic("failed to read zone files directory: " + err.Error())
	}

	for _, file := range files {
		if !file.IsDir() {
			loadDomainZoneFile(filepath.Join("zonefiles", file.Name()))
		}
	}
}

func loadDomainZoneFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		panic("failed to open zone file: " + err.Error())
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var currentDomainData *DomainData
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// domain group header
		if strings.HasPrefix(line, ";") {
			var data DomainData
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, ";")), &data); err != nil {
				continue // skip invalid JSON
			}

			currentDomainData = &data
			DomainDataIndexId[data.Id] = &data
			DomainDataIndexName[data.Domain] = &data
			UserDomainIndexId[data.Owner] = append(UserDomainIndexId[data.Owner], &data)
			EnsureDomainIndexes(data)
			continue
		}

		// not a domain group header
		if currentDomainData == nil {
			continue
		}

		// parse DNS record
		parts := strings.SplitN(line, ";", 2)
		rawRecord := strings.TrimSpace(parts[0])

		var metadata types.RecordMetadata
		if len(parts) == 2 {
			jsonMeta := strings.TrimSpace(parts[1])
			_ = json.Unmarshal([]byte(jsonMeta), &metadata)
		}

		rr, err := dns.NewRR(rawRecord)
		if err != nil {
			continue
		}

		record := &types.DNSRecord{
			RR:       rr,
			Metadata: metadata,
		}

		InsertRecord(currentDomainData, record)
	}

	if err := scanner.Err(); err != nil {
		panic("error while reading zonefile.txt: " + err.Error())
	}
}

func WriteZoneFile(zone string) error {
	filePath := filepath.Join("zonefiles", zone+".txt")

	var domainData *DomainData
	for _, d := range DomainDataIndexName {
		if d.Domain == zone {
			domainData = d
			break
		}
	}

	if domainData == nil {
		return fmt.Errorf("no domain data for zone %s", zone)
	}

	records := DomainRecordIndexId[domainData.Id]

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	marshaledData, err := json.Marshal(domainData)
	if err != nil {
		return err
	}

	header := fmt.Sprintf(";%s", string(marshaledData))
	_, _ = writer.WriteString(header + "\n")

	for _, record := range records {
		rrStr := strings.TrimSpace(record.RR.String())
		marshaledMeta, err := json.Marshal(record.Metadata)
		if err != nil {
			return err
		}

		_, _ = writer.WriteString(rrStr + "; " + string(marshaledMeta) + "\n")
	}

	return writer.Flush()
}

func PruneTrie(root *TrieNode, fqdn string, recordId string) {
	labels := dns.SplitDomainName(fqdn)
	node := root

	for i := len(labels) - 1; i >= 0; i-- {
		if node == nil {
			return
		}

		node = node.Children[labels[i]]
	}

	if node == nil {
		return
	}

	newRecs := node.Records[:0]
	for _, rec := range node.Records {
		if rec.Metadata.Id != recordId {
			newRecs = append(newRecs, rec)
		}
	}

	node.Records = newRecs
}
