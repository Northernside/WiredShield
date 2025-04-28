package dns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/types"
	"wired/node/protocol/packets"

	"github.com/miekg/dns"
)

func loadZonefile() {
	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Println("Error opening zone file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		var comment = types.RecordMetadata{}
		if strings.Contains(line, ";") {
			err := json.Unmarshal([]byte(strings.Split(line, ";")[1]), &comment)
			if err != nil {
				logger.Println("Error unmarshalling comment metadata:", err)
				continue
			}
		}

		rr, err := zoneFileToRecord(line)
		if err != nil {
			if err == types.ErrUnusableLine {
				continue
			}

			logger.Println("Error parsing zone file line:", err)
			continue
		}

		hdr := rr.Header()
		name := strings.ToLower(hdr.Name)
		zone := dns.CanonicalName(name)
		if _, ok := zones[zone]; !ok {
			zones[zone] = []types.DNSRecord{}
		}

		zones[zone] = append(zones[zone], types.DNSRecord{
			Record:   rr,
			Metadata: comment,
		})
	}

	if err := scanner.Err(); err != nil {
		logger.Println("Error reading zone file:", err)
		return
	}

	logger.Println("Loaded zone file successfully")

	/*for zone, records := range zones {
		logger.Println(fmt.Sprintf("Zone: %s, Records: %d", zone, len(records)))
		for _, record := range records {
			logger.Println("  ", recordToZoneFile(record.Record), " Protected:", record.Metadata.Protected, " Geo:", record.Metadata.Geo)
		}
	}*/
}

func AddRecord(zone string, record types.DNSRecord) error {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		zones[zone] = []types.DNSRecord{}
	}

	zones[zone] = append(zones[zone], record)

	logger.Println("Adding record to zone:", zone)
	// append new line to zone file with func recordToZoneFile <- one string (the line)
	file, err := os.OpenFile("zonefile.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening zone file for appending:", err)
		return err
	}
	defer file.Close()

	marshalledMetadata, err := json.Marshal(record.Metadata)
	if err != nil {
		logger.Println("Error marshalling metadata:", err)
		return err
	}

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(recordToZoneFile(record.Record) + ";" + string(marshalledMetadata) + "\n")
	if err != nil {
		logger.Println("Error writing to zone file:", err)
		return err
	}
	err = writer.Flush()
	if err != nil {
		logger.Println("Error flushing writer:", err)
	}

	packets.PacketEventBus.Pub(event.Event{
		Type:    event.Event_AddRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data: event_data.AddRecordData{
			Record: record,
		},
	})

	return nil
}

func RemoveRecord(zone string, index int) error {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		return fmt.Errorf("zone %s not found", zone)
	}

	if index < 0 || index >= len(zones[zone]) {
		return fmt.Errorf("index %d out of range for zone %s", index, zone)
	}

	zones[zone] = append(zones[zone][:index], zones[zone][index+1:]...)

	// remove lines[index] from zone file
	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Println("Error opening zone file for reading:", err)
		return err
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		logger.Println("Error reading zone file:", err)
		return err
	}

	if index < 0 || index >= len(lines) {
		return fmt.Errorf("index %d out of range for zone file", index)
	}

	lines = append(lines[:index], lines[index+1:]...)

	file, err = os.OpenFile("zonefile.txt", os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		logger.Println("Error opening zone file for writing:", err)
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			logger.Println("Error writing to zone file:", err)
			return err
		}
	}

	err = writer.Flush()
	if err != nil {
		logger.Println("Error flushing writer:", err)
		return err
	}

	return nil
}

func ListRecordsByZone(zone string) ([]types.DNSRecord, error) {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		return nil, fmt.Errorf("zone %s not found", zone)
	}

	return zones[zone], nil
}

func ListRecords() map[string][]types.DNSRecord {
	return zones
}
