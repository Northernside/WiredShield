package dns

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
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

		rr, err := zoneFileToRecord(line)
		if err != nil {
			logger.Println("Error parsing zone file line:", err)
			continue
		}

		hdr := rr.Header()
		name := strings.ToLower(hdr.Name)
		zone := dns.CanonicalName(name)
		if _, ok := zones[zone]; !ok {
			zones[zone] = []dns.RR{}
		}

		zones[zone] = append(zones[zone], rr)
	}

	if err := scanner.Err(); err != nil {
		logger.Println("Error reading zone file:", err)
		return
	}

	logger.Println("Loaded zone file successfully")

	for zone, records := range zones {
		logger.Println(fmt.Sprintf("Zone: %s, Records: %d", zone, len(records)))
		for _, record := range records {
			logger.Println("  ", recordToZoneFile(record))
		}
	}
}

func addRecord(zone string, record dns.RR) error {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		zones[zone] = []dns.RR{}
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

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(recordToZoneFile(record) + "\n")
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

func removeRecord(zone string, index int) error {
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

func listRecords(zone string) ([]dns.RR, error) {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		return nil, fmt.Errorf("zone %s not found", zone)
	}

	return zones[zone], nil
}
