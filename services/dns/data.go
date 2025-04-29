package dns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/snowflake"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var (
	sf              *snowflake.Snowflake
	DNSEventChannel = make(chan event.Event)
	DNSEventBus     = event.NewEventBus("dns")
)

func init() {
	machineIDStr := env.GetEnv("SNOWFLAKE_MACHINE_ID", "0")
	machineID, err := strconv.ParseInt(machineIDStr, 10, 64)
	if err != nil {
		logger.Println("Invalid SNOWFLAKE_MACHINE_ID:", err)
		panic(err)
	}

	sf, err = snowflake.NewSnowflake(machineID)
	if err != nil {
		logger.Println("Error creating Snowflake instance:", err)
		panic(err)
	}
}

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
}

func AddRecord(zone string, record types.DNSRecord) (string, error) {
	zone = strings.ToLower(zone)
	if _, ok := zones[zone]; !ok {
		zones[zone] = []types.DNSRecord{}
	}

	id := sf.GenerateID()
	record.Metadata.ID = fmt.Sprintf("%d", id)

	zones[zone] = append(zones[zone], record)

	logger.Println("Adding record to zone: ", zone)
	file, err := os.OpenFile("zonefile.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening zone file for appending:", err)
		return "", err
	}
	defer file.Close()

	marshalledMetadata, err := json.Marshal(record.Metadata)
	if err != nil {
		logger.Println("Error marshalling metadata:", err)
		return "", err
	}

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(recordToZoneFile(record.Record) + ";" + string(marshalledMetadata) + "\n")
	if err != nil {
		logger.Println("Error writing to zone file:", err)
		return "", err
	}

	err = writer.Flush()
	if err != nil {
		logger.Println("Error flushing writer:", err)
		return "", err
	}

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_AddRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data: event_data.AddRecordData{
			Record: record,
		},
	})

	return record.Metadata.ID, nil
}

func RemoveRecord(id string) error {
	var foundZone string
	var foundIndex int = -1

	for zone, records := range zones {
		for i, record := range records {
			if record.Metadata.ID == id {
				foundZone = zone
				foundIndex = i
				break
			}
		}

		if foundIndex != -1 {
			break
		}
	}

	if foundIndex == -1 {
		return fmt.Errorf("record with ID %s not found", id)
	}

	zones[foundZone] = append(zones[foundZone][:foundIndex], zones[foundZone][foundIndex+1:]...)

	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Println("Error opening zone file for reading:", err)
		return err
	}
	defer file.Close()

	lines := []string{}
	scanner := bufio.NewScanner(file)
	targetLine := -1
	lineNumber := 0
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ";", 2)
		if len(parts) > 1 {
			var metadata types.RecordMetadata
			if err := json.Unmarshal([]byte(parts[1]), &metadata); err != nil {
				logger.Println("Error parsing metadata for line", lineNumber, ":", err)
			} else if metadata.ID == id {
				targetLine = lineNumber
			}
		}

		lines = append(lines, line)
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		logger.Println("Error reading zone file:", err)
		return err
	}

	if targetLine == -1 {
		return fmt.Errorf("record with ID %s not found in zone file", id)
	}

	lines = append(lines[:targetLine], lines[targetLine+1:]...)

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

	if err := writer.Flush(); err != nil {
		logger.Println("Error flushing writer:", err)
		return err
	}

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_RemoveRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data: event_data.RemoveRecordData{
			ID: id,
		},
	})

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
