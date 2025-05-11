package user

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
	"wired/services/dns"
)

var (
	sf *snowflake.Snowflake
)

func init() {
	env.LoadEnvFile()
	machineIDStr := env.GetEnv("SNOWFLAKE_MACHINE_ID", "0")
	machineID, err := strconv.ParseInt(machineIDStr, 10, 64)
	if err != nil {
		logger.Fatal("Invalid SNOWFLAKE_MACHINE_ID: ", err)
	}

	sf, err = snowflake.NewSnowflake(machineID)
	if err != nil {
		logger.Fatal("Error creating Snowflake instance: ", err)
	}
}

func (user *User) AddRecord(zone string, record *types.DNSRecord) (string, error, bool) {
	dns.ZonefileMu.Lock()
	defer dns.ZonefileMu.Unlock()

	zone = strings.ToLower(zone)
	id := sf.GenerateID()
	record.Metadata.ID = fmt.Sprintf("%d", id)

	dns.Zones.Insert(user.ID, record)

	file, err := os.OpenFile("zonefile.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logger.Println("Error opening zone file for appending:", err)
		return "", err, false
	}
	defer file.Close()

	meta, err := json.Marshal(record.Metadata)
	if err != nil {
		logger.Println("Error marshalling metadata:", err)
		return "", err, false
	}

	writer := bufio.NewWriter(file)
	_, err = writer.WriteString(dns.RecordToZoneFile(record.Record) + ";" + string(meta) + "\n")
	if err != nil {
		logger.Println("Error writing to zone file:", err)
		return "", err, false
	}
	writer.Flush()

	dns.DNSEventBus.Pub(event.Event{
		Type:    event.Event_AddRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.AddRecordData{OwnerID: user.ID, Record: record},
	})

	return record.Metadata.ID, nil, true
}

func (user *User) RemoveRecord(id string) (error, bool) {
	ok := dns.Zones.Delete(user.ID, id)
	if !ok {
		return fmt.Errorf("record with ID %s not found", id), false
	}

	dns.ZonefileMu.Lock()
	defer dns.ZonefileMu.Unlock()

	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Println("Error opening zone file for reading:", err)
		return err, false
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ";", 2)
		if len(parts) > 1 {
			var meta types.RecordMetadata
			if json.Unmarshal([]byte(parts[1]), &meta) == nil {
				if meta.ID == id {
					continue
				}
			}
		}

		lines = append(lines, line)
	}

	file, err = os.OpenFile("zonefile.txt", os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		logger.Println("Error opening zone file for writing:", err)
		return err, false
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		writer.WriteString(line + "\n")
	}
	writer.Flush()

	dns.DNSEventBus.Pub(event.Event{
		Type:    event.Event_RemoveRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.RemoveRecordData{OwnerID: user.ID, ID: id},
	})

	return nil, true
}

func (user *User) UpdateRecord(id string, updateFunc func(*types.DNSRecord)) bool {
	dns.ZonesMutex.Lock()
	defer dns.ZonesMutex.Unlock()

	indexed, ok := dns.IdIndex[id]
	if !ok {
		return false
	}

	updateFunc(indexed.Record)
	return true
}
