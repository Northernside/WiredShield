package dns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
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
	sf *snowflake.Snowflake

	DNSEventChannel = make(chan event.Event)
	DNSEventBus     = event.NewEventBus("dns")

	zonefileMu sync.Mutex
)

func init() {
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

func AddRecord(zone string, record types.DNSRecord) (string, error, bool) {
	zonefileMu.Lock()
	defer zonefileMu.Unlock()

	zone = strings.ToLower(zone)
	id := sf.GenerateID()
	record.Metadata.ID = fmt.Sprintf("%d", id)

	Zones.insert(zone, record)

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
	_, err = writer.WriteString(recordToZoneFile(record.Record) + ";" + string(meta) + "\n")
	if err != nil {
		logger.Println("Error writing to zone file:", err)
		return "", err, false
	}
	writer.Flush()

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_AddRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.AddRecordData{Record: record},
	})

	return record.Metadata.ID, nil, true
}

func RemoveRecord(id string) (error, bool) {
	ok := Zones.deleteByID(id)
	if !ok {
		return fmt.Errorf("record with ID %s not found", id), false
	}

	zonefileMu.Lock()
	defer zonefileMu.Unlock()

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

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_RemoveRecord,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.RemoveRecordData{ID: id},
	})

	return nil, true
}

func (trie *dnsTrie) UpdateRecord(id string, updateFunc func(*types.DNSRecord)) bool {
	trie.mu.Lock()
	defer trie.mu.Unlock()

	indexed, ok := trie.idIndex[id]
	if !ok {
		return false
	}

	updateFunc(indexed.record)
	return true
}

func ListRecordsByZone(zone string) ([]types.DNSRecord, error) {
	zone = strings.ToLower(zone)
	reversedLabels := reverse(domainToLabels(dns.Fqdn(zone)))

	Zones.mu.RLock()
	defer Zones.mu.RUnlock()

	currentNode := Zones.root
	for _, label := range reversedLabels {
		child, ok := currentNode.children[label]
		if !ok {
			return nil, fmt.Errorf("zone %s not found", zone)
		}

		currentNode = child
	}

	var records []types.DNSRecord
	var walk func(*trieNode)
	walk = func(node *trieNode) {
		records = append(records, node.records...)
		for _, child := range node.children {
			walk(child)
		}
	}

	walk(currentNode)
	return records, nil
}

func ListRecords() map[string][]types.DNSRecord {
	result := make(map[string][]types.DNSRecord)

	var walk func(node *trieNode, path []string)
	walk = func(node *trieNode, path []string) {
		if len(node.records) > 0 {
			domain := strings.Join(reverse(path), ".")
			result[dns.Fqdn(domain)] = node.records
		}

		for label, child := range node.children {
			walk(child, append(path, label))
		}
	}

	Zones.mu.RLock()
	defer Zones.mu.RUnlock()
	walk(Zones.root, []string{})

	return result
}
