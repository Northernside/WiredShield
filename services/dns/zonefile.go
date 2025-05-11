package dns

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/types"
)

var (
	ZonefileMu = &sync.Mutex{}
)

var zoneMeta struct {
	Owner string `json:"owner"`
}

func LoadZonefile() {
	logger.Println("Loading zone file...")
	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Fatal("Error opening zone file:", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var currentOwner string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, ";") {
			err := json.Unmarshal([]byte(strings.TrimPrefix(line, "; ")), &zoneMeta)
			if err != nil {
				logger.Println("Error parsing zone metadata:", err)
				continue
			}

			currentOwner = zoneMeta.Owner
			continue
		}

		parts := strings.SplitN(line, ";", 2)
		dnsPart := strings.TrimSpace(parts[0])
		if dnsPart == "" {
			continue
		}

		rr, err := zoneFileToRecord(dnsPart)
		if err != nil {
			if err == types.ErrUnusableLine {
				continue
			}

			logger.Println("Error parsing zone file line:", err)
			continue
		}

		if currentOwner == "" {
			logger.Println("Skipping record with no owner context:", dnsPart)
			continue
		}

		var metadata types.RecordMetadata
		if len(parts) > 1 {
			err := json.Unmarshal([]byte(strings.TrimSpace(parts[1])), &metadata)
			if err != nil {
				logger.Println("Error parsing record metadata:", err)
			}
		}

		Zones.Insert(
			currentOwner,
			&types.DNSRecord{
				Record:   rr,
				Metadata: metadata,
			},
		)
	}

	if err := scanner.Err(); err != nil {
		logger.Fatal("Error reading zone file:", err)
	}

	createIPCompatibility()
	logger.Println("Loaded zone file successfully")

	DNSEventBus.Pub(event.Event{
		Type:    event.Event_DNSServiceInitialized,
		FiredAt: time.Now(),
		FiredBy: env.GetEnv("NODE_KEY", "node-key"),
		Data:    event_data.DNSServiceInitializedData{},
	})
}
