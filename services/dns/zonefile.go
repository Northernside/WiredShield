package dns

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/types"
)

func LoadZonefile() {
	file, err := os.Open("zonefile.txt")
	if err != nil {
		logger.Println("Error opening zone file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		var comment types.RecordMetadata
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

		name := strings.ToLower(rr.Header().Name)
		Zones.insert(name, &types.DNSRecord{
			Record:   rr,
			Metadata: comment,
		})
	}

	if err := scanner.Err(); err != nil {
		logger.Println("Error reading zone file:", err)
		return
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
