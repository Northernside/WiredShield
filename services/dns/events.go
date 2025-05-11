package dns

import (
	"wired/modules/env"
	"wired/modules/event"
	"wired/modules/logger"

	event_data "wired/modules/event/events"
)

func init() {
	eventChan := make(chan event.Event)
	DNSEventBus.Sub(1, eventChan, func() { addRecordEventHandler(eventChan) })
	DNSEventBus.Sub(2, eventChan, func() { removeRecordEventHandler(eventChan) })
}

func addRecordEventHandler(eventChan <-chan event.Event) {
	for event := range eventChan {
		if event.FiredBy == env.GetEnv("NODE_KEY", "node-key") {
			continue
		}

		if event.Type != 1 {
			continue
		}

		data, ok := event.Data.(event_data.AddRecordData)
		if !ok {
			logger.Println("Invalid event data for AddRecord")
			continue
		}

		Zones.Insert(data.OwnerID, data.Record)
	}
}

func removeRecordEventHandler(eventChan <-chan event.Event) {
	for event := range eventChan {
		if event.FiredBy == env.GetEnv("NODE_KEY", "node-key") {
			continue
		}

		if event.Type != 2 {
			continue
		}

		data, ok := event.Data.(event_data.RemoveRecordData)
		if !ok {
			logger.Println("Invalid event data for RemoveRecord")
			continue
		}

		Zones.Delete(data.OwnerID, data.ID)
	}
}
