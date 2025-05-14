package dns

import (
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/postgresql"
	"wired/modules/types"
)

func init() {
	eventChan := make(chan event.Event)
	DNSEventBus.Sub(event.Event_AddRecord, eventChan, func() { addRecordEventHandler(eventChan) })
	DNSEventBus.Sub(event.Event_RemoveRecord, eventChan, func() { removeRecordEventHandler(eventChan) })
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

		owner := postgresql.Users[data.OwnerId]
		if owner == nil {
			postgresql.Users[data.OwnerId] = &types.User{
				Id: data.OwnerId,
			}
		}

		err := postgresql.GetUser(owner)
		if err != nil {
			logger.Println("Failed to get user: ", err)
			continue
		}

		_, err = CreateRecord(owner, data.DomainId, data.Record)
		if err != nil {
			logger.Println("Failed to create record: ", err)
			continue
		}
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

		owner := postgresql.Users[data.OwnerId]
		if owner == nil {
			postgresql.Users[data.OwnerId] = &types.User{
				Id: data.OwnerId,
			}
		}

		err := postgresql.GetUser(owner)
		if err != nil {
			logger.Println("Failed to get user: ", err)
			continue
		}

		err = DeleteRecord(owner, data.Id)
		if err != nil {
			logger.Println("Failed to delete record: ", err)
			continue
		}
	}
}
