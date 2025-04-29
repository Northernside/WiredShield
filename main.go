package main

import (
	"fmt"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	tick_event "wired/modules/event/events"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	eventBus := event.NewEventBus("test_event_bus")

	go func() {
		for {
			eventBus.Pub(event.Event{
				Type:    event.Event_Tick,
				FiredAt: time.Now(),
				FiredBy: env.GetEnv("NODE_KEY", "master"),
				Data:    tick_event.TickData{},
			})

			time.Sleep(50 * time.Millisecond)
		}
	}()

	eventChan := make(chan event.Event)
	eventBus.Sub(0, eventChan, func() { eventHandler(eventChan) })

	time.Sleep(10 * time.Second)
	fmt.Println("Timeout reached, exiting...")
}

func eventHandler(eventChan <-chan event.Event) {
	for event := range eventChan {
		_, ok := event.Data.(event_data.TickData)
		if !ok {
			fmt.Println("Invalid event data")
			continue
		}

		fmt.Println("Tick fired at:", event.FiredAt, "by:", event.FiredBy, "- Event ID:", event.Type)
	}
}
