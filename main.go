package main

import (
	"fmt"
	"time"
	"wired/modules/env"
	"wired/modules/event"
	tick_event "wired/modules/event/events"
)

func main() {
	eventBus := event.NewEventBus()

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
	eventBus.Sub(0, eventChan)
	EventHandler(eventChan)
}

func EventHandler(eventChan <-chan event.Event) {
	for event := range eventChan {
		_, ok := event.Data.(tick_event.TickData)
		if !ok {
			fmt.Println("Invalid event data")
			continue
		}

		fmt.Println("Tick fired at:", event.FiredAt)
	}
}
