package event

import (
	"time"
)

var (
	Event_Tick uint8 = 0
)

type Event struct {
	Type    uint8
	FiredAt time.Time
	FiredBy string
	Data    interface{}
}

type EventBus struct {
	Subscribers map[uint8][]chan<- Event
}

func NewEventBus() *EventBus {
	return &EventBus{
		Subscribers: make(map[uint8][]chan<- Event),
	}
}

func (eventBus *EventBus) Sub(eventType uint8, subscriber chan<- Event, handler func()) {
	eventBus.Subscribers[eventType] = append(eventBus.Subscribers[eventType], subscriber)
	go handler()
}

func (eventBus *EventBus) Pub(event Event) {
	if subscribers, ok := eventBus.Subscribers[event.Type]; ok {
		for _, subscriber := range subscribers {
			subscriber <- event
		}
	}
}
