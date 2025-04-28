package event

import (
	"time"
	"wired/modules/cache"
	"wired/modules/env"
	"wired/modules/protocol"
	"wired/modules/types"
)

var (
	Event_Tick                  uint8 = 0
	Event_AddRecord             uint8 = 1
	Event_RemoveRecord          uint8 = 2
	Event_DNSServiceInitialized uint8 = 128
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

	if env.GetEnv("NODE_KEY", "node-key") == "master" {
		// send ID_EventTransmission packet to nodes
		value, found := cache.Get[map[string]types.NodeInfo]("nodes")
		if !found {
			return
		}

		nodesMap := value
		for _, node := range nodesMap {
			node.Conn.SendPacket(13, EventTransmission{
				Event: event,
			})
		}
	} else {
		// send ID_EventTransmission packet to master
		master, found := cache.Get[protocol.Conn]("master")
		if !found {
			return
		}

		master.SendPacket(13, EventTransmission{
			Event: event,
		})
	}
}

type EventTransmission struct {
	Event Event
}
