package packets

import (
	"wired/modules/env"
	"wired/modules/event"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/protocol"
)

var PacketEventBus = event.NewEventBus("event_transmission_packet")

type EventTransmissionHandler struct{}

func (h *EventTransmissionHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var txEvent packet.EventTransmission
	err := protocol.DecodePacket(p.Data, &txEvent)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	if txEvent.Event.FiredBy == env.GetEnv("NODE_KEY", "node-key") {
		return
	}

	eventBus := event.NewEventBus(txEvent.EventBusName)
	if eventBus == nil {
		logger.Println("Failed to get event bus during event transmission:", txEvent.EventBusName)
		return
	}

	eventBus.Pub(txEvent.Event)
	PacketEventBus.Pub(txEvent.Event)
}
