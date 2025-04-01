package packets

import (
	"wired/modules/env"
	"wired/modules/event"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/protocol"
)

var PacketEventBus = event.NewEventBus()

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

	PacketEventBus.Pub(txEvent.Event)
}
