package protocol

import (
	"wired/modules/cache"
	packet "wired/modules/packets"
	"wired/modules/protocol"
	"wired/node/protocol/packets"
)

var handlers = map[protocol.VarInt]PacketHandler{
	packet.ID_ChallengeStart:    &packets.ChallengeStartHandler{},
	packet.ID_ChallengeFinish:   &packets.ChallengeFinishHandler{},
	packet.ID_EventTransmission: &packets.EventTransmissionHandler{},
	packet.ID_NodeAttached:      &packets.NodeAttachedHandler{},
	packet.ID_NodeDetached:      &packets.NodeDetachedHandler{},
}

func GetHandler(id protocol.VarInt) PacketHandler {
	if id != packet.ID_ChallengeStart && id != packet.ID_ChallengeFinish {
		if value, found := cache.Get[bool]("authentication_finished"); !found || !value {
			return nil
		}
	}

	return handlers[id]
}
