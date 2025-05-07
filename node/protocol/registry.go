package protocol

import (
	"wired/modules/globals"
	"wired/modules/utils"
	"wired/node/protocol/packets"
)

var handlers = map[globals.VarInt]PacketHandler{
	globals.Packet.ID_ChallengeStart:    &packets.ChallengeStartHandler{},
	globals.Packet.ID_ChallengeFinish:   &packets.ChallengeFinishHandler{},
	globals.Packet.ID_EventTransmission: &packets.EventTransmissionHandler{},
	globals.Packet.ID_NodeAttached:      &packets.NodeAttachedHandler{},
	globals.Packet.ID_NodeDetached:      &packets.NodeDetachedHandler{},
}

func GetHandler(id globals.VarInt) PacketHandler {
	if id != globals.Packet.ID_ChallengeStart && id != globals.Packet.ID_ChallengeFinish && !utils.AuthenticationFinished {
		return nil
	}

	return handlers[id]
}
