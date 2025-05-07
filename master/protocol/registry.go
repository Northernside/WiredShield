package protocol

import (
	"wired/master/protocol/packets"
	"wired/modules/globals"
	"wired/modules/protocol"
)

var handlers = map[globals.VarInt]PacketHandler{
	globals.Packet.ID_Login:             &packets.LoginHandler{},
	globals.Packet.ID_ChallengeResult:   &packets.ChallengeResultHandler{},
	globals.Packet.ID_EventTransmission: &packets.EventTransmissionHandler{},
}

func GetHandler(conn *protocol.Conn, id globals.VarInt) PacketHandler {
	if id != globals.Packet.ID_Login && id != globals.Packet.ID_ChallengeResult && conn.State != protocol.StateFullyReady {
		return nil
	}

	return handlers[id]
}
