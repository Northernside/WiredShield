package protocol

import (
	"wired/master/protocol/packets"
	packet "wired/modules/packets"
	"wired/modules/protocol"
)

var handlers = map[protocol.VarInt]PacketHandler{
	packet.ID_Login:           &packets.LoginHandler{},
	packet.ID_ChallengeResult: &packets.ChallengeResultHandler{},
}

func GetHandler(conn *protocol.Conn, id protocol.VarInt) PacketHandler {
	if id != packet.ID_Login && id != packet.ID_ChallengeResult {
		if conn.State != protocol.StateFullyReady {
			return nil
		}
	}

	return handlers[id]
}
