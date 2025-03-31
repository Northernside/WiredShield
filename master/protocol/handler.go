package protocol

import (
	"wired/modules/protocol"
)

type PacketHandler interface {
	Handle(conn *protocol.Conn, p *protocol.Packet)
}
