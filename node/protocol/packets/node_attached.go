package packets

import (
	"wired/modules/cache"
	"wired/modules/logger"
	"wired/modules/protocol"
	"wired/modules/types"
)

type NodeAttachedHandler struct{}

func (h *NodeAttachedHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var attcPacket types.NodeInfo
	err := protocol.DecodePacket(p.Data, &attcPacket)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	value, found := cache.Get[map[string]types.NodeInfo]("nodes")
	if !found {
		value = make(map[string]types.NodeInfo)
	}

	value[attcPacket.Key] = attcPacket
	cache.Store("nodes", value, 0)
	logger.Println("Node attached:", attcPacket.Key)
}
