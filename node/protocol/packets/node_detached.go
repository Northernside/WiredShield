package packets

import (
	"wired/modules/cache"
	"wired/modules/geo"
	"wired/modules/logger"
	"wired/modules/protocol"
	"wired/modules/types"
)

type NodeDetachedHandler struct{}

func (h *NodeDetachedHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var detcPacket types.NodeInfo
	err := protocol.DecodePacket(p.Data, &detcPacket)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	value, found := cache.Get[map[string]types.NodeInfo]("nodes")
	if !found {
		value = make(map[string]types.NodeInfo)
	}

	delete(value, detcPacket.Key)
	delete(geo.NodeListeners, detcPacket.Key)

	logger.Println("Node detached:", detcPacket.Key)
}
