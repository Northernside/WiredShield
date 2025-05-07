package packets

import (
	"wired/modules/geo"
	"wired/modules/logger"
	"wired/modules/protocol"
	"wired/modules/types"
	"wired/modules/utils"
)

type NodeDetachedHandler struct{}

func (h *NodeDetachedHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var detcPacket types.NodeInfo
	err := protocol.DecodePacket(p.Data, &detcPacket)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	utils.NodesMux.Lock()
	delete(utils.Nodes, detcPacket.Key)
	utils.NodesMux.Unlock()
	delete(geo.NodeListeners, detcPacket.Key)

	logger.Println("Node detached: ", detcPacket.Key)
}
