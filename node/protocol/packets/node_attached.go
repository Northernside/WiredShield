package packets

import (
	"wired/modules/geo"
	"wired/modules/logger"
	"wired/modules/protocol"
	"wired/modules/types"
	"wired/modules/utils"
)

type NodeAttachedHandler struct{}

func (h *NodeAttachedHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var attcPacket types.NodeInfo
	err := protocol.DecodePacket(p.Data, &attcPacket)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	utils.NodesMux.Lock()
	utils.Nodes[attcPacket.Key] = attcPacket
	utils.NodesMux.Unlock()

	if _, found := geo.NodeListeners[attcPacket.Key]; !found {
		geo.NodeListeners[attcPacket.Key] = make([]geo.GeoInfo, 0)
	}

	for _, listener := range attcPacket.Listeners {
		loc, err := geo.GetLocation(listener)
		if err != nil {
			logger.Println("Failed to get location for listener:", err)
			continue
		}

		geoInfo := geo.GeoInfo{
			IP:         listener,
			MMLocation: loc,
		}

		geo.NodeListeners[attcPacket.Key] = append(geo.NodeListeners[attcPacket.Key], geoInfo)
	}

	logger.Println("Node attached: ", attcPacket.Key)
}
