package packets

import (
	"wired/modules/cache"
	"wired/modules/geo"
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

	cache.Store("nodes", value, 0)
	logger.Println("Node attached: ", attcPacket.Key)
}
