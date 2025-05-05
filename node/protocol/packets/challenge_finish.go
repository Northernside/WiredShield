package packets

import (
	"wired/modules/cache"
	"wired/modules/geo"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/utils"
)

type ChallengeFinishHandler struct{}

func (h *ChallengeFinishHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var ch packet.Challenge
	err := protocol.DecodePacket(p.Data, &ch)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	masterPublicKey, err := pgp.LoadPublicKey("keys/master-public.pem")
	if err != nil {
		logger.Fatal("Failed to load master public key:", err)
	}

	err = pgp.VerifySignature(ch.Challenge, ch.Result, masterPublicKey)
	if err != nil {
		logger.Fatal("Failed to verify mutual challenge signature (sent by master):", err)
	}

	for _, node := range ch.Nodes {
		if _, found := geo.NodeListeners[node.Key]; !found {
			geo.NodeListeners[node.Key] = make([]geo.GeoInfo, 0)
		}

		for _, listener := range node.Listeners {
			loc, err := geo.GetLocation(listener)
			if err != nil {
				logger.Println("Failed to get location for listener:", err)
				continue
			}

			geoInfo := geo.GeoInfo{
				IP:         listener,
				MMLocation: loc,
			}

			geo.NodeListeners[node.Key] = append(geo.NodeListeners[node.Key], geoInfo)
		}
	}
	
	utils.NodesMux.Lock()
	utils.Nodes = ch.Nodes
	utils.NodesMux.Unlock()

	cache.Store("authentication_finished", true, 0)
}
