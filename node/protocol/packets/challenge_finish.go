package packets

import (
	"wired/modules/cache"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
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

	cache.Store("authentication_finished", true, 0)
}
