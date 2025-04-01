package packets

import (
	"fmt"
	"time"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/utils"
)

type ChallengeStartHandler struct{}

func (h *ChallengeStartHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var ch packet.Challenge
	err := protocol.DecodePacket(p.Data, &ch)
	if err != nil {
		logger.Fatal("Failed to decode challenge packet:", err)
	}

	signature, err := pgp.SignMessage(ch.Challenge, pgp.PrivateKey)
	if err != nil {
		logger.Fatal("Failed to sign challenge:", err)
	}

	mutualChallenge := fmt.Sprintf("%s-%d-%s",
		"master",
		time.Now().UnixMilli(),
		utils.RandomString(8),
	)

	challengeResultPacket := packet.Challenge{
		Key:             env.GetEnv("NODE_KEY", "node-key"),
		Challenge:       ch.Challenge,
		Result:          signature,
		MutualChallenge: mutualChallenge,
	}

	err = conn.SendPacket(packet.ID_ChallengeResult, challengeResultPacket)
	if err != nil {
		logger.Fatal("Failed to send challenge result packet:", err)
	}
}
