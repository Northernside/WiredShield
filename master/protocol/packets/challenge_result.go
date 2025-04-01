package packets

import (
	"fmt"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
)

type ChallengeResultHandler struct{}

func (h *ChallengeResultHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var ch packet.Challenge
	err := protocol.DecodePacket(p.Data, &ch)
	if err != nil {
		logger.Println("Error decoding challenge result packet:", err)
		return
	}

	if _, ok := packet.PendingChallenges[ch.Challenge]; !ok {
		logger.Println("Challenge not found:", ch.Challenge)
		return
	}

	publicKey, err := pgp.LoadPublicKey("keys/" + ch.Key + "-public.pem")
	if err != nil {
		logger.Println("Error loading public key:", err)
		conn.Close()
		return
	}

	if err := pgp.VerifySignature(ch.Challenge, ch.Result, publicKey); err != nil {
		logger.Println("Signature verification failed:", err)
		delete(packet.PendingChallenges, ch.Challenge)
		conn.Close()
		return
	}

	mutualSignature, err := pgp.SignMessage(ch.MutualChallenge, pgp.PrivateKey)
	if err != nil {
		logger.Println("Error signing mutual challenge:", err)
		conn.Close()
		return
	}

	challengeFinishPacket := packet.Challenge{
		Key:       env.GetEnv("NODE_KEY", "node-key"),
		Challenge: ch.MutualChallenge,
		Result:    mutualSignature,
	}

	conn.State = protocol.StateFullyReady
	conn.SendPacket(packet.ID_ChallengeFinish, challengeFinishPacket)
	delete(packet.PendingChallenges, ch.Challenge)

	logger.Println(fmt.Sprintf("Node %s%s%s connected", logger.ColorGray, ch.Key, logger.ColorReset))
}
