package packets

import (
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
		logger.Log("error decoding challenge result packet:", err)
		return
	}

	if _, ok := packet.PendingChallenges[ch.Challenge]; !ok {
		logger.Log("challenge not found:", ch.Challenge)
		return
	}

	publicKey, err := pgp.LoadPublicKey("keys/" + ch.Key + "-public.pem")
	if err != nil {
		logger.Log("error loading public key:", err)
		conn.Close()
		return
	}

	if err := pgp.VerifySignature(ch.Challenge, ch.Result, publicKey); err != nil {
		logger.Log("signature verification failed:", err)
		delete(packet.PendingChallenges, ch.Challenge)
		conn.Close()
		return
	}

	mutualSignature, err := pgp.SignMessage(ch.MutualChallenge, pgp.PrivateKey)
	if err != nil {
		logger.Log("error signing mutual challenge:", err)
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
}
