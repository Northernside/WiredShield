package packets

import (
	"wired/modules/globals"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/utils"
)

type ChallengeResultHandler struct{}

func (h *ChallengeResultHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var ch packet.Challenge
	err := protocol.DecodePacket(p.Data, &ch)
	if err != nil {
		logger.Println("Error decoding challenge result packet: ", err)
		return
	}

	if _, ok := packet.PendingChallenges[ch.Challenge]; !ok {
		logger.Println("Challenge not found: ", ch.Challenge)
		return
	}

	newNode := packet.PendingChallenges[ch.Challenge].NodeInfo
	publicKey, err := pgp.LoadPublicKey("keys/" + newNode.Key + "-public.pem")
	if err != nil {
		logger.Println("Error loading public key: ", err)
		conn.Close()
		return
	}

	if err := pgp.VerifySignature(ch.Challenge, ch.Result, publicKey); err != nil {
		logger.Println("Signature verification failed: ", err)
		delete(packet.PendingChallenges, ch.Challenge)
		conn.Close()
		return
	}

	mutualSignature, err := pgp.SignMessage(ch.MutualChallenge, pgp.PrivateKey)
	if err != nil {
		logger.Println("Error signing mutual challenge: ", err)
		conn.Close()
		return
	}

	logger.Printf("Node %s%s%s connected\n", logger.ColorGray, newNode.Key, logger.ColorReset)

	for _, node := range utils.Nodes {
		if node.Key == newNode.Key {
			continue
		}

		node.Conn.SendPacket(globals.Packet.ID_NodeAttached, newNode)
	}

	challengeFinishPacket := packet.Challenge{
		Challenge: ch.MutualChallenge,
		Result:    mutualSignature,
		Nodes:     utils.Nodes,
	}

	conn.State = protocol.StateFullyReady
	conn.SendPacket(globals.Packet.ID_ChallengeFinish, challengeFinishPacket)
	delete(packet.PendingChallenges, ch.Challenge)
}
