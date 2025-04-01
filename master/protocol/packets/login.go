package packets

import (
	"fmt"
	"time"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/utils"
)

type LoginHandler struct{}

func (h *LoginHandler) Handle(conn *protocol.Conn, p *protocol.Packet) {
	var login packet.Login
	err := protocol.DecodePacket(p.Data, &login)
	if err != nil {
		logger.Println("Error decoding login packet:", err)
		conn.Close()
		return
	}

	_, err = pgp.LoadPublicKey("keys/" + login.Key + "-public.pem")
	if err != nil {
		logger.Println("Error loading public key:", err)
		conn.Close()
		return
	}

	challenge := fmt.Sprintf("%s-%d-%s",
		login.Key,
		time.Now().UnixMilli(),
		utils.RandomString(8),
	)

	packet.PendingChallenges[challenge] = packet.Challenge{
		Challenge: challenge,
		Key:       login.Key,
	}

	err = conn.SendPacket(packet.ID_ChallengeStart, packet.Challenge{
		Challenge: challenge,
	})
	if err != nil {
		logger.Println("Error sending challenge packet:", err)
		conn.Close()
		return
	}
}
