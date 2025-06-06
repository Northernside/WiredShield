package packets

import (
	"fmt"
	"time"
	"wired/modules/globals"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/types"
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
		NodeInfo:  login.NodeInfo,
		Challenge: challenge,
	}

	err = conn.SendPacket(globals.Packet.ID_ChallengeStart, packet.Challenge{
		Challenge: challenge,
	})
	if err != nil {
		logger.Println("Error sending challenge packet:", err)
		conn.Close()
		return
	}

	nodeInfo := types.NodeInfo{
		Key:       login.Key,
		Arch:      login.Arch,
		Version:   login.Version,
		Hash:      login.Hash,
		PID:       login.PID,
		Listeners: login.Listeners,
		Location:  login.Location,
		Modules:   login.Modules,
		Conn:      conn,
	}

	utils.NodesMux.Lock()
	utils.Nodes[login.Key] = nodeInfo
	utils.NodesMux.Unlock()

	conn.Key = login.Key
}
