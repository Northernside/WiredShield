package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"runtime"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/types"
	"wired/modules/utils"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	pgp.InitKeys()
	initNode()
}

func initNode() {
	conn, err := connectToMaster()
	if err != nil {
		logger.Fatal("failed to connect to master:", err)
		return
	}
	defer conn.Close()

	sharedSecret := utils.RandomBytes(16)
	masterPubKey, err := pgp.LoadPublicKey("keys/master-public.pem")
	if err != nil {
		logger.Fatal("failed to load master public key:", err)
		return
	}

	buf, err := rsa.EncryptPKCS1v15(rand.Reader, masterPubKey, sharedSecret)
	if err != nil {
		logger.Log("failed to encrypt shared secret:", err)
		return
	}

	err = conn.SendRawPacket(packet.ID_SharedSecret, buf)
	if err != nil {
		logger.Fatal("failed to send shared secret packet:", err)
		return
	}

	err = conn.EnableEncryption(sharedSecret)
	if err != nil {
		logger.Fatal("failed to enable encryption:", err)
		return
	}

	err = conn.SendPacket(packet.ID_Login, packet.Login{
		NodeInfo: types.NodeInfo{
			Key:       env.GetEnv("NODE_KEY", "node-key"),
			Arch:      runtime.GOARCH,
			Version:   "",
			Hash:      []byte{},
			PID:       os.Getpid(),
			Listeners: getListeners(),
			Location:  types.Location{Lon: 0, Lat: 0},
			Modules:   []types.Modules{},
		},
	})
	if err != nil {
		logger.Fatal("failed to send login packet:", err)
		return
	}

	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			logger.Fatal("failed to read packet:", err)
			return
		}

		switch p.ID {
		case packet.ID_ChallengeStart:
			var challenge packet.Challenge
			err := protocol.DecodePacket(p.Data, &challenge)
			if err != nil {
				logger.Fatal("failed to decode challenge packet:", err)
				return
			}

			signature, err := pgp.SignMessage(challenge.Challenge, pgp.PrivateKey)
			if err != nil {
				logger.Fatal("failed to sign challenge:", err)
				return
			}

			challengeResultPacket := packet.Challenge{
				Challenge: challenge.Challenge,
				Result:    signature,
				Key:       env.GetEnv("NODE_KEY", "node-key"),
			}

			err = conn.SendPacket(packet.ID_ChallengeResult, challengeResultPacket)
			if err != nil {
				logger.Fatal("failed to send challenge result packet:", err)
				return
			}
		case packet.ID_Config:
			var config string
			if err := protocol.DecodePacket(p.Data, &config); err != nil {
				logger.Fatal("failed to decode config packet:", err)
				return
			}

			logger.Log("received config:", config)
		default:
			return
		}
	}
}

func connectToMaster() (*protocol.Conn, error) {
	conn, err := net.Dial("tcp", "127.0.0.1:2000")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to master: %w", err)
	}

	return protocol.NewConn(conn), nil
}

func getListeners() []net.IP {
	listeners := []net.IP{}

	ifaces, err := net.Interfaces()
	if err != nil {
		logger.Log("failed to get network interfaces:", err)
		return listeners
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Log("failed to get addresses for interface:", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
				continue
			}
			listeners = append(listeners, ipNet.IP)
		}
	}

	return listeners
}
