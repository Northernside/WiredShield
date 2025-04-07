package main

import (
	"crypto/rand"
	"crypto/rsa"
	_ "embed"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"
	"wired/modules/cache"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/types"
	"wired/modules/utils"
	"wired/node/dns"
	protocol_handler "wired/node/protocol"
)

//go:embed version.txt
var version string

func init() {
	env.LoadEnvFile()
}

func main() {
	cache.Store("authentication_finished", false, 0)
	pgp.InitKeys()
	go dns.Start()

	for {
		initNode()
		logger.Println("Reconnecting to master...")
		time.Sleep(5 * time.Second)
	}
}

func initNode() {
	conn, err := connectToMaster()
	if err != nil {
		logger.Println("Failed to connect to master:", err)
		return
	}
	defer conn.Close()

	handleEncryption(conn)

	logger.Println("Connected to master")

	fileHash, err := utils.GetFileHash(os.Args[0])
	if err != nil {
		logger.Fatal("Failed to get binary hash:", err)
		return
	}

	err = conn.SendPacket(packet.ID_Login, packet.Login{
		NodeInfo: types.NodeInfo{
			Key:       env.GetEnv("NODE_KEY", "node-key"),
			Arch:      runtime.GOARCH,
			Version:   version,
			Hash:      fileHash,
			PID:       os.Getpid(),
			Listeners: utils.GetListeners(),
			Location:  types.Location{Lon: 0, Lat: 0},
			Modules:   []types.Modules{},
		},
	})
	if err != nil {
		logger.Fatal("Failed to send login packet:", err)
		return
	}

	cache.Store("master_conn", conn, 0)
	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			if err == io.EOF {
				logger.Println("Lost connecton to master")
				return
			}

			logger.Fatal("Failed to read packet:", err)
			return
		}

		handler := protocol_handler.GetHandler(p.ID)
		if handler != nil {
			handler.Handle(conn, p)
		} else {
			logger.Println("Unknown packet ID:", p.ID)
		}
	}
}

func connectToMaster() (*protocol.Conn, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:2000", env.GetEnv("GATEWAY", "shepherd.wired.rip")))
	if err != nil {
		return nil, err
	}

	return protocol.NewConn(conn), nil
}

func handleEncryption(conn *protocol.Conn) {
	sharedSecret := utils.RandomBytes(16)
	masterPubKey, err := pgp.LoadPublicKey("keys/master-public.pem")
	if err != nil {
		logger.Fatal("Failed to load master public key:", err)
		return
	}

	buf, err := rsa.EncryptPKCS1v15(rand.Reader, masterPubKey, sharedSecret)
	if err != nil {
		logger.Println("Failed to encrypt shared secret:", err)
		return
	}

	err = conn.SendRawPacket(packet.ID_SharedSecret, buf)
	if err != nil {
		logger.Fatal("Failed to send shared secret packet:", err)
		return
	}

	err = conn.EnableEncryption(sharedSecret)
	if err != nil {
		logger.Fatal("Failed to enable encryption:", err)
		return
	}
}
