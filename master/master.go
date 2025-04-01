package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	protocol_handler "wired/master/protocol"
	"wired/modules/cache"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
	"wired/modules/types"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	logger.Printf(logger.Banner)

	pgp.InitKeys()
	initNodeListener()
}

func initNodeListener() {
	listener, err := net.Listen("tcp", ":2000")
	if err != nil {
		logger.Fatal("Failed to start node listener:", err)
	}
	defer func() {
		err := listener.Close()
		if err != nil {
			logger.Fatal("Failed to close node listener:", err)
		}

		logger.Println("Node listener closed")
	}()

	logger.Println("Listening for nodes on port 2000")

	for {
		client, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go nodeHandler(protocol.NewConn(client))
	}
}

func nodeHandler(conn *protocol.Conn) {
	defer func() {
		r := recover()
		if r != nil {
			logger.Println("Recovered in nodeHandler: ", r)
		}

		conn.Close()

		if conn.Key != "" {
			logger.Println(fmt.Sprintf("Node %s%s%s disconnected", logger.ColorGray, conn.Key, logger.ColorReset))

			value, found := cache.Get[map[string]types.NodeInfo]("nodes")
			if found {
				delete(value, conn.Key)
				cache.Store("nodes", value, 0)
			}
		}
	}()

	handleEncryption(conn)

	p := new(protocol.Packet)
	err := p.Read(conn)
	if err != nil {
		return
	}

	if p.ID != packet.ID_Login {
		logger.Println("Unexpected packet ID during login stage:", p.ID)
		return
	}

	packetHandler(conn, p)

	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			if err != io.EOF {
				logger.Println("Failed to read packet: ", err)
			}

			return
		}

		packetHandler(conn, p)
	}
}

func handleEncryption(conn *protocol.Conn) {
	identifier := [4]byte{}
	_, err := io.ReadFull(conn, identifier[:])
	if err != nil {
		return
	}

	var recvPacket protocol.Packet
	err = recvPacket.Read(io.MultiReader(bytes.NewReader(identifier[:]), conn))
	if err != nil {
		return
	}

	if recvPacket.ID != packet.ID_SharedSecret {
		logger.Println("Unexpected packet ID:", recvPacket.ID)
		return
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, pgp.PrivateKey, recvPacket.Data)
	if err != nil {
		logger.Println("Error decrypting shared secret:", err)
		return
	}

	err = conn.EnableEncryption(decryptedBytes)
	if err != nil {
		logger.Fatal("Error enabling encryption:", err)
		return
	}
}

func packetHandler(conn *protocol.Conn, p *protocol.Packet) {
	handler := protocol_handler.GetHandler(conn, p.ID)
	if handler == nil {
		logger.Println("No handler for packet ID:", p.ID)
		return
	}

	handler.Handle(conn, p)
}
