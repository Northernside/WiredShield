package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	protocol_handler "wired/master/protocol"
	"wired/modules/env"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	pgp.InitKeys()
	initNodeListener()
}

func initNodeListener() {
	listener, err := net.Listen("tcp", ":2000")
	if err != nil {
		logger.Fatal(err)
	}
	defer func() {
		err := listener.Close()
		if err != nil {
			logger.Fatal(err)
		}

		logger.Log("node listener closed")
	}()

	logger.Log("Listening for nodes on port 2000")

	for {
		client, err := listener.Accept()
		if err != nil {
			fmt.Println("error accepting connection:", err)
			continue
		}

		go nodeHandler(protocol.NewConn(client))
	}
}

func nodeHandler(conn *protocol.Conn) {
	defer func() {
		r := recover()
		if r != nil {
			logger.Log("recovered in nodeHandler: ", r)
		}

		conn.Close()
		logger.Log("node connection closed")
	}()

	handleEncryption(conn)

	p := new(protocol.Packet)
	err := p.Read(conn)
	if err != nil {
		return
	}

	if p.ID != packet.ID_Login {
		logger.Log("unexpected packet ID at login stage:", p.ID)
		return
	}

	packetHandler(conn, p)

	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			logger.Log("failed to read packet:", err)
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
		logger.Log("unexpected packet ID:", recvPacket.ID)
		return
	}

	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, pgp.PrivateKey, recvPacket.Data)
	if err != nil {
		logger.Log("error decrypting shared secret:", err)
		return
	}

	err = conn.EnableEncryption(decryptedBytes)
	if err != nil {
		logger.Fatal("error enabling encryption:", err)
		return
	}
}

func packetHandler(conn *protocol.Conn, p *protocol.Packet) {
	handler := protocol_handler.GetHandler(conn, p.ID)
	if handler == nil {
		logger.Log("no handler for packet ID:", p.ID)
		return
	}

	handler.Handle(conn, p)
}
