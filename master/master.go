package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"wired/master/modules/node"
	"wired/modules/logger"
	packet "wired/modules/packets"
	"wired/modules/pgp"
	"wired/modules/protocol"
)

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

	logger.Log("shared secret received")
	err = conn.EnableEncryption(decryptedBytes)
	if err != nil {
		logger.Fatal("error enabling encryption:", err)
		return
	}

	p := new(protocol.Packet)
	err = p.Read(conn)
	if err != nil {
		return
	}

	switch p.ID {
	case packet.ID_Login:
		var login packet.Login
		err = protocol.DecodePacket(p.Data, &login)
		if err != nil {
			logger.Log("error decoding login packet:", err)
			return
		}

		if _, ok := checkNodeEntry(login.Key); !ok {
			logger.Log("node key not found:", login.Key)
			return
		}

		err = node.SendChallenge(conn, &login)
		if err != nil {
			logger.Log("failed to send challenge:", err)
			return
		}
	default:
		logger.Log("unexpected packet ID:", p.ID)
		return
	}

	for {
		p := new(protocol.Packet)
		err := p.Read(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "connection reset by peer") || errors.Is(err, net.ErrClosed) {
				logger.Log("connection closed by peer")
				return
			}

			logger.Log("error reading packet:", err)
			continue
		}

		switch p.ID {
		case packet.ID_ChallengeResult:
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

			publicKey, ok := checkNodeEntry(ch.Key)
			if !ok {
				logger.Log("node key not found:", ch.Key)
				return
			}

			if err := pgp.VerifySignature(ch.Challenge, ch.Result, publicKey); err != nil {
				delete(packet.PendingChallenges, ch.Challenge)
				return
			}

			conn.SendPacket(packet.ID_Config, "foo")
			delete(packet.PendingChallenges, ch.Challenge)
		default:
			logger.Log("unexpected packet ID:", p.ID)
			return
		}
	}
}

func checkNodeEntry(key string) (*rsa.PublicKey, bool) {
	_, err := os.Stat("keys/" + key + "-public.pem")
	if os.IsNotExist(err) {
		return nil, false
	}

	publicKey, err := pgp.LoadPublicKey("keys/" + key + "-public.pem")
	if err != nil {
		return nil, false
	}

	return publicKey, true
}
