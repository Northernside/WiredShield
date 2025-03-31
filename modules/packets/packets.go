package packet

import (
	"wired/modules/event"
	"wired/modules/protocol"
	"wired/modules/types"
)

const (
	ID_SharedSecret    protocol.VarInt = 0 // node -> master
	ID_Login           protocol.VarInt = 1
	ID_ChallengeStart  protocol.VarInt = 2
	ID_ChallengeResult protocol.VarInt = 3
	ID_ChallengeFinish protocol.VarInt = 4
	ID_Config          protocol.VarInt = 5 // master -> node // just json encoded config as string
	ID_Ready           protocol.VarInt = 7 // node -> node, node is ready

	ID_Ping  protocol.VarInt = 8  // master -> node
	ID_Pong  protocol.VarInt = 9  // node -> master response to ping
	ID_Error protocol.VarInt = 10 // just string (error)

	ID_BinaryData    protocol.VarInt = 11 // binary data with label
	ID_BinaryDataEnd protocol.VarInt = 12

	ID_EventTransmission protocol.VarInt = 13
)

var PendingChallenges = make(map[string]Challenge) // key -> Challenge

type Login struct {
	types.NodeInfo
}

type Challenge struct {
	Key             string
	Challenge       string
	Result          []byte // signed challenge
	MutualChallenge string // used to verify the masters identity
}

type EventTransmission struct {
	Event event.Event
}
