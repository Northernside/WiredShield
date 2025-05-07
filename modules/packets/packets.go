package packet

import (
	"wired/modules/event"
	"wired/modules/types"
)

var PendingChallenges = make(map[string]Challenge) // key -> Challenge

type Login struct {
	types.NodeInfo
}

type Challenge struct {
	NodeInfo        types.NodeInfo
	Challenge       string
	Result          []byte // signed challenge
	MutualChallenge string // used to verify the masters identity
	Nodes           map[string]types.NodeInfo
}

type EventTransmission struct {
	EventBusName string
	Event        event.Event
}
