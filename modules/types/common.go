package types

import (
	"net"
	"wired/modules/protocol"
)

type Location struct {
	Lat float64
	Lon float64
}

type Modules struct{}

// extend the NodeConfig struct as NodeInfo
type NodeInfo struct {
	Key       string
	Arch      string // arm64, x86
	Version   string
	Hash      []byte // binary hash
	PID       int
	Listeners []net.IP
	Location  Location
	Modules   []Modules
	Conn      *protocol.Conn
}
