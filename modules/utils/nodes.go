package utils

import (
	"sync"
	"wired/modules/types"
)

var Nodes = make(map[string]types.NodeInfo)
var NodesMux = &sync.RWMutex{}
