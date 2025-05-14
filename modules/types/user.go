package types

import (
	"time"
	"wired/modules/types/workers"
)

type User struct {
	Id            string // `json:"id"`
	Username      string // `json:"global_name"`
	Avatar        string // `json:"avatar"`
	WorkerScripts []workers.WorkerScript
	ErrorPages    map[int]string
	CreatedAt     time.Time
}
