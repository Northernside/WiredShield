package workers

import "time"

type WorkerScript struct {
	ScriptId  string
	Domain    string
	Script    string
	CreatedAt time.Time
}
