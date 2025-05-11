package workers

import "time"

type WorkerScript struct {
	ScriptID  string
	Domain    string
	Script    string
	CreatedAt time.Time
}
