package user

import "wired/modules/types/workers"

type User struct {
	ID             string
	Username       string
	ProfilePicture string
	WorkerScripts  []workers.WorkerScript
	ErrorPages     map[int]string
}
