package postgresql

import (
	"sync"
	"wired/modules/types/user"
	"wired/modules/types/workers"
)

var (
	Users   = make(map[string]*user.User)
	UsersMu sync.RWMutex
)

func CreateUser(id, username, profilePictureURL string) *user.User {
	UsersMu.Lock()
	defer UsersMu.Unlock()

	// TODO: Add PSQL create user logic

	user := &user.User{
		ID:             id,
		Username:       username,
		ProfilePicture: profilePictureURL,
		WorkerScripts:  make([]workers.WorkerScript, 0),
		ErrorPages:     make(map[int]string),
	}

	Users[id] = user
	return user
}

func GetUser(id string) (*user.User, bool) {
	UsersMu.RLock()
	defer UsersMu.RUnlock()

	user, exists := Users[id]
	return user, exists
}

func DeleteUser(id string) {
	UsersMu.Lock()
	defer UsersMu.Unlock()

	delete(Users, id)
	// TODO: Add PSQL delete user logic
}
