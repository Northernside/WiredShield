package postgresql

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
	"wired/modules/env"
	"wired/modules/logger"
	"wired/modules/snowflake"
	"wired/modules/types"
	"wired/modules/types/workers"
)

var (
	sf *snowflake.Snowflake

	Users   = make(map[string]*types.User)
	UsersMu sync.RWMutex
)

func init() {
	env.LoadEnvFile()
	machineIDStr := env.GetEnv("SNOWFLAKE_MACHINE_ID", "0")
	machineID, err := strconv.ParseInt(machineIDStr, 10, 64)
	if err != nil {
		logger.Fatal("Invalid SNOWFLAKE_MACHINE_ID: ", err)
	}

	sf, err = snowflake.NewSnowflake(machineID)
	if err != nil {
		logger.Fatal("Error creating Snowflake instance: ", err)
	}
}

func CreateOrUpdateUser(user *types.User) error {
	UsersMu.Lock()

	user = &types.User{
		Id:            user.Id,
		Username:      user.Username,
		Avatar:        user.Avatar,
		WorkerScripts: []workers.WorkerScript{},
		ErrorPages:    map[int]string{},
		CreatedAt:     time.Now(),
	}

	conn := Manager.GetPool("users")
	if conn != nil {
		_, err := conn.Exec(context.Background(),
			`INSERT INTO users (id, username, profile_picture) VALUES ($1, $2, $3)
			ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, profile_picture = EXCLUDED.profile_picture`,
			user.Id, user.Username, user.Avatar)
		if err != nil {
			UsersMu.Unlock()
			return fmt.Errorf("failed to insert user %s (%s) into DB: %v", user.Username, user.Id, err)
		}
	} else {
		Users[user.Id] = user
		return errors.New("no DB connection available for users")
	}

	UsersMu.Unlock()
	return GetUser(user)
}

func GetUser(user *types.User) error {
	UsersMu.Lock()
	defer UsersMu.Unlock()
	if foundUser, ok := Users[user.Id]; ok {
		*user = *foundUser
		return nil
	}

	conn := Manager.GetPool("users")
	if conn == nil {
		return errors.New("no DB connection available for users")
	}

	err := conn.QueryRow(context.Background(), `SELECT username, profile_picture, created_at FROM users WHERE id=$1`, user.Id).Scan(&user.Username, &user.Avatar, &user.CreatedAt)
	if err != nil {
		return fmt.Errorf("failed to query user %s (%s): %v", user.Username, user.Id, err)
	}

	rows, err := conn.Query(context.Background(), `SELECT script_id, domain, script, created_at FROM worker_scripts WHERE user_id=$1`, user.Id)
	if err != nil {
		return fmt.Errorf("failed to query worker scripts for user %s (%s): %v", user.Username, user.Id, err)
	}
	defer rows.Close()

	scripts := []workers.WorkerScript{}
	for rows.Next() {
		var ws workers.WorkerScript
		err := rows.Scan(&ws.ScriptId, &ws.Domain, &ws.Script, &ws.CreatedAt)
		if err == nil {
			scripts = append(scripts, ws)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to scan worker scripts for user %s (%s): %v", user.Username, user.Id, err)
	}

	user.WorkerScripts = scripts

	errRows, err := conn.Query(context.Background(), `SELECT code, html FROM error_pages WHERE user_id=$1`, user.Id)
	if err != nil {
		return fmt.Errorf("failed to query error pages for user %s (%s): %v", user.Username, user.Id, err)
	}
	defer errRows.Close()

	for errRows.Next() {
		var code int
		var html string
		err := errRows.Scan(&code, &html)
		if err != nil {
			return fmt.Errorf("failed to scan error pages for user %s (%s): %v", user.Username, user.Id, err)
		}

		user.ErrorPages[code] = html
	}

	Users[user.Id] = user
	return nil
}

func DeleteUser(id string) {
	UsersMu.Lock()
	defer UsersMu.Unlock()
	delete(Users, id)

	conn := Manager.GetPool("users")
	if conn != nil {
		_, err := conn.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, id)
		if err != nil {
			logger.Println("Failed to delete user in DB: ", err)
		}
	}
}
