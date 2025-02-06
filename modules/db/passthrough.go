package db

import (
	"encoding/json"
	"fmt"
	"strconv"
	"wiredshield/modules/epoch"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

const (
	passthroughDB = "passthrough"
)

// Passthrough is a basic reverse proxy feature
// Instead of the domain being NS registered to us, we can just pass the request to the target

type Passthrough struct { // omit key in json
	Id         uint64 `json:"-"` // snowflake id
	Domain     string `json:"domain"`
	Path       string `json:"path"`
	TargetAddr string `json:"target_addr"`
	TargetPort uint16 `json:"target_port"`
	TargetPath string `json:"target_path"`
	Ssl        bool   `json:"ssl"`
}

func InsertPassthrough(passthrough Passthrough) error {
	pErr := env.Update(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(passthroughDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		var id uint64
		snowflake, err := epoch.NewSnowflake(512)
		if err != nil {
			return fmt.Errorf("failed to create snowflake: %v", err)
		}

		id = snowflake.GenerateID()

		// save as json, key is the snowflake id
		data, err := json.Marshal(passthrough)
		if err != nil {
			return fmt.Errorf("failed to marshal passthrough: %v", err)
		}

		key := strconv.FormatUint(id, 10)
		if err := txn.Put(dbi, []byte(key), data, 0); err != nil {
			return fmt.Errorf("failed to put data: %v", err)
		}

		return nil
	})

	return pErr
}

func GetAllPassthroughs() ([]Passthrough, error) {
	var passthroughs []Passthrough

	pErr := env.View(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(passthroughDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		cursor, err := txn.OpenCursor(dbi)
		if err != nil {
			return fmt.Errorf("failed to open cursor: %v", err)
		}
		defer cursor.Close()

		for {
			k, v, err := cursor.Get(nil, nil, lmdb.Next)
			if lmdb.IsNotFound(err) {
				break
			} else if err != nil {
				return fmt.Errorf("cursor error: %v", err)
			}

			var passthrough Passthrough
			if err := json.Unmarshal(v, &passthrough); err != nil {
				return fmt.Errorf("failed to unmarshal passthrough: %v", err)
			}

			passthrough.Id, err = strconv.ParseUint(string(k), 10, 64)
			if err != nil {
				return fmt.Errorf("failed to parse key: %v", err)
			}

			passthroughs = append(passthroughs, passthrough)
		}

		return nil
	})

	return passthroughs, pErr
}

func DeletePassthrough(id uint64) error {
	pErr := env.Update(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(passthroughDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		key := strconv.FormatUint(id, 10)
		if err := txn.Del(dbi, []byte(key), nil); err != nil {
			return fmt.Errorf("failed to delete data: %v", err)
		}

		return nil
	})

	return pErr
}
