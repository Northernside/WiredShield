package acme_http

import (
	"encoding/json"
	"fmt"
	"wiredshield/modules/db"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

const (
	acmeHttpDB = "acme_http"
)

type HttpChallenge struct {
	PublicToken string `json:"token"`
	FullToken   string `json:"full_token"`
	Domain      string `json:"domain"`
}

func InsertHttpChallenge(httpChallenge HttpChallenge, self bool) error {
	aErr := db.LEnv.Update(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(acmeHttpDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		// save as json, key is the token
		data, err := json.Marshal(httpChallenge)
		if err != nil {
			return fmt.Errorf("failed to marshal httpChallenge: %v", err)
		}

		if err := txn.Put(dbi, []byte(httpChallenge.PublicToken), data, 0); err != nil {
			return fmt.Errorf("failed to put data: %v", err)
		}

		return nil
	})

	if aErr == nil && !self {
		go syncSet(httpChallenge)
	}

	return aErr
}

func GetHttpChallenge(token string) (HttpChallenge, error) {
	var httpChallenge HttpChallenge

	aErr := db.LEnv.View(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(acmeHttpDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		// get the data by token
		data, err := txn.Get(dbi, []byte(token))
		if err != nil {
			return fmt.Errorf("failed to get data: %v", err)
		}

		if err := json.Unmarshal(data, &httpChallenge); err != nil {
			return fmt.Errorf("failed to unmarshal httpChallenge: %v", err)
		}

		return nil
	})

	return httpChallenge, aErr
}

func DeleteHttpChallenge(token string, self bool) error {
	aErr := db.LEnv.Update(func(txn *lmdb.Txn) error {
		dbi, err := txn.OpenDBI(acmeHttpDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		if err := txn.Del(dbi, []byte(token), nil); err != nil {
			return fmt.Errorf("failed to delete data: %v", err)
		}

		return nil
	})

	if aErr == nil && !self {
		go syncDel(token)
	}

	return aErr
}
