package db

import (
	"fmt"
	"log"

	"github.com/bmatsuo/lmdb-go/lmdb"

	_env "wiredshield/modules/env"
)

var env *lmdb.Env
var db lmdb.DBI

func Init() {
	var err error
	env, err = lmdb.NewEnv()
	if err != nil {
		log.Fatal("failed to create LMDB environment:", err)
	}

	err = env.SetMaxReaders(1024 * 32)
	if err != nil {
		log.Fatal("failed to set max readers:", err)
	}

	err = env.SetMaxDBs(2 ^ 32 - 1)
	if err != nil {
		log.Fatal("failed to set max DBs:", err)
	}

	err = env.SetMapSize(1 << 22) // 4MB
	if err != nil {
		log.Fatal("failed to set map size:", err)
	}

	lmdbPath := _env.GetEnv("LMDB_PATH", "./wiredshield.lmdb")
	err = env.Open(lmdbPath, lmdb.Create|lmdb.NoSubdir, 0644)
	if err != nil {
		log.Fatal("failed to open LMDB environment:", err)
	}

	err = env.Update(func(txn *lmdb.Txn) error {
		db, err = txn.OpenDBI("wiredshield", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		return nil
	})

	if err != nil {
		log.Fatal("transaction failed:", err)
	}

	env.Update(func(txn *lmdb.Txn) error {
		_, err := txn.OpenDBI(entriesDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open entries DB: %w", err)
		}

		_, err = txn.OpenDBI(domainIndexDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open domain_index DB: %w", err)
		}

		return nil
	})
}

func SetTarget(host, target string) error {
	err := env.Update(func(txn *lmdb.Txn) error {
		err := txn.Put(db, []byte(host), []byte(target), 0)
		if err != nil {
			return fmt.Errorf("failed to put key: %v", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func GetTarget(host string) string {
	var target string

	err := env.View(func(txn *lmdb.Txn) error {
		val, err := txn.Get(db, []byte(host))
		if err != nil {
			return fmt.Errorf("failed to get key: %v", err)
		}

		target = string(val)

		return nil
	})

	if err != nil {
		return ""
	}

	return target
}
