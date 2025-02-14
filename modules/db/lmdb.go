package db

import (
	"fmt"
	"log"
	"wiredshield/modules/env"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

var LEnv *lmdb.Env

func Init() {
	var err error
	LEnv, err = lmdb.NewEnv()
	if err != nil {
		log.Fatal("failed to create LMDB Environment:", err)
	}

	err = LEnv.SetMaxReaders(1024 * 32)
	if err != nil {
		log.Fatal("failed to set max readers:", err)
	}

	err = LEnv.SetMaxDBs(2 ^ 32 - 1)
	if err != nil {
		log.Fatal("failed to set max DBs:", err)
	}

	err = LEnv.SetMapSize(1 << 22) // 4MB
	if err != nil {
		log.Fatal("failed to set map size:", err)
	}

	lmdbPath := env.GetEnv("LMDB_PATH", "./wiredshield.lmdb")
	err = LEnv.Open(lmdbPath, lmdb.Create|lmdb.NoSubdir, 0644)
	if err != nil {
		log.Fatal("failed to open LMDB Environment:", err)
	}

	err = LEnv.Update(func(txn *lmdb.Txn) error {
		_, err := txn.OpenDBI("wiredshield", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		_, err = txn.OpenDBI("entries", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open entries DB: %w", err)
		}

		_, err = txn.OpenDBI("domain_index", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open domain_index DB: %w", err)
		}

		_, err = txn.OpenDBI("passthrough", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open passthrough DB: %w", err)
		}

		_, err = txn.OpenDBI("acme_http", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open passthrough DB: %w", err)
		}

		return nil
	})

	if err != nil {
		log.Fatal("transaction failed:", err)
	}
}
