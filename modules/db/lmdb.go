package db

import (
	"fmt"
	"log"

	"github.com/bmatsuo/lmdb-go/lmdb"

	_Env "wiredshield/modules/Env"
)

var Env *lmdb.Env

func Init() {
	var err error
	Env, err = lmdb.NewEnv()
	if err != nil {
		log.Fatal("failed to create LMDB Environment:", err)
	}

	err = Env.SetMaxReaders(1024 * 32)
	if err != nil {
		log.Fatal("failed to set max readers:", err)
	}

	err = Env.SetMaxDBs(2 ^ 32 - 1)
	if err != nil {
		log.Fatal("failed to set max DBs:", err)
	}

	err = Env.SetMapSize(1 << 22) // 4MB
	if err != nil {
		log.Fatal("failed to set map size:", err)
	}

	lmdbPath := _Env.GetEnv("LMDB_PATH", "./wiredshield.lmdb")
	err = Env.Open(lmdbPath, lmdb.Create|lmdb.NoSubdir, 0644)
	if err != nil {
		log.Fatal("failed to open LMDB Environment:", err)
	}

	err = Env.Update(func(txn *lmdb.Txn) error {
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
