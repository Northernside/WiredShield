package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/bmatsuo/lmdb-go/lmdb"

	_env "wiredshield/modules/env"
)

var env *lmdb.Env

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
		_, err := txn.OpenDBI("wiredshield", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		_, err = txn.OpenDBI(entriesDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open entries DB: %w", err)
		}

		domainIndex, err := txn.OpenDBI(domainIndexDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to create/open domain_index DB: %w", err)
		}

		key := []byte(dnsDomainsKey)
		_, err = txn.Get(domainIndex, key)
		if errors.Is(err, lmdb.NotFound) {
			emptyDomains := []string{}
			emptyDomainsData, err := json.Marshal(emptyDomains)
			if err != nil {
				return fmt.Errorf("failed to marshal empty domains list: %w", err)
			}

			if err := txn.Put(domainIndex, key, emptyDomainsData, 0); err != nil {
				return fmt.Errorf("failed to initialize dns_domains key: %w", err)
			}

			fmt.Println("Initialized 'dns_domains' key with an empty list.")
		} else if err != nil {
			return fmt.Errorf("failed to fetch dns_domains key: %w", err)
		} else {
			fmt.Println("Found 'dns_domains' key in the domain_index DB.")
		}

		return nil
	})

	if err != nil {
		log.Fatal("transaction failed:", err)
	}
}
