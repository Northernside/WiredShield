package db

import (
	"fmt"
	"strings"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

// function to set a dns record in the database (create a new db for a second level domain)
func SetRecord(recordType, domain, target string) error {
	return env.Update(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		return txn.Put(db, []byte(recordType+":"+domain), []byte(target), 0)
	})
}

// function to get a dns record from the database
func GetRecord(recordType, domain string) (string, error) {
	var target string
	err := env.View(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		val, err := txn.Get(db, []byte(recordType+":"+domain))
		if err != nil {
			return fmt.Errorf("failed to get key: %v", err)
		}

		target = string(val)

		return nil
	})

	return target, err
}

// function to delete a dns record from the database
func DeleteRecord(recordType, domain string) error {
	return env.Update(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		return txn.Del(db, []byte(recordType+":"+domain), nil)
	})
}

// function to get all dns records from a second level domain
func GetAllRecords(host string) (map[string]string, error) {
	records := make(map[string]string)
	err := env.View(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(host)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		cursor, err := txn.OpenCursor(db)
		if err != nil {
			return fmt.Errorf("failed to open cursor: %v", err)
		}
		defer cursor.Close()

		for {
			k, v, err := cursor.Get(nil, nil, lmdb.Next)
			if lmdb.IsNotFound(err) {
				break
			} else if err != nil {
				return fmt.Errorf("failed to get next: %v", err)
			}

			parts := strings.Split(string(k), ":")
			records[parts[0]+" "+parts[1]] = string(v)
		}

		return nil
	})

	return records, err
}

func getSecondLevelDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain")
	}

	return parts[len(parts)-2] + "." + parts[len(parts)-1], nil
}
