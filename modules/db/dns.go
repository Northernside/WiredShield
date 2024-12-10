package db

import (
	"fmt"
	"strings"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

// function to set a dns record in the database (create a new db for a second level domain)
func SetRecord(recordType, domain, target string, protected bool) error {
	return env.Update(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		return txn.Put(db, []byte(recordType+":"+domain), []byte(target+"#"+fmt.Sprint(protected)), 0)
	})
}

// function to get a dns record from the database
func GetRecord(recordType, domain string) (string, bool, error) {
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

	var protected bool

	// split by # to get the protected status
	if strings.Contains(target, "#") {
		parts := strings.Split(target, "#")
		target = parts[0]
		protected = parts[1] == "true"
	}

	return target, protected, err
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

type Record struct {
	RecordType string
	Domain     string
	Target     string
	Protected  bool
}

type RecordResponse struct {
	Target    string
	Protected bool
}

// function to get all dns records from a second level domain
func GetAllRecords(host string) (map[string]RecordResponse, error) {
	records := make(map[string]RecordResponse)
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

			keyParts := strings.SplitN(string(k), ":", 2)
			valueParts := strings.SplitN(string(v), "#", 2)
			if len(keyParts) != 2 || len(valueParts) != 2 {
				continue
			}

			recordType := keyParts[0]
			domain := keyParts[1]
			target := valueParts[0]
			protected := valueParts[1] == "true"

			records[recordType+" "+domain] = RecordResponse{
				Target:    target,
				Protected: protected,
			}
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
