package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"wiredshield/services"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

const (
	entriesDB     = "entries"
	domainIndexDB = "domain_index"
	dnsDomainsKey = "dns_domains"
)

func GetRecordType(record interface{}) string {
	typeName := reflect.TypeOf(record).Name()
	typeName = strings.TrimSuffix(typeName, "Record")

	return typeName
}

func InsertRecord(record DNSRecord, self bool) error {
	eErr := env.Update(func(txn *lmdb.Txn) error {
		// open "entries" and "domain_index" dbs
		entries, err := txn.OpenDBI(entriesDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open entries DB: %w", err)
		}

		domainIndex, err := txn.OpenDBI(domainIndexDB, lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open domain_index DB: %w", err)
		}

		recordBytes, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("failed to serialize record: %w", err)
		}

		// insert into "entries" DB
		if err := txn.Put(entries, uint64ToByteArray(record.GetID()), recordBytes, 0); err != nil {
			return fmt.Errorf("failed to add record to entries DB: %w", err)
		}

		// update "domain_index" db
		domain, err := getSecondLevelDomain(record.GetDomain())
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %w", err)
		}

		indexData, err := txn.Get(domainIndex, []byte(domain))

		// create domain index if not exists
		if err != nil {
			if lmdb.IsNotFound(err) {
				indexData = []byte("[]")
			} else {
				return fmt.Errorf("failed to get domain index: %w", err)
			}
		}

		var recordIDs []uint64
		if err := json.Unmarshal(indexData, &recordIDs); err != nil {
			return fmt.Errorf("failed to deserialize domain index: %w", err)
		}

		// append new id if not present
		exists := false
		for _, id := range recordIDs {
			if id == record.GetID() {
				exists = true
				break
			}
		}

		if !exists {
			recordIDs = append(recordIDs, record.GetID())
			indexBytes, err := json.Marshal(recordIDs)
			if err != nil {
				return fmt.Errorf("failed to serialize updated domain index: %w", err)
			}

			if err := txn.Put(domainIndex, []byte(domain), indexBytes, 0); err != nil {
				return fmt.Errorf("failed to update domain index: %w", err)
			}
		}

		return nil
	})

	if eErr == nil && !self {
		go syncSet(record)
	}

	return eErr
}

func DeleteRecord(id uint64, domain string, self bool) error {
	eErr := env.Update(func(txn *lmdb.Txn) error {
		// open "entries" and "domain_index" databases
		entries, err := txn.OpenDBI(entriesDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open entries DB: %w", err)
		}

		domainIndex, err := txn.OpenDBI(domainIndexDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open domain_index DB: %w", err)
		}

		// remove from "entries" db
		if err := txn.Del(entries, uint64ToByteArray(id), nil); err != nil {
			return fmt.Errorf("failed to delete record from entries DB: %w", err)
		}

		// remove from "domain_index" db
		indexData, err := txn.Get(domainIndex, []byte(domain))
		if err != nil {
			if errors.Is(err, lmdb.NotFound) {
				return nil // no records for this domain
			}

			return fmt.Errorf("failed to fetch domain index: %w", err)
		}

		// deserialize, remove the id & reserialize
		var recordIDs []uint64
		if err := json.Unmarshal(indexData, &recordIDs); err != nil {
			return fmt.Errorf("failed to unmarshal domain index: %w", err)
		}

		newRecordIDs := []uint64{}
		for _, existingID := range recordIDs {
			if existingID != id {
				newRecordIDs = append(newRecordIDs, existingID)
			}
		}

		if len(newRecordIDs) == 0 {
			// no more records for this domain, delete the domain key
			if err := txn.Del(domainIndex, []byte(domain), nil); err != nil {
				return fmt.Errorf("failed to delete domain index: %w", err)
			}
		} else {
			// otherwise, update the domains id list
			indexBytes, err := json.Marshal(newRecordIDs)
			if err != nil {
				return fmt.Errorf("failed to serialize updated domain index: %w", err)
			}
			if err := txn.Put(domainIndex, []byte(domain), indexBytes, 0); err != nil {
				return fmt.Errorf("failed to update domain index: %w", err)
			}
		}

		return nil
	})

	if eErr == nil && !self {
		go syncDel(id, domain)
	}

	return eErr
}

func GetRecordsByDomain(domain string) ([]DNSRecord, error) {
	records := []DNSRecord{}
	domain, err := getSecondLevelDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get second level domain: %v", err)
	}

	err = env.View(func(txn *lmdb.Txn) error {
		entries, err := txn.OpenDBI(entriesDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open entries DB: %w", err)
		}

		domainIndex, err := txn.OpenDBI(domainIndexDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open domain_index DB: %w", err)
		}

		// get the list of record ids for the domain
		indexData, err := txn.Get(domainIndex, []byte(domain))
		if err != nil {
			if errors.Is(err, lmdb.NotFound) {
				return nil // no records for this domain
			}

			return fmt.Errorf("failed to fetch domain index: %w", err)
		}

		var recordIDs []uint64
		if err := json.Unmarshal(indexData, &recordIDs); err != nil {
			return fmt.Errorf("failed to unmarshal domain index: %w", err)
		}

		// fetch all records by id
		for _, id := range recordIDs {
			entryData, err := txn.Get(entries, uint64ToByteArray(id))
			if err != nil {
				if errors.Is(err, lmdb.NotFound) {
					continue // skip missing records
				}

				return fmt.Errorf("failed to fetch record: %w", err)
			}

			// try unmarshalling into concrete record types
			var record DNSRecord
			if err := unmarshalRecord(entryData, &record); err != nil {
				return fmt.Errorf("failed to deserialize record: %w", err)
			}

			records = append(records, record)
		}

		return nil
	})

	return records, err
}

func unmarshalRecord(data []byte, record *DNSRecord) error {
	var recordType map[string]interface{}
	if err := json.Unmarshal(data, &recordType); err != nil {
		return err
	}

	// unmarshal to the correct type
	switch recordType["type"] {
	case "A":
		var aRecord ARecord
		if err := json.Unmarshal(data, &aRecord); err != nil {
			return err
		}

		*record = &aRecord
	case "AAAA":
		var aaaaRecord AAAARecord
		if err := json.Unmarshal(data, &aaaaRecord); err != nil {
			return err
		}

		*record = &aaaaRecord
	case "SRV":
		var srvRecord SRVRecord
		if err := json.Unmarshal(data, &srvRecord); err != nil {
			return err
		}

		*record = &srvRecord
	case "CNAME":
		var cnameRecord CNAMERecord
		if err := json.Unmarshal(data, &cnameRecord); err != nil {
			return err
		}

		*record = &cnameRecord
	case "SOA":
		var soaRecord SOARecord
		if err := json.Unmarshal(data, &soaRecord); err != nil {
			return err
		}

		*record = &soaRecord
	case "TXT":
		var txtRecord TXTRecord
		if err := json.Unmarshal(data, &txtRecord); err != nil {
			return err
		}

		*record = &txtRecord
	case "NS":
		var nsRecord NSRecord
		if err := json.Unmarshal(data, &nsRecord); err != nil {
			return err
		}

		*record = &nsRecord
	case "MX":
		var mxRecord MXRecord
		if err := json.Unmarshal(data, &mxRecord); err != nil {
			return err
		}

		*record = &mxRecord
	case "CAA":
		var caaRecord CAARecord
		if err := json.Unmarshal(data, &caaRecord); err != nil {
			return err
		}

		*record = &caaRecord
	default:
		services.ProcessService.InfoLog(fmt.Sprintf("unsupported record type: %v", recordType))
		return fmt.Errorf("unsupported record type: %v", recordType["type"])
	}

	return nil
}

func GetAllDomains() ([]string, error) {
	var domains []string

	err := env.View(func(txn *lmdb.Txn) error {
		domainIndex, err := txn.OpenDBI(domainIndexDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open domain_index DB: %w", err)
		}

		indexData, err := txn.Get(domainIndex, []byte(dnsDomainsKey))
		if errors.Is(err, lmdb.NotFound) {
			// initialize the key if it doesn't exist
			domains = []string{}
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to fetch domain index: %w", err)
		}

		if err := json.Unmarshal(indexData, &domains); err != nil {
			return fmt.Errorf("failed to unmarshal domain index: %w", err)
		}

		return nil
	})

	return domains, err
}

func GetRecords(recordType, domain string) ([]DNSRecord, error) {
	var records []DNSRecord

	// get the second-level domain
	domain, err := getSecondLevelDomain(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get second-level domain: %w", err)
	}

	err = env.View(func(txn *lmdb.Txn) error {
		entries, err := txn.OpenDBI(entriesDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open entries DB: %w", err)
		}

		domainIndex, err := txn.OpenDBI(domainIndexDB, 0)
		if err != nil {
			return fmt.Errorf("failed to open domain_index DB: %w", err)
		}

		// get the list of record ids for the domain
		indexData, err := txn.Get(domainIndex, []byte(domain))
		if err != nil {
			if errors.Is(err, lmdb.NotFound) {
				return nil // no records for this domain
			}

			return fmt.Errorf("failed to fetch domain index: %w", err)
		}

		services.ProcessService.InfoLog(fmt.Sprintf("indexData: %v", indexData))

		var recordIDs []uint64
		if err := json.Unmarshal(indexData, &recordIDs); err != nil {
			return fmt.Errorf("failed to unmarshal domain index: %w", err)
		}

		services.ProcessService.InfoLog(fmt.Sprintf("recordIDs: %v", recordIDs))

		// fetch and filter records by id and type
		for _, id := range recordIDs {
			entryData, err := txn.Get(entries, uint64ToByteArray(id))
			if err != nil {
				if errors.Is(err, lmdb.NotFound) {
					continue // skip missing records
				}

				return fmt.Errorf("failed to fetch record: %w", err)
			}

			services.ProcessService.InfoLog(fmt.Sprintf("entryData: %v", entryData))

			// deserialize the record
			var record DNSRecord
			if err := unmarshalRecord(entryData, &record); err != nil {
				return fmt.Errorf("failed to deserialize record: %w", err)
			}

			services.ProcessService.InfoLog(fmt.Sprintf("record: %v", record))
			services.ProcessService.InfoLog(fmt.Sprintf("record type: %v", GetRecordType(record)))
			services.ProcessService.InfoLog(fmt.Sprintf("record type: %v", recordType))

			// check the record type
			if GetRecordType(record) == recordType {
				records = append(records, record)
			}
		}

		return nil
	})

	return records, err
}

func getSecondLevelDomain(domain string) (string, error) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid domain: %s", domain)
	}

	if len(parts) == 2 {
		return domain, nil
	}

	return strings.Join(parts[len(parts)-2:], "."), nil
}

func uint64ToByteArray(id uint64) []byte {
	idBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		idBytes[i] = byte(id >> uint(8*i))
	}

	return idBytes
}
