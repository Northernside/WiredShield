package db

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bmatsuo/lmdb-go/lmdb"
)

func UpdateRecord(recordType, domain string, record interface{}) error {
	err := env.Update(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		var generalDb lmdb.DBI
		generalDb, err = txn.OpenDBI("wiredshield_general", lmdb.Create)
		if err != nil {
			return fmt.Errorf("failed to open general db: %v", err)
		}

		var db lmdb.DBI
		db, err = txn.OpenDBI("wireddns_"+secondLevelDomain, 0)
		if err != nil {
			if strings.Contains(err.Error(), "MDB_NOTFOUND") {
				// create new db
				db, err = txn.OpenDBI("wireddns_"+secondLevelDomain, lmdb.Create)
				if err != nil {
					return fmt.Errorf("failed to create db: %v", err)
				}

				domainsKey := []byte("dns_domains")
				existingDomains := []string{}

				value, err := txn.Get(generalDb, domainsKey)
				if err != nil && !strings.Contains(err.Error(), "MDB_NOTFOUND") {
					return fmt.Errorf("failed to get domains list: %v", err)
				}

				if value != nil {
					if err := json.Unmarshal(value, &existingDomains); err != nil {
						return fmt.Errorf("failed to unmarshal domains list: %v", err)
					}
				}

				// check if domain already exists
				exists := false
				for _, d := range existingDomains {
					if d == secondLevelDomain {
						exists = true
						break
					}
				}

				if !exists {
					existingDomains = append(existingDomains, secondLevelDomain)
					serialized, err := json.Marshal(existingDomains)
					if err != nil {
						return fmt.Errorf("failed to serialize domains list: %v", err)
					}

					if err := txn.Put(generalDb, domainsKey, serialized, 0); err != nil {
						return fmt.Errorf("failed to update domains list: %v", err)
					}
				}
			} else {
				return fmt.Errorf("failed to open db: %v", err)
			}
		}

		key := []byte(recordType + ":" + domain)
		value, err := txn.Get(db, key)

		if err != nil {
			if !strings.Contains(err.Error(), "MDB_NOTFOUND") {
				return fmt.Errorf("failed to get record: %v", err)
			}

			// create new record
			records := []interface{}{record}
			serialized, err := json.Marshal(records)
			if err != nil {
				return fmt.Errorf("failed to serialize record: %v", err)
			}

			if err := txn.Put(db, key, serialized, 0); err != nil {
				return fmt.Errorf("failed to update record: %v", err)
			}

			return nil
		}

		if value != nil { // append to array
			var records []interface{}
			if err := json.Unmarshal(value, &records); err != nil {
				return fmt.Errorf("failed to unmarshal existing records: %v", err)
			}

			records = append(records, record)
			serialized, err := json.Marshal(records)
			if err != nil {
				return fmt.Errorf("failed to serialize updated records: %v", err)
			}

			if err := txn.Put(db, key, serialized, 0); err != nil {
				return fmt.Errorf("failed to update records: %v", err)
			}

			return nil
		}

		return nil
	})

	return err
}

func DeleteRecord(id uint64) error {
	err := env.Update(func(txn *lmdb.Txn) error {
		db, err := txn.OpenDBI("wiredshield_general", 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		cursor, err := txn.OpenCursor(db)
		if err != nil {
			return fmt.Errorf("failed to open cursor: %v", err)
		}
		defer cursor.Close()

		for {
			key, value, err := cursor.Get(nil, nil, lmdb.Next)
			if err != nil {
				if strings.Contains(err.Error(), "MDB_NOTFOUND") {
					break
				}

				return fmt.Errorf("failed to get record: %v", err)
			}

			var records []interface{}
			if err := json.Unmarshal(value, &records); err != nil {
				return fmt.Errorf("failed to unmarshal records: %v", err)
			}

			for i, record := range records {
				switch r := record.(type) {
				case ARecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case AAAARecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case CNAMERecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case MXRecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case NSRecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case SOARecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case SRVRecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case TXTRecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				case CAARecord:
					if r.ID == id {
						records = append(records[:i], records[i+1:]...)
						break
					}
				default:
					return fmt.Errorf("unknown record type")
				}
			}

			serialized, err := json.Marshal(records)
			if err != nil {
				return fmt.Errorf("failed to serialize updated records: %v", err)
			}

			if err := txn.Put(db, key, serialized, 0); err != nil {
				return fmt.Errorf("failed to update records: %v", err)
			}

			return nil
		}

		return nil
	})

	return err
}

func GetRecords(recordType, domain string) ([]interface{}, error) {
	var records []interface{}
	err := env.View(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
		if err != nil {
			return fmt.Errorf("failed to get second level domain: %v", err)
		}

		db, err := txn.OpenDBI("wireddns_"+secondLevelDomain, 0)
		if err != nil {
			return fmt.Errorf("failed to open db: %v", err)
		}

		key := []byte(recordType + ":" + domain)
		value, err := txn.Get(db, key)
		if err != nil {
			if strings.Contains(err.Error(), "MDB_NOTFOUND") {
				return nil
			}

			return fmt.Errorf("failed to get record: %v", err)
		}

		if value != nil {
			var rawRecords []json.RawMessage
			if err := json.Unmarshal(value, &rawRecords); err != nil {
				return fmt.Errorf("failed to unmarshal records: %v", err)
			}

			for _, raw := range rawRecords {
				var record interface{}
				switch recordType {
				case string(A):
					var aRecord ARecord
					if err := json.Unmarshal(raw, &aRecord); err != nil {
						return fmt.Errorf("failed to unmarshal A record: %v", err)
					}

					record = aRecord
				case string(AAAA):
					var aaaaRecord AAAARecord
					if err := json.Unmarshal(raw, &aaaaRecord); err != nil {
						return fmt.Errorf("failed to unmarshal AAAA record: %v", err)
					}

					record = aaaaRecord
				case string(SRV):
					var srvRecord SRVRecord
					if err := json.Unmarshal(raw, &srvRecord); err != nil {
						return fmt.Errorf("failed to unmarshal SRV record: %v", err)
					}

					record = srvRecord
				case string(CNAME):
					var cnameRecord CNAMERecord
					if err := json.Unmarshal(raw, &cnameRecord); err != nil {
						return fmt.Errorf("failed to unmarshal CNAME record: %v", err)
					}

					record = cnameRecord
				case string(SOA):
					var soaRecord SOARecord
					if err := json.Unmarshal(raw, &soaRecord); err != nil {
						return fmt.Errorf("failed to unmarshal SOA record: %v", err)
					}
					record = soaRecord
				case string(TXT):
					var txtRecord TXTRecord
					if err := json.Unmarshal(raw, &txtRecord); err != nil {
						return fmt.Errorf("failed to unmarshal TXT record: %v", err)
					}
					record = txtRecord
				case string(NS):
					var nsRecord NSRecord
					if err := json.Unmarshal(raw, &nsRecord); err != nil {
						return fmt.Errorf("failed to unmarshal NS record: %v", err)
					}
					record = nsRecord
				case string(MX):
					var mxRecord MXRecord
					if err := json.Unmarshal(raw, &mxRecord); err != nil {
						return fmt.Errorf("failed to unmarshal MX record: %v", err)
					}
					record = mxRecord
				case string(CAA):
					var caaRecord CAARecord
					if err := json.Unmarshal(raw, &caaRecord); err != nil {
						return fmt.Errorf("failed to unmarshal CAA record: %v", err)
					}
					record = caaRecord
				default:
					return fmt.Errorf("unsupported record type: %v", recordType)
				}
				records = append(records, record)
			}
		}

		return nil
	})

	return records, err
}

func GetAllRecords(domain string) ([]interface{}, error) {
	var records []interface{}
	err := env.View(func(txn *lmdb.Txn) error {
		secondLevelDomain, err := getSecondLevelDomain(domain)
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
			key, value, err := cursor.Get(nil, nil, lmdb.Next)
			if err != nil {
				if strings.Contains(err.Error(), "MDB_NOTFOUND") {
					break
				}

				return fmt.Errorf("failed to get record: %v", err)
			}

			recordType := strings.Split(string(key), ":")[0]
			switch recordType {
			case "A":
				var _records []ARecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal A records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "AAAA":
				var _records []AAAARecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal AAAA records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "CNAME":
				var _records []CNAMERecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal CNAME records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "MX":
				var _records []MXRecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal MX records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "NS":
				var _records []NSRecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal NS records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "SOA":
				var _records []SOARecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal SOA records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "SRV":
				var _records []SRVRecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal SRV records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "TXT":
				var _records []TXTRecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal TXT records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			case "CAA":
				var _records []CAARecord
				if err := json.Unmarshal(value, &_records); err != nil {
					return fmt.Errorf("failed to unmarshal CAA records: %v", err)
				}

				for _, r := range _records {
					records = append(records, r)
				}
			default:
				return fmt.Errorf("unknown record type: %s", recordType)
			}
		}

		return nil
	})

	return records, err
}

func GetAllDomains() ([]string, error) {
	var domains []string
	err := env.View(func(txn *lmdb.Txn) error {
		generalDb, err := txn.OpenDBI("wiredshield_general", 0)
		if err != nil {
			return fmt.Errorf("failed to open general db: %v", err)
		}

		domainsKey := []byte("dns_domains")
		value, err := txn.Get(generalDb, domainsKey)
		if err != nil {
			if strings.Contains(err.Error(), "MDB_NOTFOUND") {
				return nil
			}

			return fmt.Errorf("failed to get domains list: %v", err)
		}

		if value != nil {
			if err := json.Unmarshal(value, &domains); err != nil {
				return fmt.Errorf("failed to unmarshal domains list: %v", err)
			}
		}

		return nil
	})

	return domains, err
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
