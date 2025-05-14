package dns

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"wired/modules/env"
	"wired/modules/event"
	event_data "wired/modules/event/events"
	"wired/modules/logger"
	"wired/modules/snowflake"
	"wired/modules/types"

	"github.com/miekg/dns"
)

var (
	sf *snowflake.Snowflake
)

func init() {
	env.LoadEnvFile()
	machineIDStr := env.GetEnv("SNOWFLAKE_MACHINE_ID", "0")
	machineID, err := strconv.ParseInt(machineIDStr, 10, 64)
	if err != nil {
		logger.Fatal("Invalid SNOWFLAKE_MACHINE_ID: ", err)
	}

	sf, err = snowflake.NewSnowflake(machineID)
	if err != nil {
		logger.Fatal("Error creating Snowflake instance: ", err)
	}
}

func CreateDomain(user *types.User, domainName string) error {
	domainData := &DomainData{
		Id:     strconv.Itoa(int(sf.GenerateID())),
		Domain: domainName,
		Owner:  user.Id,
	}

	DomainDataIndexId[domainData.Id] = domainData
	DomainDataIndexName[domainName] = domainData
	UserDomainIndexId[user.Id] = append(UserDomainIndexId[user.Id], domainData)
	EnsureDomainIndexes(*domainData)

	mutex, ok := ZoneFileMutexes[domainName]
	if !ok {
		mutex = &sync.Mutex{}
		ZoneFileMutexes[domainName] = mutex
	}

	mutex.Lock()
	defer mutex.Unlock()

	for _, ns := range []string{"woof", "meow"} {
		InsertRecord(domainData, &types.DNSRecord{
			RR: &dns.NS{
				Hdr: dns.RR_Header{Name: dns.Fqdn(domainName), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  fmt.Sprintf("%s.ns.wired.rip", ns),
			},
			Metadata: types.RecordMetadata{
				Id:        strconv.Itoa(int(sf.GenerateID())),
				Protected: false, Geo: false, IPCompat: false,
				SSLInfo: types.SSLInfo{},
			},
		})
	}

	return WriteZoneFile(domainName)
}

func GetDomains(user *types.User) []DomainData {
	return GetUserDomains(user.Id)
}

func GetRecordsByDomain(user *types.User, domainId string) []*types.DNSRecord {
	return DomainRecordIndexId[domainId]
}

func CreateRecord(user *types.User, domainId string, record *types.DNSRecord) (string, error) {
	recordId := strconv.Itoa(int(sf.GenerateID()))
	domainData, ok := DomainDataIndexId[domainId]
	if !ok || domainData.Owner != user.Id {
		return "", fmt.Errorf("domain not found or not owned by user")
	}

	mutex := ZoneFileMutexes[domainData.Domain]
	mutex.Lock()
	defer mutex.Unlock()

	record.Metadata.Id = recordId

	zonefilePath := filepath.Join("zonefiles", domainData.Domain+".txt")
	zoneFile, err := os.OpenFile(zonefilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err == nil {
		line := record.RR.String()
		if jsonMeta, err := json.Marshal(record.Metadata); err == nil {
			line += "; " + string(jsonMeta)
		}

		_, err = zoneFile.WriteString(line + "\n")
		if err != nil {
			return "", err
		}

		err = zoneFile.Close()
		if err != nil {
			return "", err
		}
	}

	InsertRecord(domainData, record)
	DNSEventBus.Pub(event.Event{
		Type: event.Event_AddRecord,
		Data: event_data.AddRecordData{OwnerId: user.Id, DomainId: domainId, Record: record},
	})

	return recordId, nil
}

func DeleteRecord(user *types.User, recordId string) error {
	indexed := ZoneIndexId[recordId]
	if indexed == nil {
		return fmt.Errorf("record not found")
	}

	mutex, ok := ZoneFileMutexes[indexed.Domain]
	if ok {
		mutex.Lock()
		defer mutex.Unlock()
	}

	delete(ZoneIndexId, recordId)

	records := DomainRecordIndexId[indexed.Domain]
	newRecords := make([]*types.DNSRecord, 0, len(records))
	for _, r := range records {
		if r.Metadata.Id != recordId {
			newRecords = append(newRecords, r)
		}
	}

	DomainRecordIndexId[indexed.Domain] = newRecords

	trie := Zones[indexed.Zone]
	if trie != nil {
		PruneTrie(trie, indexed.Record.RR.Header().Name, recordId)
	}

	DNSEventBus.Pub(event.Event{
		Type: event.Event_RemoveRecord,
		Data: event_data.RemoveRecordData{OwnerId: user.Id, DomainId: DomainDataIndexName[indexed.Domain].Id, Id: recordId},
	})

	return RemoveRecordFromZoneFile(indexed.Zone, recordId)
}
