package dns

import (
	"wired/modules/event"
	"wired/modules/types"
)

var (
	DNSEventChannel = make(chan event.Event)
	DNSEventBus     = event.NewEventBus("dns")
)

func GetUserDomains(userId string) []DomainData {
	ZonesMutex.RLock()
	defer ZonesMutex.RUnlock()

	var result []DomainData
	if list, ok := UserDomainIndexId[userId]; ok {
		for _, d := range list {
			result = append(result, *d)
		}
	}

	return result
}

func GetAllRecords() []*types.DNSRecord {
	var records []*types.DNSRecord

	for _, indexed := range ZoneIndexId {
		if indexed != nil && indexed.Record != nil {
			records = append(records, indexed.Record)
		}
	}

	return records
}
