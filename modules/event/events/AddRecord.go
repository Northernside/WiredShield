package event_data

import (
	"wired/modules/types"
)

type AddRecordData struct {
	OwnerId  string
	DomainId string
	Record   *types.DNSRecord
}
