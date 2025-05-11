package event_data

import (
	"wired/modules/types"
)

type AddRecordData struct {
	OwnerID string
	Record  *types.DNSRecord
}
