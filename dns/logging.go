package wireddns

import (
	"fmt"
	"time"
	"wiredshield/modules/logging"
)

func newLog() *logging.DNSRequestLog {
	return &logging.DNSRequestLog{
		QueryTime:     time.Now().Unix(),
		ClientIP:      "",
		QueryName:     "",
		QueryType:     "",
		QueryClass:    "",
		ResponseCode:  "",
		ResponseTime:  0,
		IsSuccessful:  false,
		ClientCountry: "",
	}
}

func logDNSRequest(log *logging.DNSRequestLog) {
	logging.DNSLogsChannel <- log
}

func processRequestLogs() {
	logWorkers := 512
	for i := 0; i < logWorkers; i++ {
		go func() {
			for log := range logging.DNSLogsChannel {
				logs := log.CollectAdditionalLogs()
				if len(logs) > 0 {
					if err := log.BatchInsert(logs); err != nil {
						service.ErrorLog(fmt.Sprintf("Failed to insert logs: %v", err))
					}
				}
			}
		}()
	}
}
