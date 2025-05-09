package api_domains

import (
	"encoding/json"
	"net/http"
	"strings"
	"wired/services/dns"
)

type DomainStats struct {
	Name     string `json:"name"`
	Records  int    `json:"records"`
	SSLCerts int    `json:"ssl_certs"`
}

func Get(w http.ResponseWriter, r *http.Request) {
	records := dns.ListRecords()

	domainStats := map[string]*DomainStats{}
	for zone, recordList := range records {
		parts := strings.Split(strings.TrimSuffix(zone, "."), ".")
		if len(parts) < 2 {
			continue
		}

		sld := strings.Join(parts[len(parts)-2:], ".")
		if _, exists := domainStats[sld]; !exists {
			domainStats[sld] = &DomainStats{Name: sld}
		}

		recordAmount := len(recordList)
		for _, record := range recordList {
			if record.Metadata.Artificial {
				recordAmount--
				continue
			}

			if record.Metadata.Protected {
				domainStats[sld].SSLCerts++
			}
		}

		domainStats[sld].Records += recordAmount
	}

	var domains []DomainStats
	for _, stats := range domainStats {
		domains = append(domains, *stats)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	marshal, err := json.Marshal(domains)
	if err != nil {
		http.Error(w, "Failed to marshal domains", http.StatusInternalServerError)
		return
	}

	w.Write(marshal)
}
