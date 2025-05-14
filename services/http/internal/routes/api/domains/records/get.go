package api_domains_records

import (
	"encoding/json"
	"net/http"
	"strings"
	"wired/modules/types"

	wired_dns "wired/services/dns"

	"github.com/miekg/dns"
)

func Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	domain := dns.Fqdn(strings.ToLower(r.URL.Query().Get("domain")))
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Domain is required"}`))
		return
	}

	domainData := wired_dns.DomainDataIndexName[domain]
	if domainData == nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Domain not found"}`))
		return
	}

	records := wired_dns.DomainRecordIndexId[domainData.Id]
	filteredRecords := make([]*types.DNSRecord, 0)
	for _, record := range records {
		if !record.Metadata.IPCompat {
			filteredRecords = append(filteredRecords, record)
		}
	}

	marshaledRecords, err := json.Marshal(filteredRecords)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Failed to marshal records", "details": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(marshaledRecords)
}
