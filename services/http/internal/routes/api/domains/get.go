package api_domains

import (
	"encoding/json"
	"net/http"
	"strings"
	wired_dns "wired/services/dns"
)

type DomainStats struct {
	Name     string `json:"name"`
	Records  int    `json:"records"`
	SSLCerts int    `json:"ssl_certs"`
}

func Get(w http.ResponseWriter, r *http.Request) {
	userId := r.Header.Get("Wired-User-Id")
	domainStats := make([]DomainStats, 0)

	domains := wired_dns.UserDomainIndexId[userId]
	for _, domain := range domains {
		records := wired_dns.DomainRecordIndexId[domain.Id]
		sslCerts := 0
		recordsCount := 0
		for i := range records {
			if records[i].Metadata.IPCompat {
				continue
			}

			if !records[i].Metadata.SSLInfo.IssuedAt.IsZero() {
				sslCerts++
			}

			recordsCount++
		}

		domainStats = append(domainStats, DomainStats{
			Name:     strings.TrimSuffix(domain.Domain, "."),
			Records:  recordsCount,
			SSLCerts: sslCerts,
		})
	}

	marshal, err := json.Marshal(domainStats)
	if err != nil {
		http.Error(w, "Failed to marshal domains", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(marshal)
}
