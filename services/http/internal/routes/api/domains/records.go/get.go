package api_domains_records

import (
	"encoding/json"
	"net/http"
	"strings"
	"wired/modules/pages"
	"wired/services/dns"
)

func Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	rZone := strings.ToLower(r.URL.Query().Get("domain"))
	if rZone == "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		w.Write(pages.ErrorPages[700].Rerender(404, []string{"Domain not found", "Please provide a domain name in the URL."}))
		return
	}

	records, err := dns.ListRecordsByZone(rZone)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Failed to retrieve records", "details": "` + err.Error() + `"}`))
		return
	}

	marshaledRecords, err := json.Marshal(records)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Failed to marshal records", "details": "` + err.Error() + `"}`))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(marshaledRecords)
}
