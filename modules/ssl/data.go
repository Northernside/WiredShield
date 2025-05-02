package ssl

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"sort"
	"strings"
)

type SSLClient struct {
	Key          *rsa.PrivateKey `json:"key"`
	DirectoryURL string          `json:"directory_url"`
}

func (s *SSLClient) saveKey() {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal key: %v", err)
	}

	err = os.WriteFile("ssl_client_key.json", data, 0600)
	if err != nil {
		log.Fatalf("Failed to save key to file: %v", err)
	}
}

func (s *SSLClient) loadKey() {
	data, err := os.ReadFile("ssl_client_key.json")
	if err != nil {
		log.Fatalf("Failed to read key from file: %v", err)
	}

	err = json.Unmarshal(data, s)
	if err != nil {
		log.Fatalf("Failed to unmarshal key: %v", err)
	}
}

func generateBatchID(domains []string) string {
	sort.Strings(domains)
	h := sha256.New()
	h.Write([]byte(strings.Join(domains, ",")))
	return hex.EncodeToString(h.Sum(nil))[:8]
}
