package ssl

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"wired/modules/logger"
)

type SSLClient struct {
	Key          *rsa.PrivateKey `json:"key"`
	DirectoryURL string          `json:"directory_url"`
}

func (s *SSLClient) saveKey() {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		logger.Fatal("Failed to marshal key: ", err)
	}

	err = os.WriteFile("ssl_client_key.json", data, 0600)
	if err != nil {
		logger.Fatal("Failed to save key to file: ", err)
	}
}

func (s *SSLClient) loadKey() {
	data, err := os.ReadFile("ssl_client_key.json")
	if err != nil {
		logger.Fatal("Failed to read key from file: ", err)
	}

	err = json.Unmarshal(data, s)
	if err != nil {
		logger.Fatal("Failed to unmarshal key: ", err)
	}
}

func generateBatchID(domains []string) string {
	sort.Strings(domains)
	h := sha256.New()
	h.Write([]byte(strings.Join(domains, ",")))
	return hex.EncodeToString(h.Sum(nil))[:8]
}
