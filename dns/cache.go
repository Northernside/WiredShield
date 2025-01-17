package wireddns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	cache       = make(map[string]dnsCacheEntry)
	geoLocCache = make(map[string]geoLocCacheEntry)
	cacheMux    sync.RWMutex
)

type dnsCacheEntry struct {
	records    []dns.RR
	expiration time.Time
}

type geoLocCacheEntry struct {
	country    string
	expiration time.Time
}

func updateCache(cacheKey string, records []dns.RR) {
	cacheMux.Lock()
	defer cacheMux.Unlock()

	cache[cacheKey] = dnsCacheEntry{
		records:    records,
		expiration: time.Now().Add(1 * time.Hour),
	}
}

func getCache(cacheKey string) ([]dns.RR, bool) {
	cacheMux.RLock()
	defer cacheMux.RUnlock()

	entry, found := cache[cacheKey]
	if found && time.Now().Before(entry.expiration) {
		return entry.records, true
	}

	return nil, false
}
