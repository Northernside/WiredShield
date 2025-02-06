package db

import (
	"sync"
	"time"
)

var (
	cache      = make(map[string]cacheEntry)
	cacheMutex sync.Mutex
)

type cacheEntry struct {
	entries any
	expiry  time.Time
}
