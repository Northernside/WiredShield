package cache

import (
	"sync"
	"time"
)

type Cache[V any] struct {
	value      V
	expiration int64
}

var (
	cache = make(map[string]any)
	mux   sync.RWMutex
)

func Store[V any](key string, value V, valid int64) {
	mux.Lock()
	defer mux.Unlock()

	c := &Cache[V]{
		value: value,
	}

	if valid > 0 {
		c.expiration = time.Now().Unix() + valid
	}

	cache[key] = c
}

func Delete(key string) {
	mux.Lock()
	defer mux.Unlock()
	delete(cache, key)
}

func Get[V any](key string) (V, bool) {
	mux.RLock()
	defer mux.RUnlock()

	a, found := cache[key]
	if !found {
		var zero V
		return zero, false
	}

	c, ok := a.(*Cache[V])
	if !ok {
		var zero V
		return zero, false
	}

	if c.expiration > 0 && time.Now().Unix() > c.expiration {
		delete(cache, key)
		var zero V
		return zero, false
	}

	return c.value, true
}
