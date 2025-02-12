package caching

// web cache (html, css, js, jpg, jpeg, gif, png, mp4, webp, webm, mov, mkv, tiff, pdf, ico, mp3, apng, svg, aac, flac)

import (
	"sync"
	"time"
)

type CacheItem struct {
	Domain          string
	ResponseStatus  int
	ResponseHeaders map[string]string
	ResponseBody    []byte
	Expiration      int64
}

type Cache struct {
	items map[string]CacheItem
	mu    sync.RWMutex
}

func NewCache(domain string) *Cache {
	return &Cache{
		items: make(map[string]CacheItem),
	}
}

func (c *Cache) Set(domain, key string, responseStatus int, responseHeaders map[string]string, responseBody []byte, duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expiration := time.Now().Add(duration).Unix()
	c.items[key] = CacheItem{
		Domain:          domain,
		ResponseStatus:  responseStatus,
		ResponseHeaders: responseHeaders,
		ResponseBody:    responseBody,
		Expiration:      expiration,
	}
}

func (c *Cache) Get(key string) (int, map[string]string, []byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, found := c.items[key]
	if !found || time.Now().Unix() > item.Expiration {
		return 0, nil, nil, false
	}

	return item.ResponseStatus, item.ResponseHeaders, item.ResponseBody, true
}

func (c *Cache) DeleteExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().Unix()
	for key, item := range c.items {
		if now > item.Expiration {
			delete(c.items, key)
		}
	}
}

func (c *Cache) DeleteByDomain(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, item := range c.items {
		if item.Domain == domain {
			delete(c.items, key)
		}
	}
}

func (c *Cache) StartGC(interval time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			c.DeleteExpired()
		}
	}()
}
