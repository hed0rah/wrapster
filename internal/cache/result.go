// Package cache provides a session-scoped result cache for idempotent tool calls.
// Commands whose (host, command) key matches a recent cached entry return a
// lightweight {cached: true, hash: "..."} response instead of re-executing.
package cache

import (
	"sync"
	"time"
)

// Entry holds a cached command result.
type Entry struct {
	Hash      string    // sha256 of stdout+stderr (hex)
	Stdout    string
	Stderr    string
	ExitCode  int
	CachedAt  time.Time
}

// ResultCache is a session-scoped, thread-safe LRU-ish cache for command results.
// Keys are (host, command) strings. Entries expire after TTL.
type ResultCache struct {
	mu      sync.Mutex
	entries map[string]*Entry
	ttl     time.Duration
}

// New returns a ResultCache with the given TTL.
func New(ttl time.Duration) *ResultCache {
	return &ResultCache{
		entries: make(map[string]*Entry),
		ttl:     ttl,
	}
}

func key(host, command string) string {
	return host + "\x00" + command
}

// Get returns the cached entry if present and not expired. Returns nil otherwise.
func (c *ResultCache) Get(host, command string) *Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key(host, command)]
	if !ok {
		return nil
	}
	if time.Since(e.CachedAt) > c.ttl {
		delete(c.entries, key(host, command))
		return nil
	}
	return e
}

// Put stores a result. Evicts expired entries opportunistically.
func (c *ResultCache) Put(host, command string, e *Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e.CachedAt = time.Now()
	c.entries[key(host, command)] = e
	// opportunistic eviction: remove entries older than TTL
	for k, v := range c.entries {
		if time.Since(v.CachedAt) > c.ttl {
			delete(c.entries, k)
		}
	}
}

// Invalidate removes a specific entry.
func (c *ResultCache) Invalidate(host, command string) {
	c.mu.Lock()
	delete(c.entries, key(host, command))
	c.mu.Unlock()
}

// Flush removes all entries.
func (c *ResultCache) Flush() {
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.mu.Unlock()
}
