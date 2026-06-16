// Package bufstore provides an in-memory ring buffer for full command output.
// When output is truncated before being sent to the model, the pre-truncation
// version is stored here and addressable via a short handle (buf_id).
// The model can page through the full content via the buf:// resource or grep_output.
package bufstore

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const defaultMaxEntries = 64 // max concurrent buffers; oldest evicted when full

// Store is a session-scoped ring buffer of command outputs keyed by buf_id.
type Store struct {
	mu         sync.Mutex
	entries    map[string]string // buf_id -> full content
	order      []string          // insertion order for eviction
	maxEntries int
}

// New creates a Store with the given max entry count. If max <= 0, uses 64.
func New(max int) *Store {
	if max <= 0 {
		max = defaultMaxEntries
	}
	return &Store{
		entries:    make(map[string]string),
		maxEntries: max,
	}
}

// Put stores content and returns a new buf_id.
func (s *Store) Put(content string) string {
	id := newID()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.order) >= s.maxEntries {
		// evict oldest
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, oldest)
	}
	s.entries[id] = content
	s.order = append(s.order, id)
	return id
}

// IDs returns all active buffer IDs in insertion order.
func (s *Store) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Len returns the byte length of a buffer. Returns 0 if not found.
func (s *Store) Len(id string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries[id])
}

// Slice returns a byte range of the content. offset and length are in bytes.
// Returns empty string if buf_id not found.
func (s *Store) Slice(id string, offset, length int) string {
	s.mu.Lock()
	content, ok := s.entries[id]
	s.mu.Unlock()
	if !ok {
		return ""
	}
	if offset < 0 {
		offset = 0
	}
	if length < 0 || offset >= len(content) {
		return ""
	}
	end := offset + length
	if end < offset || end > len(content) { // integer overflow or past end
		end = len(content)
	}
	return content[offset:end]
}

// Grep returns lines matching the given regex pattern.
// Returns at most maxLines lines (0 = no limit).
func (s *Store) Grep(id, pattern string, maxLines int) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("bad pattern: %w", err)
	}

	s.mu.Lock()
	content, ok := s.entries[id]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("buf_id %q not found", id)
	}

	var matches []string
	for _, line := range strings.Split(content, "\n") {
		if re.MatchString(line) {
			matches = append(matches, line)
			if maxLines > 0 && len(matches) >= maxLines {
				break
			}
		}
	}
	return matches, nil
}

func newID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic and essentially never happens on
		// supported platforms; a zero-value ID would alias buffers, so fail hard.
		panic("bufstore: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
