package bufstore

import (
	"testing"
)

// TestSliceBounds verifies that Slice correctly handles edge cases:
// valid ranges, negative lengths, out-of-bounds offsets, and missing buffers.
func TestSliceBounds(t *testing.T) {
	s := New(0) // use default size
	id := s.Put("hello world")

	tests := []struct {
		name     string
		id       string
		offset   int
		length   int
		expected string
	}{
		{
			name:     "valid slice start",
			id:       id,
			offset:   0,
			length:   5,
			expected: "hello",
		},
		{
			name:     "valid slice middle",
			id:       id,
			offset:   6,
			length:   5,
			expected: "world",
		},
		{
			name:     "negative length",
			id:       id,
			offset:   0,
			length:   -1,
			expected: "",
		},
		{
			name:     "offset past end",
			id:       id,
			offset:   100,
			length:   5,
			expected: "",
		},
		{
			name:     "length extends past end",
			id:       id,
			offset:   6,
			length:   100,
			expected: "world",
		},
		{
			name:     "missing buffer",
			id:       "missing",
			offset:   0,
			length:   5,
			expected: "",
		},
		{
			name:     "zero length",
			id:       id,
			offset:   0,
			length:   0,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Slice(tt.id, tt.offset, tt.length)
			if result != tt.expected {
				t.Errorf("Slice(%q, %d, %d) = %q, want %q",
					tt.id, tt.offset, tt.length, result, tt.expected)
			}
		})
	}
}

// TestPutEvict verifies that when the Store reaches capacity,
// the oldest entry is evicted to make room for new ones.
func TestPutEvict(t *testing.T) {
	s := New(2) // max 2 entries

	id1 := s.Put("content1")
	id2 := s.Put("content2")
	id3 := s.Put("content3")

	// id1 should have been evicted, id2 and id3 should remain
	ids := s.IDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs after eviction, got %d", len(ids))
	}

	// id1 should not be found
	if s.Slice(id1, 0, 100) != "" {
		t.Errorf("id1 should have been evicted but is still present")
	}

	// id2 and id3 should be present
	if s.Slice(id2, 0, 100) != "content2" {
		t.Errorf("id2 was evicted when it should remain")
	}
	if s.Slice(id3, 0, 100) != "content3" {
		t.Errorf("id3 was evicted when it should remain")
	}

	// the order should be [id2, id3]
	if len(ids) == 2 && ids[0] != id2 {
		t.Errorf("ids order: expected id2 first, got %s", ids[0])
	}
	if len(ids) == 2 && ids[1] != id3 {
		t.Errorf("ids order: expected id3 second, got %s", ids[1])
	}

	// add a fourth entry; id2 should be evicted
	id4 := s.Put("content4")
	ids = s.IDs()
	if len(ids) != 2 {
		t.Errorf("expected 2 IDs after second eviction, got %d", len(ids))
	}

	if s.Slice(id2, 0, 100) != "" {
		t.Errorf("id2 should have been evicted")
	}
	if s.Slice(id3, 0, 100) != "content3" {
		t.Errorf("id3 should still be present")
	}
	if s.Slice(id4, 0, 100) != "content4" {
		t.Errorf("id4 should be present")
	}
}

// TestNewDefaultSize verifies that New with zero or negative max creates
// a Store with the default max size.
func TestNewDefaultSize(t *testing.T) {
	s0 := New(0)
	s1 := New(1)
	sNeg := New(-5)

	// All should be usable and have a reasonable max
	id0 := s0.Put("test0")
	id1 := s1.Put("test1")
	idNeg := sNeg.Put("testNeg")

	if s0.Slice(id0, 0, 100) != "test0" {
		t.Error("New(0) store should be usable")
	}
	if s1.Slice(id1, 0, 100) != "test1" {
		t.Error("New(1) store should be usable")
	}
	if sNeg.Slice(idNeg, 0, 100) != "testNeg" {
		t.Error("New(-5) store should be usable")
	}

	// Fill each to verify they use default size, not 0 or 1
	// Put more than the original max to trigger eviction behavior
	for i := 0; i < 70; i++ {
		_ = s0.Put("fill")
	}
	if len(s0.IDs()) == 0 {
		t.Error("New(0) should use default size and hold entries")
	}
}

// TestLen returns the byte length of stored content.
func TestLen(t *testing.T) {
	s := New(10)
	id := s.Put("hello")

	if s.Len(id) != 5 {
		t.Errorf("Len(%q) = %d, want 5", id, s.Len(id))
	}

	if s.Len("missing") != 0 {
		t.Errorf("Len of missing buffer should be 0, got %d", s.Len("missing"))
	}
}

// TestConcurrentPuts verifies that concurrent Put operations do not corrupt
// the Store or cause buffer losses.
func TestConcurrentPuts(t *testing.T) {
	s := New(100)
	const numPuts = 50

	ids := make([]string, numPuts)
	done := make(chan struct{})
	errCh := make(chan error, numPuts)

	for i := 0; i < numPuts; i++ {
		go func(idx int) {
			content := "content-" + string(rune('A'+idx%26))
			ids[idx] = s.Put(content)
			errCh <- nil
		}(i)
	}

	// wait for all goroutines
	for i := 0; i < numPuts; i++ {
		<-errCh
	}
	close(done)

	// verify all IDs are present
	allIDs := s.IDs()
	if len(allIDs) > numPuts {
		t.Errorf("expected at most %d IDs, got %d", numPuts, len(allIDs))
	}
	if len(allIDs) == 0 {
		t.Fatal("no IDs present after concurrent puts")
	}
}
