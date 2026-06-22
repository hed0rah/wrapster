package output

import (
	"strings"
	"testing"
)

func TestStreamWriterBasic(t *testing.T) {
	w := NewStreamWriter(0, nil)
	w.Write([]byte("hello \x1b[31mworld\x1b[0m\n"))
	w.Write([]byte("line2\n"))
	w.Close()
	if got, want := w.String(), "hello world\nline2\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if w.Truncated() {
		t.Error("should not be truncated")
	}
}

// TestStreamWriterSplitEscape: an escape split across two writes is still
// stripped, proving the sink is streaming-safe across chunk boundaries.
func TestStreamWriterSplitEscape(t *testing.T) {
	w := NewStreamWriter(0, nil)
	w.Write([]byte("a\x1b["))
	w.Write([]byte("31mb"))
	w.Close()
	if got := w.String(); got != "ab" {
		t.Errorf("got %q, want %q", got, "ab")
	}
}

// TestStreamWriterCap: over-limit input is discarded but Write must NEVER
// short-write or error (a short write stalls io.Copy and hangs the child).
func TestStreamWriterCap(t *testing.T) {
	w := NewStreamWriter(10, nil)
	for i := 0; i < 100; i++ {
		n, err := w.Write([]byte("x"))
		if n != 1 || err != nil {
			t.Fatalf("Write returned (%d,%v), want (1,nil) -- must never short-write", n, err)
		}
	}
	w.Close()
	if !w.Truncated() {
		t.Error("expected Truncated")
	}
	if !strings.HasPrefix(w.String(), "xxxxxxxxxx") {
		t.Errorf("expected 10 retained bytes then a marker, got %q", w.String())
	}
	if !strings.Contains(w.String(), "truncated") {
		t.Error("expected a truncation marker")
	}
	if w.RawLen() != 100 {
		t.Errorf("RawLen = %d, want 100", w.RawLen())
	}
}

func TestStreamWriterChunks(t *testing.T) {
	var chunks []string
	w := NewStreamWriter(0, func(b []byte) { chunks = append(chunks, string(b)) })
	w.Write([]byte("foo"))
	w.Write([]byte("\x1b[0mbar")) // escape stripped, only "bar" forwarded
	w.Close()
	if got := strings.Join(chunks, ""); got != "foobar" {
		t.Errorf("forwarded chunks = %q, want %q", got, "foobar")
	}
}
