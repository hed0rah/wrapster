package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Entry represents a single audit log record.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	Host       string    `json:"host"`
	Command    string    `json:"command"`
	Allowed    bool      `json:"allowed"`
	Reason     string    `json:"reason"`
	ExitCode   *int      `json:"exit_code,omitempty"`
	TimedOut   bool      `json:"timed_out,omitempty"`
	OutputHash string    `json:"output_hash,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
}

// Logger writes structured audit entries to a file or stream.
type Logger struct {
	mu  sync.Mutex
	w   io.Writer
	enc *json.Encoder
}

// NewLogger creates an audit logger writing to the given path.
// Pass "-" or "" for stderr.
func NewLogger(path string) (*Logger, error) {
	var w io.Writer

	if path == "" || path == "-" {
		w = os.Stderr
	} else {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("opening audit log: %w", err)
		}
		w = f
	}

	return &Logger{
		w:   w,
		enc: json.NewEncoder(w),
	}, nil
}

// Log writes an audit entry.
func (l *Logger) Log(e Entry) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// best-effort: audit log write failure shouldn't kill the process,
	// but we print to stderr so it's visible.
	if err := l.enc.Encode(e); err != nil {
		fmt.Fprintf(os.Stderr, "audit: failed to write entry: %v\n", err)
	}
}

// HashOutput returns a hex-encoded SHA-256 of the output for the audit trail.
func HashOutput(stdout, stderr string) string {
	h := sha256.New()
	h.Write([]byte(stdout))
	h.Write([]byte{0}) // separator
	h.Write([]byte(stderr))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Close closes the underlying writer if it implements io.Closer.
func (l *Logger) Close() error {
	if c, ok := l.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
