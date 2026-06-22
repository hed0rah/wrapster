package output

import "bytes"

// DefaultStreamLimit caps retained/forwarded output per stream.
const DefaultStreamLimit = 1 << 20 // 1 MiB

// StreamWriter is the streaming output sink. os/exec's copy goroutine writes
// child output into it as the process runs, so output is never held to
// completion. Each chunk is sanitized (via the chunk-safe Sanitizer), capped at
// a byte limit (excess discarded, but Write always reports the full length so
// the child's pipe never stalls), optionally forwarded live to onChunk, and
// accumulated into a capped buffer that becomes the final result string.
//
// A StreamWriter is single-writer: os/exec drains stdout and stderr on separate
// goroutines, so give each stream its own StreamWriter (no shared state, no
// lock). The onChunk callback, if set, may be invoked from either stream's
// goroutine, so it must be safe for concurrent use and must not block.
type StreamWriter struct {
	san     Sanitizer
	limit   int
	written int
	rawIn   int
	buf     bytes.Buffer
	onChunk func([]byte)
	capped  bool
}

// NewStreamWriter returns a sink with the given byte limit (<=0 uses the
// default) and an optional live-chunk callback (nil to only accumulate).
func NewStreamWriter(limit int, onChunk func([]byte)) *StreamWriter {
	if limit <= 0 {
		limit = DefaultStreamLimit
	}
	return &StreamWriter{limit: limit, onChunk: onChunk}
}

// Write sanitizes and forwards a chunk. It always returns (len(p), nil): the
// child must never block on a full pipe, so over-limit bytes are drained and
// discarded rather than short-written.
func (w *StreamWriter) Write(p []byte) (int, error) {
	w.rawIn += len(p)
	if clean := w.san.Feed(p); len(clean) > 0 {
		w.forward(clean)
	}
	return len(p), nil
}

// Close flushes any bytes the sanitizer held back at end of stream. Call it
// after the process exits (cmd.Wait has returned).
func (w *StreamWriter) Close() {
	if tail := w.san.Flush(); len(tail) > 0 {
		w.forward(tail)
	}
}

func (w *StreamWriter) forward(clean []byte) {
	remaining := w.limit - w.written
	if remaining <= 0 {
		w.markTruncated()
		return
	}
	if len(clean) > remaining {
		clean = clean[:remaining]
	}
	w.written += len(clean)
	w.buf.Write(clean)
	if w.onChunk != nil {
		w.onChunk(clean)
	}
	if w.written >= w.limit {
		w.markTruncated()
	}
}

func (w *StreamWriter) markTruncated() {
	if w.capped {
		return
	}
	w.capped = true
	marker := []byte("\n[output truncated: byte limit reached]\n")
	w.buf.Write(marker)
	if w.onChunk != nil {
		w.onChunk(marker)
	}
}

// String returns the accumulated, sanitized, byte-capped output.
func (w *StreamWriter) String() string { return w.buf.String() }

// RawLen is the number of raw bytes received from the child (for stats).
func (w *StreamWriter) RawLen() int { return w.rawIn }

// Truncated reports whether the byte limit was reached.
func (w *StreamWriter) Truncated() bool { return w.capped }
