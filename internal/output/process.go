package output

import (
	"fmt"
	"strings"
	"sync/atomic"
)

// Config controls output post-processing.
type Config struct {
	ANSIStrip bool           `yaml:"ansi_strip"`
	Truncate  TruncateConfig `yaml:"truncate"`
	Stats     bool           `yaml:"stats"`
}

// TruncateConfig controls head+tail truncation.
type TruncateConfig struct {
	Enabled   bool `yaml:"enabled"`
	MaxChars  int  `yaml:"max_chars"`
	HeadLines int  `yaml:"head_lines"`
	TailLines int  `yaml:"tail_lines"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		ANSIStrip: true,
		Truncate: TruncateConfig{
			Enabled:   true,
			MaxChars:  8192,
			HeadLines: 64,
			TailLines: 16,
		},
		Stats: true,
	}
}

// Stats tracks cumulative output processing metrics.
type Stats struct {
	Calls    int64
	RawBytes int64
	OutBytes int64
}

// Tracker accumulates stats across a session. Safe for concurrent use.
type Tracker struct {
	calls    atomic.Int64
	rawBytes atomic.Int64
	outBytes atomic.Int64
}

// Record adds a processing result to the tracker.
func (t *Tracker) Record(rawLen, outLen int) {
	t.calls.Add(1)
	t.rawBytes.Add(int64(rawLen))
	t.outBytes.Add(int64(outLen))
}

// Snapshot returns the current cumulative stats.
func (t *Tracker) Snapshot() Stats {
	return Stats{
		Calls:    t.calls.Load(),
		RawBytes: t.rawBytes.Load(),
		OutBytes: t.outBytes.Load(),
	}
}

// SavingsPct returns the percentage of bytes saved, or 0 if no data processed.
func (s Stats) SavingsPct() float64 {
	if s.RawBytes == 0 {
		return 0
	}
	return 100.0 * float64(s.RawBytes-s.OutBytes) / float64(s.RawBytes)
}

// StripANSI removes terminal escape sequences and unsafe control bytes from s,
// passing through printable UTF-8 plus newline and tab. It is a thin wrapper
// over Sanitize for the buffered output path; the streaming path uses the
// stateful Sanitizer directly. See sanitize.go for the threat model (OSC 52
// clipboard writes, OSC 8 phishing links, transcript-rewriting cursor moves).
func StripANSI(s string) string {
	return Sanitize(s)
}

// Process applies configured transformations to raw command output.
// Returns the processed string.
func Process(raw string, cfg Config) string {
	out := raw

	if cfg.ANSIStrip {
		out = StripANSI(out)
	}

	if cfg.Truncate.Enabled && len(out) > cfg.Truncate.MaxChars {
		out = truncate(out, cfg.Truncate)
	}

	return out
}

// truncate keeps head and tail lines, drops the middle. Walks the string
// byte-by-byte to find newline offsets so it never allocates a per-line
// substring header for the body it is about to discard.
func truncate(s string, cfg TruncateConfig) string {
	head := cfg.HeadLines
	tail := cfg.TailLines

	// Ring buffer holds byte offsets of the last (tail+1) newlines seen.
	// Sized to tail+1 so the oldest slot points to the newline that begins
	// the tail section once the ring is full.
	var ring []int
	if tail > 0 {
		ring = make([]int, tail+1)
	}
	ringIdx := 0
	ringFilled := 0

	newlineCount := 0
	headEnd := -1
	if head == 0 {
		headEnd = 0
	}

	for i := 0; i < len(s); i++ {
		if s[i] != '\n' {
			continue
		}
		newlineCount++
		if newlineCount == head {
			headEnd = i + 1
		}
		if tail > 0 {
			ring[ringIdx] = i
			ringIdx++
			if ringIdx == len(ring) {
				ringIdx = 0
			}
			if ringFilled < len(ring) {
				ringFilled++
			}
		}
	}

	// strings.Split(s, "\n") returns newlineCount+1 entries, so match that.
	lineCount := newlineCount + 1
	if lineCount <= head+tail || headEnd < 0 {
		return s
	}

	tailStart := len(s)
	if tail > 0 && ringFilled == len(ring) {
		// Oldest entry sits at ringIdx (next-write slot). Tail content
		// begins immediately after that newline.
		tailStart = ring[ringIdx] + 1
	}

	omitted := lineCount - head - tail
	headSlice := s[:headEnd]
	tailSlice := s[tailStart:]

	var b strings.Builder
	b.Grow(len(headSlice) + len(tailSlice) + 32)
	b.WriteString(headSlice)
	fmt.Fprintf(&b, "\n... %d lines omitted ...\n\n", omitted)
	b.WriteString(tailSlice)
	return b.String()
}
