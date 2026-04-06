package output

import (
	"fmt"
	"regexp"
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
	Calls     int64
	RawBytes  int64
	OutBytes  int64
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

// ansiPattern matches ANSI escape sequences: CSI sequences, OSC sequences,
// and simple two-byte escapes.
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\x1b[=><78HMND]`)

// Process applies configured transformations to raw command output.
// Returns the processed string.
func Process(raw string, cfg Config) string {
	out := raw

	if cfg.ANSIStrip {
		out = ansiPattern.ReplaceAllString(out, "")
	}

	if cfg.Truncate.Enabled && len(out) > cfg.Truncate.MaxChars {
		out = truncate(out, cfg.Truncate)
	}

	return out
}

// truncate keeps head and tail lines, drops the middle.
func truncate(s string, cfg TruncateConfig) string {
	lines := strings.Split(s, "\n")
	total := len(lines)

	head := cfg.HeadLines
	tail := cfg.TailLines

	// if the line count fits within head+tail, no truncation needed
	if total <= head+tail {
		return s
	}

	var b strings.Builder

	// write head
	for i := 0; i < head && i < total; i++ {
		b.WriteString(lines[i])
		b.WriteByte('\n')
	}

	omitted := total - head - tail
	b.WriteString(fmt.Sprintf("\n... %d lines omitted ...\n\n", omitted))

	// write tail
	for i := total - tail; i < total; i++ {
		b.WriteString(lines[i])
		if i < total-1 {
			b.WriteByte('\n')
		}
	}

	return b.String()
}
