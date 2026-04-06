package output

import (
	"strings"
	"testing"
)

func TestANSIStrip(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain text", "hello world", "hello world"},
		{"color code", "\x1b[31mred\x1b[0m", "red"},
		{"bold", "\x1b[1mbold\x1b[0m text", "bold text"},
		{"complex", "\x1b[38;5;196mhi\x1b[0m", "hi"},
		{"cursor move", "\x1b[2J\x1b[H", ""},
	}

	cfg := Config{ANSIStrip: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Process(tt.input, cfg)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	// build 200 lines
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, "line content here")
	}
	input := strings.Join(lines, "\n")

	cfg := Config{
		ANSIStrip: false,
		Truncate: TruncateConfig{
			Enabled:   true,
			MaxChars:  100, // force truncation
			HeadLines: 5,
			TailLines: 3,
		},
	}

	got := Process(input, cfg)

	if !strings.Contains(got, "192 lines omitted") {
		t.Errorf("expected omitted marker, got:\n%s", got)
	}

	resultLines := strings.Split(got, "\n")
	// should have: 5 head + 1 blank + 1 marker + 1 blank + 3 tail = ~11 lines
	if len(resultLines) > 15 {
		t.Errorf("expected roughly 11 lines, got %d", len(resultLines))
	}
}

func TestTruncateShortInput(t *testing.T) {
	input := "line1\nline2\nline3"
	cfg := Config{
		Truncate: TruncateConfig{
			Enabled:   true,
			MaxChars:  5, // would trigger on char count
			HeadLines: 10,
			TailLines: 10,
		},
	}

	got := Process(input, cfg)
	// 3 lines < head+tail, so no truncation despite char count
	if strings.Contains(got, "omitted") {
		t.Error("should not truncate when line count fits within head+tail")
	}
}

func TestNoProcessing(t *testing.T) {
	input := "\x1b[31mred\x1b[0m long output"
	cfg := Config{ANSIStrip: false, Truncate: TruncateConfig{Enabled: false}}

	got := Process(input, cfg)
	if got != input {
		t.Errorf("with no processing enabled, output should be unchanged")
	}
}

func TestTracker(t *testing.T) {
	tr := &Tracker{}
	tr.Record(1000, 200)
	tr.Record(500, 100)

	s := tr.Snapshot()
	if s.Calls != 2 {
		t.Errorf("calls = %d, want 2", s.Calls)
	}
	if s.RawBytes != 1500 {
		t.Errorf("raw = %d, want 1500", s.RawBytes)
	}
	if s.OutBytes != 300 {
		t.Errorf("out = %d, want 300", s.OutBytes)
	}

	pct := s.SavingsPct()
	if pct < 79.9 || pct > 80.1 {
		t.Errorf("savings = %.1f%%, want 80.0%%", pct)
	}
}
