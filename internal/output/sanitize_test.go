package output

import "testing"

const esc = "\x1b"

func TestSanitizeOneShot(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "hello world", "hello world"},
		{"tab and newline kept", "a\tb\nc", "a\tb\nc"},
		{"csi color", esc + "[31mred" + esc + "[0m", "red"},
		{"cursor clear", esc + "[2J" + esc + "[H", ""},
		{"osc bel title", esc + "]0;title\x07ok", "ok"},
		// the bug: OSC terminated by ST (ESC \), not BEL -- previously leaked through.
		{"osc52 clipboard via ST", esc + "]52;c;ZXZpbA==" + esc + "\\ok", "ok"},
		{"osc8 hyperlink", esc + "]8;;http://evil\x07text" + esc + "]8;;\x07", "text"},
		{"dcs string", esc + "Pq garbage " + esc + "\\done", "done"},
		{"apc string", esc + "_payload" + esc + "\\x", "x"},
		{"sos string", esc + "Xsecret" + esc + "\\y", "y"},
		{"charset designator", esc + "(Btxt", "txt"},
		{"two-byte esc", esc + "7abc" + esc + "8", "abc"},
		{"bare CR dropped", "a\rb", "ab"},
		{"backspace dropped", "a\bb", "ab"},
		{"nul dropped", "a\x00b", "ab"},
		{"del dropped", "a\x7fb", "ab"},
		{"bel dropped", "a\x07b", "ab"},
		// a raw C1 OSC introducer (0x9d) is an invalid lead byte -> dropped; the
		// payload then renders as inert text (no active escape), which is safe.
		{"c1 introducer dropped", "a\x9d52;x\x07b", "a52;xb"},
		{"unicode preserved", "café Ω 漢字", "café Ω 漢字"},
		{"stray continuation byte dropped", "a\x80b", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sanitize(tt.in); got != tt.want {
				t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// representative payload mixing CSI, OSC(BEL+ST), DCS, charset, multibyte runes,
// bare controls, tab and newline. Used by the chunk-equivalence tests.
var mixedPayload = "hi" + esc + "[31mred" + esc + "[0m\t" +
	esc + "]52;c;ZXZpbA==" + esc + "\\" + "ok\n" +
	"café漢字Ω" + esc + "Pq;data" + esc + "\\" + "end" +
	esc + "]0;title\x07" + "\rdone"

// TestSanitizeSplitEquivalence proves chunk-safety: splitting the input at any
// single byte offset and feeding the two halves must equal the one-shot result.
// This is the streaming correctness guarantee -- a sequence or rune split across
// a chunk boundary is handled the same as if seen whole.
func TestSanitizeSplitEquivalence(t *testing.T) {
	want := Sanitize(mixedPayload)
	pb := []byte(mixedPayload)
	for split := 1; split < len(pb); split++ {
		var s Sanitizer
		got := append([]byte(nil), s.Feed(pb[:split])...)
		got = append(got, s.Feed(pb[split:])...)
		got = append(got, s.Flush()...)
		if string(got) != want {
			t.Fatalf("split at %d: got %q, want %q", split, got, want)
		}
	}
}

// TestSanitizeByteAtATime is the extreme case: every byte fed as its own chunk,
// maximally exercising the carried escape-state and partial-rune remainder.
func TestSanitizeByteAtATime(t *testing.T) {
	want := Sanitize(mixedPayload)
	var s Sanitizer
	var got []byte
	for _, b := range []byte(mixedPayload) {
		got = append(got, s.Feed([]byte{b})...)
	}
	got = append(got, s.Flush()...)
	if string(got) != want {
		t.Errorf("byte-at-a-time = %q, want %q", got, want)
	}
}

// TestSanitizeReuse confirms a Sanitizer resets cleanly after Flush.
func TestSanitizeReuse(t *testing.T) {
	var s Sanitizer
	out := append([]byte(nil), s.Feed([]byte("a"+esc+"[1m"))...) // ends mid-CSI
	out = append(out, s.Flush()...)                              // drops incomplete CSI
	if string(out) != "a" {
		t.Fatalf("first pass = %q, want %q", out, "a")
	}
	out = append(out[:0], s.Feed([]byte("b\tc"))...)
	out = append(out, s.Flush()...)
	if string(out) != "b\tc" {
		t.Errorf("after reuse = %q, want %q", out, "b\tc")
	}
}
