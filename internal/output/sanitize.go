package output

import "unicode/utf8"

// Sanitizer is a stateful, chunk-safe filter that strips terminal control
// sequences and bare control bytes from a (possibly streamed) byte stream,
// passing through printable UTF-8 text plus newline and tab.
//
// It is the security boundary for command output. Output bytes are often
// attacker-influenced (a cat'd file, a remote MOTD, a process name), and
// terminal escape sequences in them attack whatever renders the output:
//   - OSC 52  writes the system clipboard
//   - OSC 8   makes displayed text link somewhere else (phishing)
//   - OSC 0/2 rewrite the terminal title
//   - CSI cursor moves rewrite already-printed lines, so the rendered
//     transcript can differ from the logged bytes (audit spoofing)
//
// Polarity is allowlist: emit only known-safe bytes and drop everything else,
// rather than blacklisting known-bad sequences. A blacklist misses
// ST-terminated OSC (ESC \, not just BEL), DCS/SOS/PM/APC strings, and the C1
// introducers -- exactly the gaps a regex stripper leaves open.
//
// Escape-parse state and a partial-UTF-8-rune remainder carry across Feed
// calls, so a sequence or multibyte rune split across a chunk boundary is still
// handled correctly. Memory is bounded: string-body bytes are dropped (never
// buffered), and the carried rune remainder is at most 3 bytes.
type Sanitizer struct {
	state   int
	pending []byte // incomplete trailing UTF-8 rune carried to the next Feed
}

// sanitizer states.
const (
	sNormal    = iota // passthrough
	sEsc              // saw ESC (0x1b)
	sCSI              // ESC [ ... params/intermediates until a final byte 0x40-0x7e
	sString           // OSC/DCS/SOS/PM/APC body, terminated by BEL or ST (ESC \)
	sStringEsc        // inside a string body, saw ESC, awaiting \ for ST
	sCharset          // ESC ( or ESC ) ... one designator byte
)

// Feed sanitizes one chunk and returns the safe bytes to emit. Bytes that may
// be the start of an incomplete escape (carried via state) or an incomplete
// UTF-8 rune (carried via pending) are held back until the next Feed or Flush.
func (s *Sanitizer) Feed(p []byte) []byte {
	if len(s.pending) > 0 {
		p = append(append([]byte(nil), s.pending...), p...)
		s.pending = s.pending[:0]
	}
	out := make([]byte, 0, len(p))
	i := 0
	for i < len(p) {
		b := p[i]
		switch s.state {
		case sNormal:
			switch {
			case b == 0x1b:
				s.state = sEsc
				i++
			case b == '\n' || b == '\t':
				out = append(out, b)
				i++
			case b < 0x20 || b == 0x7f:
				i++ // other C0 control or DEL: drop
			case b < 0x80:
				out = append(out, b) // printable ASCII
				i++
			default:
				// b >= 0x80: start (or stray continuation) of a UTF-8 rune.
				n := runeLen(b)
				if n == 0 {
					i++ // invalid lead or stray continuation / C1 byte: drop
					continue
				}
				if i+n > len(p) {
					// incomplete rune at end of chunk: carry the remainder.
					s.pending = append(s.pending[:0], p[i:]...)
					i = len(p)
					continue
				}
				r, size := utf8.DecodeRune(p[i : i+n])
				if r == utf8.RuneError && size == 1 {
					i++ // malformed: drop one byte
					continue
				}
				out = append(out, p[i:i+size]...)
				i += size
			}
		case sEsc:
			switch b {
			case '[':
				s.state = sCSI
			case ']', 'P', 'X', '^', '_': // OSC / DCS / SOS / PM / APC
				s.state = sString
			case '(', ')':
				s.state = sCharset
			default:
				s.state = sNormal // two-byte escape (ESC + final): drop both
			}
			i++
		case sCSI:
			if b >= 0x40 && b <= 0x7e { // final byte
				s.state = sNormal
			}
			i++
		case sCharset:
			s.state = sNormal
			i++
		case sString:
			if b == 0x07 { // BEL terminates
				s.state = sNormal
			} else if b == 0x1b {
				s.state = sStringEsc
			}
			i++
		case sStringEsc:
			if b == '\\' { // ST = ESC \
				s.state = sNormal
			} else {
				s.state = sString // not ST; stay in the string body
			}
			i++
		}
	}
	return out
}

// Flush returns any bytes still held back. At true end of stream an incomplete
// escape or rune is just truncated garbage, so it is dropped.
func (s *Sanitizer) Flush() []byte {
	s.pending = s.pending[:0]
	s.state = sNormal
	return nil
}

// runeLen returns the expected UTF-8 length for a leading byte, or 0 if b is
// not a valid leading byte (a continuation byte, a C1 control, or 0xf8-0xff).
func runeLen(b byte) int {
	switch {
	case b < 0x80:
		return 1
	case b >= 0xc0 && b < 0xe0:
		return 2
	case b >= 0xe0 && b < 0xf0:
		return 3
	case b >= 0xf0 && b < 0xf8:
		return 4
	}
	return 0
}

// Sanitize strips terminal control sequences and bare control bytes from a
// complete string (the buffered path). Equivalent to a single Feed + Flush.
func Sanitize(s string) string {
	if !needsSanitize(s) {
		return s
	}
	var san Sanitizer
	out := san.Feed([]byte(s))
	if tail := san.Flush(); len(tail) > 0 {
		out = append(out, tail...)
	}
	return string(out)
}

// needsSanitize is the fast path: pure printable ASCII plus \n and \t needs no
// work. Any control byte, DEL, or high byte (UTF-8 / C1) triggers the full scan.
func needsSanitize(s string) bool {
	for i := 0; i < len(s); i++ {
		if b := s[i]; b != '\n' && b != '\t' && (b < 0x20 || b >= 0x7f) {
			return true
		}
	}
	return false
}
