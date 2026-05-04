package output

import (
	"strings"
	"testing"
)

func makeLines(n int, line string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = line
	}
	return strings.Join(parts, "\n")
}

func BenchmarkProcessClean(b *testing.B) {
	cfg := DefaultConfig()
	in := makeLines(50, "this is a normal log line with no escape codes at all")
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Process(in, cfg)
	}
}

func BenchmarkProcessANSI(b *testing.B) {
	cfg := DefaultConfig()
	in := makeLines(50, "\x1b[31mERROR\x1b[0m something \x1b[1;33mwarn\x1b[0m happened")
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Process(in, cfg)
	}
}

func BenchmarkProcessTruncate(b *testing.B) {
	cfg := DefaultConfig()
	in := makeLines(500, "log line content here with a moderate amount of text per line so we exceed the threshold")
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Process(in, cfg)
	}
}

func BenchmarkProcessLargeClean(b *testing.B) {
	cfg := DefaultConfig()
	in := makeLines(2000, "this is a normal log line with no escape codes at all")
	b.SetBytes(int64(len(in)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Process(in, cfg)
	}
}
