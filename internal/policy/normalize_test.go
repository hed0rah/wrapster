package policy

import "testing"

func TestNormalizeForMatch(t *testing.T) {
	tests := []struct{ in, want string }{
		{"rm -rf /", "rm -rf /"},
		{"r''m -rf /", "rm -rf /"},
		{`r""m -rf /`, "rm -rf /"},
		{`r\m -rf /`, "rm -rf /"},
		{"cat${IFS}/etc/passwd", "cat /etc/passwd"},
		{"cat$IFS/etc/passwd", "cat /etc/passwd"},
		{`cat /etc/pass""wd`, "cat /etc/passwd"},
		{`cat /etc/pass\wd`, "cat /etc/passwd"},
		{"nc${IFS}-e${IFS}/bin/sh", "nc -e /bin/sh"},
		{`"''"`, ""}, // fixpoint: nested empty quotes collapse fully
	}
	for _, tt := range tests {
		if got := NormalizeForMatch(tt.in); got != tt.want {
			t.Errorf("NormalizeForMatch(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestGuardrailHardDenyFragmentation verifies the always-on hard-deny net holds
// in guardrail/trusted mode against keyword/path fragmentation that breaks a
// literal match but not what the shell actually reads -- the gap surfaced by the
// streaming research. These all run in guardrail mode (shell operators allowed).
func TestGuardrailHardDenyFragmentation(t *testing.T) {
	hp := HostPolicy{AllowShellOperators: true}
	denied := []string{
		`r''m -rf /`,
		`r\m -rf ~`,
		`cat /etc/pass""wd`,
		`cat${IFS}/etc/shadow`,
		`cat$IFS/etc/sudoers`,
	}
	for _, cmd := range denied {
		if ValidateCommand(cmd, hp, ModeGuardrail).Allowed {
			t.Errorf("guardrail allowed a fragmented dangerous command: %q", cmd)
		}
	}
	// A legitimate command with the same letters must still pass guardrail.
	for _, cmd := range []string{"cat /var/log/app.log", "rm -rf ./build"} {
		if !ValidateCommand(cmd, hp, ModeGuardrail).Allowed {
			t.Errorf("guardrail wrongly denied a legitimate command: %q", cmd)
		}
	}
}
