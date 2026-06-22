package policy

import "testing"

// FuzzValidateCommand hunts for panics, non-determinism, and normalization bugs
// across both validation modes. The validator must survive any input string.
func FuzzValidateCommand(f *testing.F) {
	seeds := []string{
		"", " ", "uptime", "rm -rf /", "ls | grep x", "echo $(date)",
		"rm${IFS}-rf${IFS}/", `$'\x72\x6d' -rf /`, "{rm,-rf,/}",
		"a; b && c || d & e | f |& g", "cat <<EOF\nx\nEOF", "echo `id`",
		"rm\t-rf\t/", "IFS=, cat,/etc/shadow", "find / -delete",
		":(){ :|:& };:", "\x00\x01\xff", "сd /etc", "ｒｍ -rf /",
		"a" + string(make([]byte, 4096)), "((1+1))", "${x:-y}", "<(ls)",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	hpAllow := HostPolicy{
		AllowedCommands:     []CommandRule{{Command: "echo"}, {Command: "ls"}},
		AllowShellOperators: true,
	}
	hpGuard := HostPolicy{AllowShellOperators: true}

	f.Fuzz(func(t *testing.T, cmd string) {
		// invariant 1: never panic in any mode.
		r1 := ValidateCommand(cmd, hpAllow, ModeAllowlist)
		r2 := ValidateCommand(cmd, hpGuard, ModeGuardrail)

		// invariant 2: deterministic (no shared-state bleed across calls).
		if ValidateCommand(cmd, hpAllow, ModeAllowlist).Allowed != r1.Allowed {
			t.Fatalf("non-deterministic allowlist result for %q", cmd)
		}
		if ValidateCommand(cmd, hpGuard, ModeGuardrail).Allowed != r2.Allowed {
			t.Fatalf("non-deterministic guardrail result for %q", cmd)
		}

		// invariant 3: command normalization is idempotent.
		n := NormalizeForMatch(cmd)
		if NormalizeForMatch(n) != n {
			t.Fatalf("NormalizeForMatch not idempotent for %q", cmd)
		}

		_ = splitSegments(cmd)
		_ = dangerousRm(cmd)
	})
}
