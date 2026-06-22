package policy

import (
	"strings"
	"testing"
)

func TestCommandLengthCap(t *testing.T) {
	hp := HostPolicy{AllowShellOperators: true}
	if r := ValidateCommand(strings.Repeat("a", (1<<16)+1), hp, ModeGuardrail); r.Allowed {
		t.Error("oversized command should be denied")
	}
	// a legitimately large-but-sane command still passes
	if r := ValidateCommand("echo "+strings.Repeat("x", 4096), hp, ModeGuardrail); !r.Allowed {
		t.Errorf("4KB command denied: %s", r.Reason)
	}
}

// BenchmarkValidatePathological measures validation cost on adversarial inputs
// the fuzzer drifted toward: huge strings and huge segment/flag counts. A shared
// hub must not let one oversized command pin a core.
func BenchmarkValidatePathological(b *testing.B) {
	hp := HostPolicy{
		AllowedCommands:     []CommandRule{{Command: "a"}},
		AllowShellOperators: true,
	}
	inputs := map[string]string{
		"1MB_plain":     strings.Repeat("a", 1<<20),
		"100k_semis":    strings.Repeat("a;", 100000),
		"100k_ifs":      strings.Repeat("${IFS}", 100000),
		"100k_rm_flags": "rm " + strings.Repeat("-r ", 100000) + "/",
		"normal":        "tar czf backup.tgz ./data | gzip | ssh host 'cat > b'",
	}
	for name, in := range inputs {
		in := in
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ValidateCommand(in, hp, ModeAllowlist)
			}
		})
	}
}
