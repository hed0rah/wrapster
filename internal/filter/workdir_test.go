package filter

import (
	"testing"
)

func TestWorkdirFilter(t *testing.T) {
	f := NewWorkdirFilter("/home/user/project")

	tests := []struct {
		name    string
		cmd     string
		blocked bool
		reason  string
	}{
		{"safe relative", "ls src/main.go", false, ""},
		{"safe in root", "cat /home/user/project/README.md", false, ""},
		{"dotdot traversal", "cat ../../../etc/passwd", true, "traversal"},
		{"absolute escape", "cat /etc/passwd", true, "path-escape"},
		{"absolute inside", "ls /home/user/project/src", false, ""},
		{"cd home", "cd ~", true, "cd-escape"},
		{"cd tilde path", "cd ~/other", true, "cd-escape"},
		{"cd dash", "cd -", true, "cd-escape"},
		{"cd outside", "cd /tmp", true, "path-escape"},
		{"cd inside", "cd /home/user/project/src", false, ""},
		{"no paths", "echo hello", false, ""},
		{"mixed safe", "grep -r TODO /home/user/project/src", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := f.Scan(tt.cmd)
			if tt.blocked && len(findings) == 0 {
				t.Errorf("expected findings for %q, got none", tt.cmd)
			}
			if !tt.blocked && len(findings) > 0 {
				t.Errorf("expected no findings for %q, got %d: %v", tt.cmd, len(findings), findings)
			}
			if tt.blocked && len(findings) > 0 && findings[0].Function != tt.reason {
				t.Errorf("expected function %q, got %q", tt.reason, findings[0].Function)
			}
		})
	}
}
