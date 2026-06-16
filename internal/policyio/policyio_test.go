package policyio

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hed0rah/wrapster/internal/policy"
)

// TestMarshalRoundTrip builds a policy with timeouts and filter blocks,
// marshals it to YAML, verifies the timeout serializes as "30s" (not a raw
// number), then loads it back and asserts data round-trips.
func TestMarshalRoundTrip(t *testing.T) {
	// Build a policy with timeouts and a host.
	p := &policy.Policy{
		Defaults: policy.HostPolicy{},
		Hosts: map[string]policy.HostPolicy{
			"testhost": {
				Hostname: "example.com",
				User:     "testuser",
				Port:     22,
				AllowedCommands: []policy.CommandRule{
					{
						Command:     "ls",
						Description: "list directory",
					},
				},
			},
		},
		Local: policy.LocalConfig{
			Mode:    "guardrail",
			Timeout: policy.Duration(30 * time.Second),
		},
		Filters: policy.FilterConfig{
			GTFOBins: policy.FilterModuleConfig{
				Enabled: true,
				Block:   []string{"shell", "reverse-shell"},
			},
			Destructive: policy.FilterModuleConfig{
				Enabled: true,
			},
		},
		Output: policy.OutputConfig{
			ANSIStrip: true,
			Truncate: policy.OutputTruncateConfig{
				Enabled:   true,
				MaxChars:  4096,
				HeadLines: 32,
				TailLines: 8,
			},
			Stats: true,
		},
	}

	// Marshal to YAML.
	data, err := MarshalYAML(p)
	if err != nil {
		t.Fatalf("MarshalYAML failed: %v", err)
	}

	yamlStr := string(data)
	t.Logf("Marshaled YAML:\n%s", yamlStr)

	// Check that "timeout: 30s" appears (human-readable duration, not nanoseconds).
	if !strings.Contains(yamlStr, "timeout: 30s") {
		t.Errorf("expected 'timeout: 30s' in YAML, but got:\n%s", yamlStr)
	}

	// Write to temp file and load it back.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Load the policy back.
	loaded, err := policy.LoadPolicy(tmpFile)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// Assert Local.Timeout round-trips to 30s.
	expected := policy.Duration(30 * time.Second)
	if loaded.Local.Timeout != expected {
		t.Errorf("Local.Timeout round-trip failed: got %v, want %v", loaded.Local.Timeout, expected)
	}

	// Assert host data survives.
	hostPolicy, ok := loaded.Hosts["testhost"]
	if !ok {
		t.Errorf("testhost not found in loaded.Hosts")
	} else {
		if hostPolicy.Hostname != "example.com" {
			t.Errorf("host.Hostname: got %q, want %q", hostPolicy.Hostname, "example.com")
		}
		if hostPolicy.User != "testuser" {
			t.Errorf("host.User: got %q, want %q", hostPolicy.User, "testuser")
		}
		if hostPolicy.Port != 22 {
			t.Errorf("host.Port: got %d, want 22", hostPolicy.Port)
		}
		if len(hostPolicy.AllowedCommands) != 1 {
			t.Errorf("host.AllowedCommands: got %d, want 1", len(hostPolicy.AllowedCommands))
		} else if hostPolicy.AllowedCommands[0].Command != "ls" {
			t.Errorf("host.AllowedCommands[0].Command: got %q, want %q", hostPolicy.AllowedCommands[0].Command, "ls")
		}
	}

	// Assert filter config round-trips.
	if !loaded.Filters.GTFOBins.Enabled {
		t.Errorf("GTFOBins.Enabled: got false, want true")
	}
	if len(loaded.Filters.GTFOBins.Block) != 2 {
		t.Errorf("GTFOBins.Block length: got %d, want 2", len(loaded.Filters.GTFOBins.Block))
	}
	if !loaded.Filters.Destructive.Enabled {
		t.Errorf("Destructive.Enabled: got false, want true")
	}
}

// TestDefaultPolicyLoads marshals DefaultPolicy, writes it to a temp file,
// loads it back, and asserts no error and Local.Mode=="guardrail".
func TestDefaultPolicyLoads(t *testing.T) {
	defPolicy := DefaultPolicy()
	data, err := MarshalYAML(defPolicy)
	if err != nil {
		t.Fatalf("MarshalYAML(DefaultPolicy) failed: %v", err)
	}

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	loaded, err := policy.LoadPolicy(tmpFile)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if loaded.Local.Mode != "guardrail" {
		t.Errorf("Local.Mode: got %q, want %q", loaded.Local.Mode, "guardrail")
	}
}

// TestLoadForEditMissing verifies that explicit missing paths error,
// and that LoadForEdit("") with no policy in the temp directory returns
// DefaultPolicy with nil error.
func TestLoadForEditMissing(t *testing.T) {
	// Explicit missing path should error.
	_, err := LoadForEdit("/nonexistent/path/xyz.yaml")
	if err == nil {
		t.Errorf("LoadForEdit with explicit missing path: expected error, got nil")
	}

	// LoadForEdit("") in an empty temp directory should return DefaultPolicy with nil error.
	tmpDir := t.TempDir()
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	defer os.Chdir(oldCwd)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	loaded, err := LoadForEdit("")
	if err != nil {
		t.Errorf("LoadForEdit(\"\") with no policy: expected nil error, got %v", err)
	}
	if loaded == nil {
		t.Errorf("LoadForEdit(\"\") with no policy: expected DefaultPolicy, got nil")
	} else if loaded.Local.Mode != "guardrail" {
		t.Errorf("LoadForEdit(\"\") returned policy with Mode %q, want %q", loaded.Local.Mode, "guardrail")
	}
}
