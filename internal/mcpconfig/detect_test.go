package mcpconfig

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestDetectAll(t *testing.T) {
	// Create a fake Probe with custom Stat and LookPath.
	// Stat returns success for paths that begin with /fake (to simulate installed clients).
	// LookPath returns success for "claude" binary.
	probe := Probe{
		Stat: func(path string) (os.FileInfo, error) {
			// Check if path starts with /fake (simple heuristic for test).
			if strings.HasPrefix(path, "/fake") {
				return &fakeFileInfo{name: path, isDir: strings.HasSuffix(path, "/")}, nil
			}
			return nil, os.ErrNotExist
		},
		LookPath: func(bin string) (string, error) {
			if bin == "claude" {
				return "/usr/bin/claude", nil
			}
			return "", os.ErrNotExist
		},
	}

	env := Env{
		GOOS: "darwin",
		Home: "/fake",
		Getenv: func(k string) string {
			return ""
		},
	}

	ctx := PathCtx{
		RepoRoot: "/fake/repo",
		Cwd:      "/fake/repo",
	}

	results := DetectAll(env, ctx, probe)

	if len(results) == 0 {
		t.Fatalf("DetectAll returned no results")
	}

	// Find the claude-desktop result which should have BinaryOnPath=true
	// (because claude is in LookPath) and possibly ConfigExists=true.
	found := false
	for _, result := range results {
		if result.Client.Name == "claude-desktop" {
			found = true
			if !result.BinaryOnPath {
				t.Error("claude-desktop: BinaryOnPath should be true (claude in LookPath)")
			}
			if result.Path == "" {
				t.Error("claude-desktop: Path should be set")
			}
			// ConfigExists depends on whether Stat succeeds for the resolved path.
			// For the test, we don't strictly require it, but check it's consistent.
			if result.ConfigExists && !strings.HasPrefix(result.Path, "/fake") {
				t.Error("claude-desktop: ConfigExists inconsistent with fake Probe")
			}
		}
	}
	if !found {
		t.Error("claude-desktop not found in results")
	}
}

func TestDetectInstalled(t *testing.T) {
	tests := []struct {
		name         string
		installed    bool
		configExists bool
		dirExists    bool
		binaryOnPath bool
	}{
		{"installed: config exists", true, true, false, false},
		{"installed: dir exists", true, false, true, false},
		{"installed: binary on path", true, false, false, true},
		{"not installed", false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det := Detection{
				ConfigExists: tt.configExists,
				DirExists:    tt.dirExists,
				BinaryOnPath: tt.binaryOnPath,
			}
			if det.Installed() != tt.installed {
				t.Errorf("Installed() = %v, want %v", det.Installed(), tt.installed)
			}
		})
	}
}

// fakeFileInfo is a minimal os.FileInfo for testing.
type fakeFileInfo struct {
	name  string
	isDir bool
}

func (f *fakeFileInfo) Name() string       { return f.name }
func (f *fakeFileInfo) Size() int64        { return 0 }
func (f *fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (f *fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f *fakeFileInfo) IsDir() bool        { return f.isDir }
func (f *fakeFileInfo) Sys() interface{}   { return nil }
