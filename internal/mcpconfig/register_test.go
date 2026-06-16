package mcpconfig

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRegisterCLI(t *testing.T) {
	// Test that claude-code with claude on PATH uses the CLI.
	client := Client{
		Name:     "claude-code",
		Display:  "Claude Code",
		Key:      "mcpServers",
		Scope:    ScopeUser,
		LookPath: []string{"claude"},
		UseCLI:   true,
		Nested:   true,
		PathFn: func(e Env, _ PathCtx) (string, error) {
			return "/home/u/.claude.json", nil
		},
	}

	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp"}}

	cliCalled := false
	var cliName string
	var cliArgs []string

	opts := RegisterOpts{
		Env:        Env{GOOS: "linux", Home: "/home/u", Getenv: func(k string) string { return "" }},
		Ctx:        PathCtx{RepoRoot: "/home/u/proj", Cwd: "/home/u/proj"},
		Entry:      entry,
		ServerName: "wrapster",
		Conflict:   Overwrite,
		Probe: Probe{
			Stat: os.Stat,
			LookPath: func(bin string) (string, error) {
				if bin == "claude" {
					return "/usr/bin/claude", nil
				}
				return "", os.ErrNotExist
			},
		},
		ReadFile: os.ReadFile,
		WriteAtom: func(path string, data []byte) error {
			// Should not be called for CLI path.
			t.Error("WriteAtom should not be called for CLI path")
			return nil
		},
		RunCLI: func(name string, args ...string) error {
			cliCalled = true
			cliName = name
			cliArgs = args
			return nil
		},
	}

	result := Register(client, opts)

	if result.Action != "cli" {
		t.Errorf("expected action 'cli', got %q", result.Action)
	}
	if !cliCalled {
		t.Error("RunCLI should have been called")
	}
	if cliName != "claude" {
		t.Errorf("expected command 'claude', got %q", cliName)
	}
	if len(cliArgs) < 3 || cliArgs[0] != "mcp" || cliArgs[1] != "add-json" {
		t.Errorf("unexpected CLI args: %v", cliArgs)
	}
}

func TestRegisterNormalMerge(t *testing.T) {
	// Test normal registration: read, merge, and write.
	client := Client{
		Name:     "cursor",
		Display:  "Cursor",
		Key:      "mcpServers",
		Scope:    ScopeUser,
		LookPath: []string{"cursor"},
		UseCLI:   false,
		Nested:   false,
		PathFn: func(e Env, _ PathCtx) (string, error) {
			return "/home/u/.cursor/mcp.json", nil
		},
	}

	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp"}}

	writeCalled := false
	var writeData []byte

	opts := RegisterOpts{
		Env:        Env{GOOS: "linux", Home: "/home/u", Getenv: func(k string) string { return "" }},
		Ctx:        PathCtx{RepoRoot: "/home/u/proj", Cwd: "/home/u/proj"},
		Entry:      entry,
		ServerName: "wrapster",
		Conflict:   Skip, // Use Skip to expect "merged" action
		Probe:      DefaultProbe(),
		ReadFile: func(path string) ([]byte, error) {
			return []byte(`{"mcpServers":{}}`), nil
		},
		WriteAtom: func(path string, data []byte) error {
			writeCalled = true
			writeData = data
			return nil
		},
		RunCLI: func(name string, args ...string) error {
			t.Error("RunCLI should not be called for normal registration")
			return nil
		},
	}

	result := Register(client, opts)

	if result.Action != "merged" {
		t.Errorf("expected action 'merged', got %q", result.Action)
	}
	if !writeCalled {
		t.Error("WriteAtom should have been called")
	}

	var written map[string]interface{}
	if err := json.Unmarshal(writeData, &written); err != nil {
		t.Fatalf("written data is not valid JSON: %v", err)
	}

	servers := written["mcpServers"].(map[string]interface{})
	if _, hasWrapster := servers["wrapster"]; !hasWrapster {
		t.Error("wrapster server not in written config")
	}
}

func TestRegisterCreated(t *testing.T) {
	// Test that registering into an empty file is reported as 'created'.
	client := Client{
		Name:     "cursor",
		Display:  "Cursor",
		Key:      "mcpServers",
		Scope:    ScopeUser,
		LookPath: []string{"cursor"},
		UseCLI:   false,
		Nested:   false,
		PathFn: func(e Env, _ PathCtx) (string, error) {
			return "/home/u/.cursor/mcp.json", nil
		},
	}

	entry := ServerEntry{Command: "/wrapster"}

	opts := RegisterOpts{
		Env:        Env{GOOS: "linux", Home: "/home/u", Getenv: func(k string) string { return "" }},
		Ctx:        PathCtx{RepoRoot: "/home/u/proj", Cwd: "/home/u/proj"},
		Entry:      entry,
		ServerName: "wrapster",
		Conflict:   Overwrite,
		Probe:      DefaultProbe(),
		ReadFile: func(path string) ([]byte, error) {
			return nil, os.ErrNotExist
		},
		WriteAtom: func(path string, data []byte) error {
			return nil
		},
		RunCLI: func(name string, args ...string) error {
			return nil
		},
	}

	result := Register(client, opts)

	if result.Action != "created" {
		t.Errorf("expected action 'created', got %q", result.Action)
	}
}

func TestRegisterSkipped(t *testing.T) {
	// Test that Skip on existing entry returns 'skipped' and doesn't write.
	client := Client{
		Name:     "cursor",
		Display:  "Cursor",
		Key:      "mcpServers",
		Scope:    ScopeUser,
		LookPath: []string{"cursor"},
		UseCLI:   false,
		Nested:   false,
		PathFn: func(e Env, _ PathCtx) (string, error) {
			return "/home/u/.cursor/mcp.json", nil
		},
	}

	entry := ServerEntry{Command: "/new/path"}

	writeCalled := false

	opts := RegisterOpts{
		Env:        Env{GOOS: "linux", Home: "/home/u", Getenv: func(k string) string { return "" }},
		Ctx:        PathCtx{RepoRoot: "/home/u/proj", Cwd: "/home/u/proj"},
		Entry:      entry,
		ServerName: "wrapster",
		Conflict:   Skip,
		Probe:      DefaultProbe(),
		ReadFile: func(path string) ([]byte, error) {
			return []byte(`{"mcpServers":{"wrapster":{"command":"/old/path"}}}`), nil
		},
		WriteAtom: func(path string, data []byte) error {
			writeCalled = true
			return nil
		},
		RunCLI: func(name string, args ...string) error {
			return nil
		},
	}

	result := Register(client, opts)

	if result.Action != "skipped" {
		t.Errorf("expected action 'skipped', got %q", result.Action)
	}
	if writeCalled {
		t.Error("WriteAtom should not be called for skipped registration")
	}
}

func TestRegisterAll(t *testing.T) {
	// Test that RegisterAll processes all clients.
	clients := []Client{
		{
			Name:    "test-1",
			Display: "Test 1",
			Key:     "mcpServers",
			Scope:   ScopeUser,
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return "/test1.json", nil
			},
		},
		{
			Name:    "test-2",
			Display: "Test 2",
			Key:     "mcpServers",
			Scope:   ScopeUser,
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return "/test2.json", nil
			},
		},
	}

	opts := RegisterOpts{
		Env:        Env{GOOS: "linux", Home: "/home/u", Getenv: func(k string) string { return "" }},
		Ctx:        PathCtx{RepoRoot: "/home/u/proj", Cwd: "/home/u/proj"},
		Entry:      ServerEntry{Command: "/wrapster"},
		ServerName: "wrapster",
		Conflict:   Overwrite,
		Probe:      DefaultProbe(),
		ReadFile: func(path string) ([]byte, error) {
			return []byte("{}"), nil
		},
		WriteAtom: func(path string, data []byte) error {
			return nil
		},
		RunCLI: func(name string, args ...string) error {
			return nil
		},
	}

	results := RegisterAll(clients, opts)

	if len(results) != len(clients) {
		t.Errorf("RegisterAll returned %d results, want %d", len(results), len(clients))
	}

	for i, result := range results {
		if result.Client != clients[i].Display {
			t.Errorf("result %d client = %q, want %q", i, result.Client, clients[i].Display)
		}
	}
}
