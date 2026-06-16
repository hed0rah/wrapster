package mcpconfig

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigBase(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		home     string
		getenv   map[string]string
		expected string
	}{
		{
			name:     "windows appdata",
			goos:     "windows",
			home:     "C:\\Users\\u",
			getenv:   map[string]string{"APPDATA": "C:\\Users\\u\\AppData\\Roaming"},
			expected: "C:\\Users\\u\\AppData\\Roaming",
		},
		{
			name:     "darwin library",
			goos:     "darwin",
			home:     "/Users/u",
			getenv:   map[string]string{},
			expected: filepath.Join("/Users/u", "Library", "Application Support"),
		},
		{
			name:     "linux xdg set",
			goos:     "linux",
			home:     "/home/u",
			getenv:   map[string]string{"XDG_CONFIG_HOME": "/home/u/.config"},
			expected: "/home/u/.config",
		},
		{
			name:     "linux xdg empty",
			goos:     "linux",
			home:     "/home/u",
			getenv:   map[string]string{"XDG_CONFIG_HOME": ""},
			expected: filepath.Join("/home/u", ".config"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := Env{
				GOOS: tt.goos,
				Home: tt.home,
				Getenv: func(k string) string {
					return tt.getenv[k]
				},
			}
			got := env.configBase()
			if got != tt.expected {
				t.Errorf("configBase() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestVscodeGlobalStorage(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		home     string
		getenv   map[string]string
		expected string
	}{
		{
			name:     "windows",
			goos:     "windows",
			home:     "C:\\Users\\u",
			getenv:   map[string]string{"APPDATA": "C:\\Users\\u\\AppData\\Roaming"},
			expected: filepath.Join("C:\\Users\\u\\AppData\\Roaming", "Code", "User", "globalStorage"),
		},
		{
			name:     "darwin",
			goos:     "darwin",
			home:     "/Users/u",
			getenv:   map[string]string{},
			expected: filepath.Join("/Users/u", "Library", "Application Support", "Code", "User", "globalStorage"),
		},
		{
			name:     "linux",
			goos:     "linux",
			home:     "/home/u",
			getenv:   map[string]string{"XDG_CONFIG_HOME": ""},
			expected: filepath.Join("/home/u", ".config", "Code", "User", "globalStorage"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := Env{
				GOOS: tt.goos,
				Home: tt.home,
				Getenv: func(k string) string {
					return tt.getenv[k]
				},
			}
			got := env.vscodeGlobalStorage()
			if got != tt.expected {
				t.Errorf("vscodeGlobalStorage() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestClientPaths(t *testing.T) {
	env := Env{
		GOOS: "linux",
		Home: "/home/u",
		Getenv: func(k string) string {
			if k == "XDG_CONFIG_HOME" {
				return ""
			}
			return ""
		},
	}
	ctx := PathCtx{
		RepoRoot: "/home/u/project",
		Cwd:      "/home/u/project",
	}

	tests := []struct {
		name         string
		clientName   string
		shouldError  bool
		pathContains string
	}{
		{
			name:         "claude-desktop",
			clientName:   "claude-desktop",
			shouldError:  false,
			pathContains: "Claude",
		},
		{
			name:         "vscode uses reporoot",
			clientName:   "vscode",
			shouldError:  false,
			pathContains: "home/u/project", // use forward slashes to match both Windows and Unix paths
		},
	}

	clients := Registry()
	clientMap := make(map[string]Client)
	for _, c := range clients {
		clientMap[c.Name] = c
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, ok := clientMap[tt.clientName]
			if !ok {
				t.Fatalf("client %q not found", tt.clientName)
			}
			path, err := client.ConfigPath(env, ctx)
			if (err != nil) != tt.shouldError {
				t.Errorf("ConfigPath error = %v, wantError %v", err, tt.shouldError)
			}
			if !tt.shouldError && path == "" {
				t.Errorf("ConfigPath returned empty string")
			}
			if tt.pathContains != "" && path != "" && !stringContains(path, tt.pathContains) {
				t.Errorf("ConfigPath = %q, want to contain %q", path, tt.pathContains)
			}
		})
	}
}

func stringContains(s, substr string) bool {
	// Normalize both to forward slashes for comparison
	s = strings.ReplaceAll(s, "\\", "/")
	substr = strings.ReplaceAll(substr, "\\", "/")
	return strings.Contains(s, substr)
}
