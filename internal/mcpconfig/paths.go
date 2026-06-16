package mcpconfig

import (
	"path/filepath"
)

// Env provides OS and environment access for path resolution.
type Env struct {
	GOOS   string
	Home   string
	Getenv func(string) string
}

// PathCtx provides context for client-specific path resolution.
type PathCtx struct {
	RepoRoot string
	Cwd      string
}

// configBase returns the base configuration directory for the operating system.
func (e Env) configBase() string {
	switch e.GOOS {
	case "windows":
		return e.Getenv("APPDATA")
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support")
	default:
		xdg := e.Getenv("XDG_CONFIG_HOME")
		if xdg != "" {
			return xdg
		}
		return filepath.Join(e.Home, ".config")
	}
}

// vscodeGlobalStorage returns the VS Code global storage directory.
func (e Env) vscodeGlobalStorage() string {
	switch e.GOOS {
	case "windows":
		return filepath.Join(e.Getenv("APPDATA"), "Code", "User", "globalStorage")
	case "darwin":
		return filepath.Join(e.Home, "Library", "Application Support", "Code", "User", "globalStorage")
	default:
		return filepath.Join(e.configBase(), "Code", "User", "globalStorage")
	}
}
