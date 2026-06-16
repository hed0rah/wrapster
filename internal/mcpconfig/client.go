package mcpconfig

import (
	"path/filepath"
)

// Scope indicates whether a client configuration is at user or project scope.
type Scope int

const (
	// ScopeUser indicates user-level (global) configuration.
	ScopeUser Scope = iota
	// ScopeProject indicates project-level configuration.
	ScopeProject
)

// Client represents an MCP client and its configuration location.
type Client struct {
	// Name is the internal identifier.
	Name string
	// Display is the human-readable name.
	Display string
	// Key is the JSON object key to merge the server entry under.
	Key string
	// Scope is whether this is user or project level.
	Scope Scope
	// LookPath lists binary names to search for via exec.LookPath.
	LookPath []string
	// PathFn resolves the configuration file path.
	PathFn func(Env, PathCtx) (string, error)
	// Nested indicates whether the client uses nested configuration (e.g., projects).
	Nested bool
	// UseCLI indicates whether to use the client's CLI for registration.
	UseCLI bool
}

// ConfigPath resolves the configuration file path for this client.
func (c Client) ConfigPath(env Env, ctx PathCtx) (string, error) {
	return c.PathFn(env, ctx)
}

// Registry returns all supported MCP clients in order of preference.
func Registry() []Client {
	return []Client{
		{
			Name:     "claude-desktop",
			Display:  "Claude Desktop",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{"claude"},
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(e.configBase(), "Claude", "claude_desktop_config.json"), nil
			},
		},
		{
			Name:     "claude-code",
			Display:  "Claude Code",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{"claude"},
			UseCLI:   true,
			Nested:   true,
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(e.Home, ".claude.json"), nil
			},
		},
		{
			Name:     "cursor",
			Display:  "Cursor",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{"cursor"},
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(e.Home, ".cursor", "mcp.json"), nil
			},
		},
		{
			Name:     "windsurf",
			Display:  "Windsurf",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{"windsurf"},
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(e.Home, ".codeium", "windsurf", "mcp_config.json"), nil
			},
		},
		{
			Name:     "cline",
			Display:  "Cline (VS Code)",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{"code"},
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(
					e.vscodeGlobalStorage(),
					"saoudrizwan.claude-dev",
					"settings",
					"cline_mcp_settings.json",
				), nil
			},
		},
		{
			Name:     "vscode",
			Display:  "VS Code",
			Key:      "servers",
			Scope:    ScopeProject,
			LookPath: []string{"code"},
			PathFn: func(_ Env, ctx PathCtx) (string, error) {
				return filepath.Join(ctx.RepoRoot, ".vscode", "mcp.json"), nil
			},
		},
		{
			Name:     "lmstudio",
			Display:  "LM Studio",
			Key:      "mcpServers",
			Scope:    ScopeUser,
			LookPath: []string{},
			PathFn: func(e Env, _ PathCtx) (string, error) {
				return filepath.Join(e.Home, ".lmstudio", "mcp.json"), nil
			},
		},
	}
}
