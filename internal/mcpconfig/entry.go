package mcpconfig

// ServerEntry represents an MCP server configuration entry.
type ServerEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// BuildEntry returns a ServerEntry configured to run the wrapster MCP server.
// exe is the path to the wrapster executable; policyPath is the path to the policy file.
func BuildEntry(exe, policyPath string) ServerEntry {
	return ServerEntry{
		Command: exe,
		Args:    []string{"--mcp", "--policy", policyPath},
	}
}
