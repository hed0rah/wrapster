package mcp

import (
	"encoding/json"
	"testing"
)

// TestMCPConformance covers the 2025-06-18 / audit fixes: the logging capability
// is declared, every annotated tool mirrors its annotation title into the
// top-level title field, and a structured tool result carries structuredContent.
func TestMCPConformance(t *testing.T) {
	r := testRunner(t)

	// logging capability declared (enables streaming output as notifications/message).
	var init initializeResult
	b, _ := json.Marshal(sendRPC(t, r, "initialize", nil).Result)
	json.Unmarshal(b, &init)
	if init.Capabilities.Logging == nil {
		t.Error("logging capability not declared")
	}

	// top-level Tool.title mirrors annotations.title on every annotated tool.
	var tl toolsListResult
	b, _ = json.Marshal(sendRPC(t, r, "tools/list", nil).Result)
	json.Unmarshal(b, &tl)
	annotated := 0
	for _, tool := range tl.Tools {
		if tool.Annotations == nil {
			continue
		}
		annotated++
		if tool.Title == "" || tool.Title != tool.Annotations.Title {
			t.Errorf("tool %q: top-level title %q != annotations.title %q", tool.Name, tool.Title, tool.Annotations.Title)
		}
	}
	if annotated == 0 {
		t.Error("expected annotated tools")
	}

	// structuredContent present on a structured tool result (ssh_validate).
	resp := sendRPC(t, r, "tools/call", map[string]any{
		"name":      "ssh_validate",
		"arguments": map[string]any{"host": "prod-web", "command": "uptime"},
	})
	b, _ = json.Marshal(resp.Result)
	var tres toolResult
	json.Unmarshal(b, &tres)
	if tres.StructuredContent == nil {
		t.Error("ssh_validate result missing structuredContent")
	}
}
