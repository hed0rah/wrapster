package mcpconfig

import (
	"encoding/json"
	"testing"
)

func TestMergeEmpty(t *testing.T) {
	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp", "--policy", "/policy"}}
	out, changed, err := Merge([]byte{}, "mcpServers", "wrapster", entry, Overwrite)

	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}
	if !changed {
		t.Error("Merge should have changed")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	servers, ok := result["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers not found or not an object")
	}

	if _, hasWrapster := servers["wrapster"]; !hasWrapster {
		t.Error("wrapster server not found in mcpServers")
	}
}

func TestMergePreservesUnrelated(t *testing.T) {
	// Start with existing config with an unrelated server and unrelated top-level key.
	existing := []byte(`{
  "mcpServers": {
    "existing": {
      "command": "/path/to/existing"
    }
  },
  "otherKey": "value"
}`)

	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp", "--policy", "/policy"}}
	out, changed, err := Merge(existing, "mcpServers", "wrapster", entry, Overwrite)

	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}
	if !changed {
		t.Error("Merge should have changed")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check unrelated top-level key is preserved.
	otherValue, ok := result["otherKey"].(string)
	if !ok || otherValue != "value" {
		t.Error("otherKey not preserved")
	}

	// Check mcpServers has both entries.
	servers, ok := result["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers not found")
	}

	if _, hasExisting := servers["existing"]; !hasExisting {
		t.Error("existing server lost during merge")
	}
	if _, hasWrapster := servers["wrapster"]; !hasWrapster {
		t.Error("wrapster server not found")
	}
}

func TestMergeVscodeServersKey(t *testing.T) {
	// VS Code uses "servers" not "mcpServers".
	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp"}}
	out, changed, err := Merge([]byte("{}"), "servers", "wrapster", entry, Overwrite)

	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}
	if !changed {
		t.Error("Merge should have changed")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if _, hasServers := result["servers"]; !hasServers {
		t.Error("servers key not found")
	}
}

func TestMergeSkip(t *testing.T) {
	// Server already exists, Skip should return unchanged.
	existing := []byte(`{
  "mcpServers": {
    "wrapster": {
      "command": "/old/path"
    }
  }
}`)

	entry := ServerEntry{Command: "/new/path", Args: []string{"--new"}}
	out, changed, err := Merge(existing, "mcpServers", "wrapster", entry, Skip)

	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}
	if changed {
		t.Error("Merge should not have changed on Skip")
	}

	if !bytesEqual(out, existing) {
		t.Error("output should be identical to input on Skip")
	}
}

func TestMergeOverwrite(t *testing.T) {
	// Server already exists, Overwrite should replace it.
	existing := []byte(`{
  "mcpServers": {
    "wrapster": {
      "command": "/old/path"
    }
  }
}`)

	entry := ServerEntry{Command: "/new/path", Args: []string{"--new"}}
	out, changed, err := Merge(existing, "mcpServers", "wrapster", entry, Overwrite)

	if err != nil {
		t.Fatalf("Merge error: %v", err)
	}
	if !changed {
		t.Error("Merge should have changed on Overwrite")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	servers := result["mcpServers"].(map[string]interface{})
	wrapster := servers["wrapster"].(map[string]interface{})

	if cmd, ok := wrapster["command"].(string); !ok || cmd != "/new/path" {
		t.Error("server command was not overwritten")
	}
}

func TestMergeInvalidJSON(t *testing.T) {
	existing := []byte(`{invalid json}`)
	entry := ServerEntry{Command: "/path"}

	_, _, err := Merge(existing, "mcpServers", "wrapster", entry, Overwrite)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestMergeNestedEmpty(t *testing.T) {
	entry := ServerEntry{Command: "/path/to/wrapster", Args: []string{"--mcp"}}
	out, changed, err := MergeNested(
		[]byte("{}"),
		[]string{"projects", "/home/user/project", "mcpServers"},
		"wrapster",
		entry,
		Overwrite,
	)

	if err != nil {
		t.Fatalf("MergeNested error: %v", err)
	}
	if !changed {
		t.Error("MergeNested should have changed")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	projectsRaw, ok := result["projects"]
	if !ok {
		t.Fatal("projects key not found in result")
	}
	projects, ok := projectsRaw.(map[string]interface{})
	if !ok {
		t.Fatal("projects is not a map")
	}

	projPathRaw, ok := projects["/home/user/project"]
	if !ok {
		t.Fatal("/home/user/project key not found in projects")
	}
	projPath, ok := projPathRaw.(map[string]interface{})
	if !ok {
		t.Fatal("/home/user/project is not a map")
	}

	serversRaw, ok := projPath["mcpServers"]
	if !ok {
		t.Fatal("mcpServers key not found in project")
	}
	servers, ok := serversRaw.(map[string]interface{})
	if !ok {
		t.Fatal("mcpServers is not a map")
	}

	if _, hasWrapster := servers["wrapster"]; !hasWrapster {
		t.Error("wrapster server not found in nested structure")
	}
}

func TestMergeNestedPreservesUnrelated(t *testing.T) {
	existing := []byte(`{
  "projects": {
    "/home/user/project": {
      "mcpServers": {
        "existing": {
          "command": "/existing"
        }
      }
    }
  },
  "topLevel": "preserved"
}`)

	entry := ServerEntry{Command: "/wrapster"}
	out, changed, err := MergeNested(
		existing,
		[]string{"projects", "/home/user/project", "mcpServers"},
		"wrapster",
		entry,
		Overwrite,
	)

	if err != nil {
		t.Fatalf("MergeNested error: %v", err)
	}
	if !changed {
		t.Error("MergeNested should have changed")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check top-level key preserved.
	topLevelRaw, ok := result["topLevel"]
	if !ok || topLevelRaw.(string) != "preserved" {
		t.Error("topLevel key not preserved")
	}

	// Check both servers in nested structure.
	projects := result["projects"].(map[string]interface{})
	projPath := projects["/home/user/project"].(map[string]interface{})
	servers := projPath["mcpServers"].(map[string]interface{})

	if _, hasExisting := servers["existing"]; !hasExisting {
		t.Error("existing server lost")
	}
	if _, hasWrapster := servers["wrapster"]; !hasWrapster {
		t.Error("wrapster server not found")
	}
}

func TestMergeNestedSkip(t *testing.T) {
	existing := []byte(`{
  "projects": {
    "/home/user/project": {
      "mcpServers": {
        "wrapster": {
          "command": "/old"
        }
      }
    }
  }
}`)

	entry := ServerEntry{Command: "/new"}
	out, changed, err := MergeNested(
		existing,
		[]string{"projects", "/home/user/project", "mcpServers"},
		"wrapster",
		entry,
		Skip,
	)

	if err != nil {
		t.Fatalf("MergeNested error: %v", err)
	}
	if changed {
		t.Error("MergeNested should not change on Skip")
	}

	if !bytesEqual(out, existing) {
		t.Error("output should be identical on Skip")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
