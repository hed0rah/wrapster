package mcpconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Conflict indicates how to handle a server that already exists.
type Conflict int

const (
	// Overwrite replaces an existing server entry.
	Overwrite Conflict = iota
	// Skip leaves an existing server entry unchanged.
	Skip
)

// Merge merges a ServerEntry into existing JSON configuration.
// It preserves all sibling keys and entries byte-for-byte, only modifying the target entry.
// Returns the merged JSON (or original on Skip), whether it was modified, and any error.
func Merge(existing []byte, key, serverName string, entry ServerEntry, onConflict Conflict) (out []byte, changed bool, err error) {
	// Treat empty/whitespace as {}.
	if bytes.TrimSpace(existing) == nil || len(bytes.TrimSpace(existing)) == 0 {
		existing = []byte("{}")
	}

	// Unmarshal top level into map[string]json.RawMessage to preserve all keys.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(existing, &top); err != nil {
		return nil, false, fmt.Errorf("parsing json: %w", err)
	}

	// Unmarshal the value at key (if present) into map[string]json.RawMessage.
	var sub map[string]json.RawMessage
	if rawSub, ok := top[key]; ok {
		if err := json.Unmarshal(rawSub, &sub); err != nil {
			return nil, false, fmt.Errorf("parsing %q: %w", key, err)
		}
	} else {
		sub = make(map[string]json.RawMessage)
	}

	// Check if serverName already exists and skip if needed.
	if _, exists := sub[serverName]; exists && onConflict == Skip {
		return existing, false, nil
	}

	// Marshal entry to json.RawMessage and set in sub.
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return nil, false, fmt.Errorf("marshaling entry: %w", err)
	}
	sub[serverName] = json.RawMessage(entryBytes)

	// Re-marshal sub and put back under key in top.
	subBytes, err := json.Marshal(sub)
	if err != nil {
		return nil, false, fmt.Errorf("marshaling %q: %w", key, err)
	}
	top[key] = json.RawMessage(subBytes)

	// Marshal top with indentation and trailing newline.
	out, err = json.MarshalIndent(top, "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("marshaling top: %w", err)
	}
	out = append(out, '\n')

	return out, true, nil
}

// MergeNested merges a ServerEntry into a nested JSON structure.
// segments is a path like ["projects", "/abs/cwd", "mcpServers"] that creates
// or navigates nested objects, then sets serverName at the leaf.
// All unrelated keys are preserved at each level.
func MergeNested(existing []byte, segments []string, serverName string, entry ServerEntry, onConflict Conflict) (out []byte, changed bool, err error) {
	// Treat empty/whitespace as {}.
	if bytes.TrimSpace(existing) == nil || len(bytes.TrimSpace(existing)) == 0 {
		existing = []byte("{}")
	}

	// Unmarshal top level.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(existing, &top); err != nil {
		return nil, false, fmt.Errorf("parsing json: %w", err)
	}

	// Navigate down the path, building a chain of maps.
	chain := make([]map[string]json.RawMessage, len(segments))
	chain[0] = top

	for i := 1; i < len(segments); i++ {
		seg := segments[i-1]
		var next map[string]json.RawMessage

		if raw, ok := chain[i-1][seg]; ok {
			if err := json.Unmarshal(raw, &next); err != nil {
				return nil, false, fmt.Errorf("parsing segment %d (%q): %w", i-1, seg, err)
			}
		} else {
			next = make(map[string]json.RawMessage)
		}
		chain[i] = next
	}

	// At the leaf, apply the merge logic.
	leafKey := segments[len(segments)-1]
	var leaf map[string]json.RawMessage

	if raw, ok := chain[len(chain)-1][leafKey]; ok {
		if err := json.Unmarshal(raw, &leaf); err != nil {
			return nil, false, fmt.Errorf("parsing leaf: %w", err)
		}
	} else {
		leaf = make(map[string]json.RawMessage)
	}

	// Check for conflict.
	if _, exists := leaf[serverName]; exists && onConflict == Skip {
		// No change; return original.
		return existing, false, nil
	}

	// Set the entry in leaf.
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return nil, false, fmt.Errorf("marshaling entry: %w", err)
	}
	leaf[serverName] = json.RawMessage(entryBytes)

	// Bubble back up the chain, re-marshaling at each level.
	// Start with the leaf (at depth len(segments)-1).
	leafBytes, err := json.Marshal(leaf)
	if err != nil {
		return nil, false, fmt.Errorf("marshaling leaf: %w", err)
	}
	chain[len(chain)-1][leafKey] = json.RawMessage(leafBytes)

	// Work backwards from the second-to-last level to the root.
	for i := len(chain) - 2; i >= 0; i-- {
		seg := segments[i]
		mapBytes, err := json.Marshal(chain[i+1])
		if err != nil {
			return nil, false, fmt.Errorf("marshaling level %d: %w", i, err)
		}
		chain[i][seg] = json.RawMessage(mapBytes)
	}

	// Marshal top level with indentation and trailing newline.
	out, err = json.MarshalIndent(chain[0], "", "  ")
	if err != nil {
		return nil, false, fmt.Errorf("marshaling top: %w", err)
	}
	out = append(out, '\n')

	return out, true, nil
}
