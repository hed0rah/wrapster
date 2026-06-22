package mcp

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// TestStreamingOutputNotifications verifies that a tools/call carrying a
// progressToken streams command output live as notifications/message records,
// while still returning the full result.
func TestStreamingOutputNotifications(t *testing.T) {
	r := testRunner(t)

	var mu sync.Mutex
	var streamed strings.Builder
	notify := notifyFunc(func(method string, params any) {
		if method != "notifications/message" {
			return
		}
		b, _ := json.Marshal(params)
		var lm struct {
			Data outputChunk `json:"data"`
		}
		json.Unmarshal(b, &lm)
		mu.Lock()
		streamed.WriteString(lm.Data.Text)
		mu.Unlock()
	})

	params, _ := json.Marshal(map[string]any{
		"name":      "exec",
		"arguments": map[string]any{"command": "echo streamtest"},
		"_meta":     map[string]any{"progressToken": "tok-1"},
	})
	msg := &jsonrpcMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}

	resp := handleMessage(r, msg, newCancelRegistry(), readyState(), notify)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected response: %+v", resp)
	}

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(streamed.String(), "streamtest") {
		t.Errorf("streamed notifications = %q, want to contain %q", streamed.String(), "streamtest")
	}
}

// TestNoStreamingWithoutProgressToken confirms output is NOT streamed when the
// client did not opt in (no progressToken) -- the result still returns normally.
func TestNoStreamingWithoutProgressToken(t *testing.T) {
	r := testRunner(t)
	got := false
	notify := notifyFunc(func(method string, _ any) {
		if method == "notifications/message" {
			got = true
		}
	})
	params, _ := json.Marshal(map[string]any{
		"name":      "exec",
		"arguments": map[string]any{"command": "echo plain"},
	})
	msg := &jsonrpcMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params}
	resp := handleMessage(r, msg, newCancelRegistry(), readyState(), notify)
	if resp == nil || resp.Error != nil {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got {
		t.Error("output was streamed without a progressToken opt-in")
	}
}
