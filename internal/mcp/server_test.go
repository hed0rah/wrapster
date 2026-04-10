package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/runner"
)

func testRunner(t *testing.T) *runner.Runner {
	t.Helper()
	pol := &policy.Policy{
		Defaults: policy.HostPolicy{
			AllowedCommands: []policy.CommandRule{
				{Command: "uptime", Description: "System uptime"},
				{Command: "df", ArgsPattern: "-[hTi]+", Description: "Disk usage"},
			},
			DeniedPatterns: []string{`\bsudo\b`},
		},
		Hosts: map[string]policy.HostPolicy{
			"prod-web": {
				User: "deploy",
				AllowedCommands: []policy.CommandRule{
					{Command: "nginx", ArgsPattern: "-t", Description: "Nginx config test"},
				},
			},
		},
	}

	// Compile all rules
	for i := range pol.Defaults.AllowedCommands {
		if err := pol.Defaults.AllowedCommands[i].Compile(); err != nil {
			t.Fatal(err)
		}
	}
	for name, hp := range pol.Hosts {
		for i := range hp.AllowedCommands {
			if err := hp.AllowedCommands[i].Compile(); err != nil {
				t.Fatal(err)
			}
		}
		pol.Hosts[name] = hp
	}

	logger, _ := audit.NewLogger("-")
	return &runner.Runner{Policy: pol, Logger: logger, OutputStats: &output.Tracker{}}
}

func sendRPC(t *testing.T, r *runner.Runner, method string, params any) *jsonrpcResponse {
	t.Helper()
	var paramsJSON json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		paramsJSON = b
	}

	msg := &jsonrpcMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  method,
		Params:  paramsJSON,
	}
	return handleMessage(r, msg, newCancelRegistry())
}

func TestInitialize(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "initialize", nil)

	if resp == nil {
		t.Fatal("expected response, got nil")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	b, _ := json.Marshal(resp.Result)
	var result initializeResult
	json.Unmarshal(b, &result)

	if result.ServerInfo.Name != "wrapster" {
		t.Errorf("server name = %q, want wrapster", result.ServerInfo.Name)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("protocol version = %q, want 2024-11-05", result.ProtocolVersion)
	}
}

func TestToolsList(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "tools/list", nil)

	b, _ := json.Marshal(resp.Result)
	var result toolsListResult
	json.Unmarshal(b, &result)

	if len(result.Tools) != 9 {
		t.Fatalf("expected 9 tools, got %d", len(result.Tools))
	}

	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"exec", "ssh_exec", "ssh_validate", "ssh_list_allowed", "batch_exec", "get_stats"} {
		if !names[expected] {
			t.Errorf("missing tool %q", expected)
		}
	}
}

func TestToolCallValidate(t *testing.T) {
	r := testRunner(t)

	tests := []struct {
		name    string
		host    string
		command string
		allowed bool
	}{
		{"allowed uptime", "prod-web", "uptime", true},
		{"allowed nginx", "prod-web", "nginx -t", true},
		{"denied ls", "prod-web", "ls", false},
		{"denied sudo", "prod-web", "sudo uptime", false},
		{"denied rm", "prod-web", "rm -rf /", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendRPC(t, r, "tools/call", callToolParams{
				Name: "ssh_validate",
				Arguments: map[string]any{
					"host":    tt.host,
					"command": tt.command,
				},
			})

			b, _ := json.Marshal(resp.Result)
			var result toolResult
			json.Unmarshal(b, &result)

			if len(result.Content) == 0 {
				t.Fatal("no content in response")
			}

			var runResult runner.RunResult
			json.Unmarshal([]byte(result.Content[0].Text), &runResult)

			if runResult.Allowed != tt.allowed {
				t.Errorf("allowed = %v, want %v (reason: %s)", runResult.Allowed, tt.allowed, runResult.Reason)
			}
		})
	}
}

func TestToolCallListAllowed(t *testing.T) {
	r := testRunner(t)

	resp := sendRPC(t, r, "tools/call", callToolParams{
		Name: "ssh_list_allowed",
		Arguments: map[string]any{
			"host": "prod-web",
		},
	})

	b, _ := json.Marshal(resp.Result)
	var result toolResult
	json.Unmarshal(b, &result)

	text := result.Content[0].Text
	if !strings.Contains(text, "uptime") {
		t.Error("expected 'uptime' in allowed list")
	}
	if !strings.Contains(text, "nginx") {
		t.Error("expected 'nginx' in allowed list")
	}
}

func TestToolCallMissingParams(t *testing.T) {
	r := testRunner(t)

	resp := sendRPC(t, r, "tools/call", callToolParams{
		Name:      "ssh_exec",
		Arguments: map[string]any{"host": "prod-web"},
	})

	b, _ := json.Marshal(resp.Result)
	var result toolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected IsError for missing command param")
	}
}

func TestUnknownTool(t *testing.T) {
	r := testRunner(t)

	resp := sendRPC(t, r, "tools/call", callToolParams{
		Name:      "nonexistent",
		Arguments: map[string]any{},
	})

	b, _ := json.Marshal(resp.Result)
	var result toolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected IsError for unknown tool")
	}
}

func TestUnknownMethod(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "bogus/method", nil)

	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("error code = %d, want -32601", resp.Error.Code)
	}
}

func TestPing(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "ping", nil)
	if resp == nil || resp.Error != nil {
		t.Fatal("ping should succeed")
	}
}

func TestNotificationNoResponse(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "notifications/initialized", nil)
	if resp != nil {
		t.Error("notifications should return nil (no response)")
	}
}

func TestServeStdio(t *testing.T) {
	r := testRunner(t)

	// Build a sequence of JSON-RPC messages
	messages := []jsonrpcMessage{
		{JSONRPC: "2.0", ID: 1, Method: "initialize"},
		{JSONRPC: "2.0", Method: "notifications/initialized"},
		{JSONRPC: "2.0", ID: 2, Method: "tools/list"},
		{JSONRPC: "2.0", ID: 3, Method: "ping"},
	}

	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, msg := range messages {
		enc.Encode(msg)
	}

	// Redirect stdin/stdout for the Serve function
	oldStdin := os.Stdin
	oldStdout := os.Stdout
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
	}()

	stdinR, stdinW, _ := os.Pipe()
	stdoutR, stdoutW, _ := os.Pipe()

	os.Stdin = stdinR
	os.Stdout = stdoutW

	// Write input and close
	go func() {
		stdinW.Write(input.Bytes())
		stdinW.Close()
	}()

	// Run server
	done := make(chan error, 1)
	go func() {
		done <- Serve(r)
	}()

	err := <-done
	stdoutW.Close()

	if err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	// Read responses
	var responses []jsonrpcResponse
	scanner := bufio.NewScanner(stdoutR)
	for scanner.Scan() {
		var resp jsonrpcResponse
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			t.Fatalf("bad response JSON: %v", err)
		}
		responses = append(responses, resp)
	}

	// should have 3 responses (initialize, tools/list, ping -- notification produces none)
	if len(responses) != 3 {
		t.Fatalf("expected 3 responses, got %d", len(responses))
	}

	// Verify IDs match
	expectedIDs := []float64{1, 2, 3}
	for i, resp := range responses {
		id, ok := resp.ID.(float64)
		if !ok || id != expectedIDs[i] {
			t.Errorf("response %d: id = %v, want %v", i, resp.ID, expectedIDs[i])
		}
	}

	io.Copy(io.Discard, stdoutR)
}
