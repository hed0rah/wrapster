package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

// readyState returns a connState already in the READY phase,
// suitable for tests that skip the handshake and test tool behavior directly.
func readyState() *connState {
	cs := &connState{}
	cs.set(stateReady)
	return cs
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
	noop := notifyFunc(func(string, any) {})
	return handleMessage(r, msg, newCancelRegistry(), readyState(), noop)
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
	if result.ProtocolVersion != "2025-06-18" {
		t.Errorf("protocol version = %q, want 2025-06-18", result.ProtocolVersion)
	}
}

func TestVersionNegotiation(t *testing.T) {
	tests := []struct {
		name     string
		client   string
		expected string
	}{
		{"empty falls back to latest", "", "2025-06-18"},
		{"2024-11-05 echoed", "2024-11-05", "2024-11-05"},
		{"2025-03-26 echoed", "2025-03-26", "2025-03-26"},
		{"2025-06-18 echoed", "2025-06-18", "2025-06-18"},
		{"unknown falls back to latest", "9999-01-01", "2025-06-18"},
	}

	r := testRunner(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendRPC(t, r, "initialize", initializeParams{
				ProtocolVersion: tt.client,
			})
			b, _ := json.Marshal(resp.Result)
			var result initializeResult
			json.Unmarshal(b, &result)
			if result.ProtocolVersion != tt.expected {
				t.Errorf("got %q, want %q", result.ProtocolVersion, tt.expected)
			}
		})
	}
}

func TestToolsList(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "tools/list", nil)

	b, _ := json.Marshal(resp.Result)
	var result toolsListResult
	json.Unmarshal(b, &result)

	if len(result.Tools) != 11 {
		t.Fatalf("expected 11 tools, got %d", len(result.Tools))
	}

	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"exec", "ssh_exec", "ssh_validate", "batch_exec", "host_info", "reach", "discover_hosts", "grep_output", "cache_invalidate", "find_files", "grep_files"} {
		if !names[expected] {
			t.Errorf("missing tool %q", expected)
		}
	}
	// verify dropped tools are gone
	for _, dropped := range []string{"ssh_list_allowed", "get_output", "get_stats"} {
		if names[dropped] {
			t.Errorf("tool %q should have been removed (migrated to resource)", dropped)
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

func TestDroppedToolReturnsUnknown(t *testing.T) {
	r := testRunner(t)

	// ssh_list_allowed was migrated to a resource; calling as tool should fail
	resp := sendRPC(t, r, "tools/call", callToolParams{
		Name:      "ssh_list_allowed",
		Arguments: map[string]any{"host": "prod-web"},
	})

	b, _ := json.Marshal(resp.Result)
	var result toolResult
	json.Unmarshal(b, &result)

	if !result.IsError {
		t.Error("expected IsError for dropped tool")
	}
}

func TestToolCallMissingParams(t *testing.T) {
	r := testRunner(t)

	resp := sendRPC(t, r, "tools/call", callToolParams{
		Name:      "ssh_exec",
		Arguments: map[string]any{"host": "prod-web"},
	})

	// missing required params now return -32602 JSON-RPC error (protocol level)
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error for missing command param")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
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

func TestStateMachineGating(t *testing.T) {
	cs := &connState{} // starts at stateConnected

	// tools/list before initialize should be rejected
	msg := &jsonrpcMessage{JSONRPC: "2.0", ID: 1, Method: "tools/list"}
	reject := gateMethod(cs, msg)
	if reject == nil {
		t.Fatal("expected rejection for tools/list before initialize")
	}
	if reject.Error == nil || reject.Error.Code != -32600 {
		t.Fatalf("expected -32600, got %v", reject.Error)
	}

	// ping should always be allowed
	msg = &jsonrpcMessage{JSONRPC: "2.0", ID: 2, Method: "ping"}
	if reject = gateMethod(cs, msg); reject != nil {
		t.Fatal("ping should be allowed in connected state")
	}

	// initialize transitions to initializing
	msg = &jsonrpcMessage{JSONRPC: "2.0", ID: 3, Method: "initialize"}
	if reject = gateMethod(cs, msg); reject != nil {
		t.Fatal("initialize should be allowed in connected state")
	}
	if cs.get() != stateInitializing {
		t.Fatal("state should be initializing after initialize")
	}

	// tools/list still rejected in initializing
	msg = &jsonrpcMessage{JSONRPC: "2.0", ID: 4, Method: "tools/list"}
	if reject = gateMethod(cs, msg); reject == nil {
		t.Fatal("expected rejection for tools/list before notifications/initialized")
	}

	// notifications/initialized transitions to ready
	msg = &jsonrpcMessage{JSONRPC: "2.0", Method: "notifications/initialized"}
	if reject = gateMethod(cs, msg); reject != nil {
		t.Fatal("notifications/initialized should be allowed in initializing state")
	}
	if cs.get() != stateReady {
		t.Fatal("state should be ready after notifications/initialized")
	}

	// everything allowed in ready state
	msg = &jsonrpcMessage{JSONRPC: "2.0", ID: 5, Method: "tools/list"}
	if reject = gateMethod(cs, msg); reject != nil {
		t.Fatal("tools/list should be allowed in ready state")
	}
}

func TestProgressNotifications(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var received []progressNotification

	notify := notifyFunc(func(method string, params any) {
		if method == "notifications/progress" {
			if p, ok := params.(progressNotification); ok {
				mu.Lock()
				received = append(received, p)
				mu.Unlock()
			}
		}
	})

	token := "test-token-123"
	startProgress(ctx, token, notify)

	// wait ~2.5s to get the first emission (1s gate + first immediate + possibly a tick)
	time.Sleep(2500 * time.Millisecond)
	cancel()

	// small grace for goroutine cleanup
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	count := len(received)
	mu.Unlock()

	if count == 0 {
		t.Fatal("expected at least one progress notification")
	}

	mu.Lock()
	first := received[0]
	mu.Unlock()

	if first.ProgressToken != token {
		t.Errorf("progressToken = %v, want %q", first.ProgressToken, token)
	}
	if first.Progress <= 0 {
		t.Error("expected progress > 0")
	}
	if first.Message == "" {
		t.Error("expected non-empty message")
	}
}

func TestProgressSkipsNilToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	called := false
	notify := notifyFunc(func(string, any) { called = true })

	startProgress(ctx, nil, notify)
	time.Sleep(1500 * time.Millisecond)
	cancel()

	if called {
		t.Error("should not emit progress when token is nil")
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

	// Drain stdout concurrently to prevent pipe-buffer deadlock when responses
	// are large (tools/list with many tools exceeds the ~4KB Windows pipe buffer).
	var rawOut bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		io.Copy(&rawOut, stdoutR)
		close(readDone)
	}()

	err := <-done
	stdoutW.Close()
	<-readDone

	if err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	// Read responses
	var responses []jsonrpcResponse
	scanner := bufio.NewScanner(&rawOut)
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

func TestResourcesList(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/list", nil)

	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/list failed: %v", resp)
	}

	b, _ := json.Marshal(resp.Result)
	var result resourcesListResult
	json.Unmarshal(b, &result)

	// should have at least stats + policy + per-host resources
	if len(result.Resources) < 2 {
		t.Errorf("expected at least 2 resources, got %d", len(result.Resources))
	}

	// verify static resources
	uris := map[string]bool{}
	for _, res := range result.Resources {
		uris[res.URI] = true
	}
	if !uris["stats://session"] {
		t.Error("missing stats://session resource")
	}
	if !uris["policy://current"] {
		t.Error("missing policy://current resource")
	}

	// should have host-specific resources for prod-web
	if !uris["host://prod-web/allowed"] {
		t.Error("missing host://prod-web/allowed resource")
	}
	if !uris["host://prod-web/info"] {
		t.Error("missing host://prod-web/info resource")
	}

	// should have URI templates
	if len(result.ResourceTemplates) == 0 {
		t.Error("expected at least one resource template")
	}
}

func TestResourcesReadStats(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/read", resourcesReadParams{URI: "stats://session"})

	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/read stats failed: %v", resp)
	}

	b, _ := json.Marshal(resp.Result)
	var result resourcesReadResult
	json.Unmarshal(b, &result)

	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(result.Contents))
	}
	if result.Contents[0].URI != "stats://session" {
		t.Errorf("URI = %q, want stats://session", result.Contents[0].URI)
	}
	if result.Contents[0].MimeType != "application/json" {
		t.Errorf("mimeType = %q, want application/json", result.Contents[0].MimeType)
	}
}

func TestResourcesReadPolicy(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/read", resourcesReadParams{URI: "policy://current"})

	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/read policy failed: %v", resp)
	}

	b, _ := json.Marshal(resp.Result)
	var result resourcesReadResult
	json.Unmarshal(b, &result)

	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(result.Contents))
	}

	// should contain host info
	if !strings.Contains(result.Contents[0].Text, "prod-web") {
		t.Error("policy resource should mention prod-web host")
	}
}

func TestResourcesReadHostAllowed(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/read", resourcesReadParams{URI: "host://prod-web/allowed"})

	if resp == nil || resp.Error != nil {
		t.Fatalf("resources/read host allowed failed: %v", resp)
	}

	b, _ := json.Marshal(resp.Result)
	var result resourcesReadResult
	json.Unmarshal(b, &result)

	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(result.Contents))
	}
	text := result.Contents[0].Text
	if !strings.Contains(text, "uptime") {
		t.Error("expected 'uptime' in allowed commands")
	}
	if !strings.Contains(text, "nginx") {
		t.Error("expected 'nginx' in allowed commands")
	}
}

func TestResourcesReadUnknown(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/read", resourcesReadParams{URI: "bogus://nope"})

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown resource URI")
	}
	if resp.Error.Code != -32002 {
		t.Errorf("error code = %d, want -32002", resp.Error.Code)
	}
}

func TestResourcesReadMissingURI(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "resources/read", resourcesReadParams{URI: ""})

	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected error for missing URI")
	}
	if resp.Error.Code != -32602 {
		t.Errorf("error code = %d, want -32602", resp.Error.Code)
	}
}

func TestPromptsList(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "prompts/list", nil)

	if resp == nil || resp.Error != nil {
		t.Fatalf("prompts/list failed: %v", resp)
	}

	b, _ := json.Marshal(resp.Result)
	var result promptsListResult
	json.Unmarshal(b, &result)

	if len(result.Prompts) != 3 {
		t.Fatalf("expected 3 prompts, got %d", len(result.Prompts))
	}

	names := map[string]bool{}
	for _, p := range result.Prompts {
		names[p.Name] = true
	}
	for _, expected := range []string{"diagnose-host", "compare-hosts", "safety-review"} {
		if !names[expected] {
			t.Errorf("missing prompt %q", expected)
		}
	}
}

func TestPromptsGet(t *testing.T) {
	r := testRunner(t)

	tests := []struct {
		name      string
		prompt    string
		args      map[string]string
		wantErr   bool
		contains  string
	}{
		{
			name:     "diagnose prod-web",
			prompt:   "diagnose-host",
			args:     map[string]string{"host": "prod-web"},
			contains: "prod-web",
		},
		{
			name:     "compare two hosts",
			prompt:   "compare-hosts",
			args:     map[string]string{"host_a": "prod-web", "host_b": "staging"},
			contains: "prod-web",
		},
		{
			name:     "safety review rm",
			prompt:   "safety-review",
			args:     map[string]string{"host": "prod-web", "command": "rm -rf /"},
			contains: "rm -rf /",
		},
		{
			name:    "diagnose missing arg",
			prompt:  "diagnose-host",
			args:    map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sendRPC(t, r, "prompts/get", promptsGetParams{
				Name:      tt.prompt,
				Arguments: tt.args,
			})
			if tt.wantErr {
				if resp.Error == nil {
					t.Fatal("expected error")
				}
				return
			}
			if resp.Error != nil {
				t.Fatalf("unexpected error: %v", resp.Error)
			}

			b, _ := json.Marshal(resp.Result)
			var result promptsGetResult
			json.Unmarshal(b, &result)

			if len(result.Messages) == 0 {
				t.Fatal("expected at least one message")
			}
			if result.Messages[0].Role != "user" {
				t.Errorf("role = %q, want user", result.Messages[0].Role)
			}
			if tt.contains != "" && !strings.Contains(result.Messages[0].Content.Text, tt.contains) {
				t.Errorf("message text does not contain %q", tt.contains)
			}
		})
	}
}

func TestPromptsGetUnknown(t *testing.T) {
	r := testRunner(t)
	resp := sendRPC(t, r, "prompts/get", promptsGetParams{Name: "nonexistent"})

	if resp.Error == nil {
		t.Fatal("expected error for unknown prompt")
	}
}
