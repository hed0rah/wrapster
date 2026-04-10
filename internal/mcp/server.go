package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/cache"
	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/runner"
)

// Serve runs an MCP server over stdio. Blocks until stdin closes.
func Serve(r *runner.Runner) error {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	var encMu sync.Mutex
	cr := newCancelRegistry()

	for {
		msg, err := readMessage(reader)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			encMu.Lock()
			writeError(encoder, nil, -32700, "parse error: "+err.Error())
			encMu.Unlock()
			continue
		}

		// notifications/cancelled: cancel an in-flight tool call by request ID.
		// With concurrent dispatch below, this arrives on the read loop while
		// the tool call goroutine is still running -- the cancel propagates
		// immediately to exec.CommandContext.
		if msg.Method == "notifications/cancelled" {
			var p struct {
				RequestID any    `json:"requestId"`
				Reason    string `json:"reason,omitempty"`
			}
			if msg.Params != nil {
				_ = json.Unmarshal(msg.Params, &p)
			}
			if p.RequestID != nil {
				cr.cancel(p.RequestID)
			}
			continue // notification, no response
		}

		// Dispatch tools/call concurrently so the read loop stays unblocked
		// and can process notifications/cancelled while execs are running.
		// Multiple tool calls (e.g. to different SSH hosts) execute in parallel.
		if msg.Method == "tools/call" {
			go func(m *jsonrpcMessage) {
				response := handleMessage(r, m, cr)
				if response != nil {
					encMu.Lock()
					if err := encoder.Encode(response); err != nil {
						fmt.Fprintf(os.Stderr, "mcp: write error: %v\n", err)
					}
					encMu.Unlock()
				}
			}(msg)
			continue
		}

		// Non-tool-call requests (initialize, tools/list, ping) are fast;
		// handle synchronously so they don't race with concurrent tool calls.
		response := handleMessage(r, msg, cr)
		if response != nil {
			encMu.Lock()
			if err := encoder.Encode(response); err != nil {
				fmt.Fprintf(os.Stderr, "mcp: write error: %v\n", err)
			}
			encMu.Unlock()
		}
	}
}

// cancelRegistry tracks cancellable contexts for in-flight tool calls.
// Keyed by JSON-RPC request ID (any -- may be string, float64, or nil).
// Safe for concurrent use by the read loop and goroutine-dispatched handlers.
type cancelRegistry struct {
	mu      sync.Mutex
	cancels map[any]context.CancelFunc
}

func newCancelRegistry() *cancelRegistry {
	return &cancelRegistry{cancels: make(map[any]context.CancelFunc)}
}

func (cr *cancelRegistry) register(id any, cancel context.CancelFunc) {
	cr.mu.Lock()
	cr.cancels[id] = cancel
	cr.mu.Unlock()
}

func (cr *cancelRegistry) cancel(id any) bool {
	cr.mu.Lock()
	fn, ok := cr.cancels[id]
	cr.mu.Unlock()
	if ok {
		fn()
	}
	return ok
}

func (cr *cancelRegistry) deregister(id any) {
	cr.mu.Lock()
	delete(cr.cancels, id)
	cr.mu.Unlock()
}

// JSON-RPC types

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP-specific types

type initializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    capabilities `json:"capabilities"`
	ServerInfo      serverInfo   `json:"serverInfo"`
}

type capabilities struct {
	Tools      *toolsCap  `json:"tools,omitempty"`
	Extensions *extensions `json:"extensions,omitempty"`
}

type toolsCap struct {
	ListChanged bool `json:"listChanged"`
}

// extensions advertises wrapster-specific transport capabilities to the client.
// Clients that don't understand this field will ignore it. Features guarded by
// these flags should degrade gracefully when unsupported.
type extensions struct {
	// GzipSSE: SSE stream is gzip-compressed when client sends Accept-Encoding: gzip.
	GzipSSE bool `json:"gzip_sse"`
	// RequestCancellation: server honours notifications/cancelled to kill in-flight execs.
	RequestCancellation bool `json:"request_cancellation"`
	// ConcurrentDispatch: server can process multiple tool calls in parallel (stdio).
	ConcurrentDispatch bool `json:"concurrent_dispatch"`
	// OutputHandles: large outputs return a buf_id handle; use get_output to page them.
	OutputHandles bool `json:"output_handles"`
}

// serverExtensions is the static extension capability set for this build.
var serverExtensions = &extensions{
	GzipSSE:             true,
	RequestCancellation: true,
	ConcurrentDispatch:  true,
	OutputHandles:       false, // not yet implemented
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// initializeParams is the client-side initialize request body.
type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	ClientInfo      *serverInfo     `json:"clientInfo,omitempty"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
}

type toolsListResult struct {
	Tools []toolDef `json:"tools"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type callToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Message handling

func handleMessage(r *runner.Runner, msg *jsonrpcMessage, cr *cancelRegistry) *jsonrpcResponse {
	switch msg.Method {
	case "initialize":
		// Parse client params for logging; we advertise the same extensions regardless.
		var params initializeParams
		if msg.Params != nil {
			_ = json.Unmarshal(msg.Params, &params) // best-effort; ignore parse errors
		}
		return respond(msg.ID, initializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities:    capabilities{Tools: &toolsCap{}, Extensions: serverExtensions},
			ServerInfo:      serverInfo{Name: "wrapster", Version: "0.1.0"},
		})

	case "notifications/initialized":
		return nil // notification, no response

	case "tools/list":
		return respond(msg.ID, toolsListResult{Tools: toolDefinitions()})

	case "tools/call":
		var params callToolParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return respondError(msg.ID, -32602, "invalid params: "+err.Error())
		}
		// Create a cancellable context for this call and register it.
		ctx, cancel := context.WithCancel(context.Background())
		cr.register(msg.ID, cancel)
		defer func() {
			cancel()
			cr.deregister(msg.ID)
		}()
		return handleToolCall(r, msg.ID, params, ctx)

	case "ping":
		return respond(msg.ID, map[string]any{})

	default:
		// Unknown methods get method-not-found per JSON-RPC
		return respondError(msg.ID, -32601, "method not found: "+msg.Method)
	}
}

func handleToolCall(r *runner.Runner, id any, params callToolParams, ctx context.Context) *jsonrpcResponse {
	switch params.Name {
	case "exec":
		command, _ := params.Arguments["command"].(string)
		nocache, _ := params.Arguments["nocache"].(bool)
		if command == "" {
			return respond(id, toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "command is required"}},
			})
		}

		if !nocache && r.ResultCache != nil {
			if hit := r.ResultCache.Get("local", command); hit != nil {
				return respond(id, toolResult{
					Content: []contentBlock{{Type: "text", Text: formatCacheHit(hit)}},
				})
			}
		}
		result := r.ExecLocal(ctx, command)
		processOutput(r, &result)
		cacheResult(r, "local", command, &result)
		out, _ := json.MarshalIndent(result, "", "  ")
		return respond(id, toolResult{
			IsError: !result.Allowed || result.Error != "",
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_exec":
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		nocache, _ := params.Arguments["nocache"].(bool)
		if host == "" || command == "" {
			return respond(id, toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "host and command are required"}},
			})
		}

		if !nocache && r.ResultCache != nil {
			if hit := r.ResultCache.Get(host, command); hit != nil {
				return respond(id, toolResult{
					Content: []contentBlock{{Type: "text", Text: formatCacheHit(hit)}},
				})
			}
		}
		result := r.Exec(ctx, host, command, nil)
		processOutput(r, &result)
		cacheResult(r, host, command, &result)
		out, _ := json.MarshalIndent(result, "", "  ")
		return respond(id, toolResult{
			IsError: !result.Allowed || result.Error != "",
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_validate":
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		if host == "" || command == "" {
			return respond(id, toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "host and command are required"}},
			})
		}

		result := r.Validate(host, command)
		out, _ := json.MarshalIndent(result, "", "  ")
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_list_allowed":
		host, _ := params.Arguments["host"].(string)
		if host == "" {
			return respond(id, toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "host is required"}},
			})
		}

		hp := r.ListAllowed(host)
		text := formatAllowed(host, hp)
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: text}},
		})

	case "batch_exec":
		host, _ := params.Arguments["host"].(string)
		commandsRaw, _ := params.Arguments["commands"].([]any)
		if host == "" || len(commandsRaw) == 0 {
			return respond(id, toolResult{
				IsError: true,
				Content: []contentBlock{{Type: "text", Text: "host and commands are required"}},
			})
		}
		commands := make([]string, len(commandsRaw))
		for i, c := range commandsRaw {
			s, _ := c.(string)
			if s == "" {
				return respond(id, toolResult{
					IsError: true,
					Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("commands[%d] is empty or not a string", i)}},
				})
			}
			commands[i] = s
		}

		var br runner.BatchResult
		if host == "local" {
			br = r.BatchExecLocal(ctx, commands)
		} else {
			br = r.BatchExec(ctx, host, commands, nil)
		}

		// apply output processing to each result
		for i := range br.Results {
			processOutput(r, &br.Results[i])
		}

		out, _ := json.MarshalIndent(br, "", "  ")
		hasError := br.Failed > 0 || br.Blocked > 0
		return respond(id, toolResult{
			IsError: hasError,
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "cache_invalidate":
		if r.ResultCache == nil {
			return respond(id, toolResult{
				Content: []contentBlock{{Type: "text", Text: "result cache not enabled"}},
			})
		}
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		if host == "" && command == "" {
			r.ResultCache.Flush()
			return respond(id, toolResult{
				Content: []contentBlock{{Type: "text", Text: "cache flushed"}},
			})
		}
		r.ResultCache.Invalidate(host, command)
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("invalidated: %s %s", host, command)}},
		})

	case "get_stats":
		if r.OutputStats == nil {
			return respond(id, toolResult{
				Content: []contentBlock{{Type: "text", Text: "output stats not enabled"}},
			})
		}
		s := r.OutputStats.Snapshot()
		out, _ := json.MarshalIndent(map[string]any{
			"calls":       s.Calls,
			"raw_bytes":   s.RawBytes,
			"output_bytes": s.OutBytes,
			"savings_pct": fmt.Sprintf("%.1f", s.SavingsPct()),
		}, "", "  ")
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	default:
		return respond(id, toolResult{
			IsError: true,
			Content: []contentBlock{{Type: "text", Text: "unknown tool: " + params.Name}},
		})
	}
}

// cacheResult stores a successful exec result in the ResultCache.
func cacheResult(r *runner.Runner, host, command string, result *runner.RunResult) {
	if r.ResultCache == nil || !result.Allowed || result.Error != "" || result.TimedOut {
		return
	}
	r.ResultCache.Put(host, command, &cache.Entry{
		Hash:     audit.HashOutput(result.Stdout, result.Stderr),
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
	})
}

// formatCacheHit formats a cache hit response for the model.
func formatCacheHit(e *cache.Entry) string {
	r := runner.RunResult{
		Allowed:   true,
		Reason:    "served from result cache",
		Stdout:    e.Stdout,
		Stderr:    e.Stderr,
		ExitCode:  e.ExitCode,
		Cached:    true,
		CacheHash: e.Hash,
	}
	out, _ := json.MarshalIndent(r, "", "  ")
	return string(out)
}

// processOutput applies ANSI stripping and truncation to stdout/stderr.
func processOutput(r *runner.Runner, result *runner.RunResult) {
	if !result.Allowed || (result.Stdout == "" && result.Stderr == "") {
		return
	}

	cfg := r.OutputConfig()
	rawLen := len(result.Stdout) + len(result.Stderr)

	if result.Stdout != "" {
		result.Stdout = output.Process(result.Stdout, cfg)
	}
	if result.Stderr != "" {
		result.Stderr = output.Process(result.Stderr, cfg)
	}

	outLen := len(result.Stdout) + len(result.Stderr)
	if r.OutputStats != nil {
		r.OutputStats.Record(rawLen, outLen)
	}
}

func toolDefinitions() []toolDef {
	return []toolDef{
		{
			Name:        "exec",
			Description: "Execute a command on the local machine. Commands pass through security filters that block shell escapes, destructive operations, and data exfiltration. Use this for general-purpose shell commands.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{
						"type":        "string",
						"description": "Shell command to execute locally",
					},
					"nocache": map[string]any{
						"type":        "boolean",
						"description": "Bypass result cache and force re-execution",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "ssh_exec",
			Description: "Execute a command on a remote host via SSH. The command must be allowed by the security policy. Returns stdout, stderr, exit code, and execution metadata.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host name (as defined in the policy file)",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command to execute on the remote host",
					},
					"nocache": map[string]any{
						"type":        "boolean",
						"description": "Bypass result cache and force re-execution",
					},
				},
				"required": []string{"host", "command"},
			},
		},
		{
			Name:        "ssh_validate",
			Description: "Check if a command would be allowed on a host without executing it. Use this to verify before running commands.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host name",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command to validate",
					},
				},
				"required": []string{"host", "command"},
			},
		},
		{
			Name:        "ssh_list_allowed",
			Description: "List all commands that are allowed on a given host. Use this to discover what operations are available.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host name",
					},
				},
				"required": []string{"host"},
			},
		},
		{
			Name:        "batch_exec",
			Description: "Execute multiple commands in a single call. Each command is individually validated. For SSH hosts, commands share a pooled connection for lower latency. Use 'local' as host for local commands.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host name, or 'local' for local execution",
					},
					"commands": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Array of commands to execute sequentially",
					},
				},
				"required": []string{"host", "commands"},
			},
		},
		{
			Name:        "cache_invalidate",
			Description: "Invalidate a specific result cache entry or flush the entire cache. Omit host and command to flush everything.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Host name of the entry to invalidate",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command string of the entry to invalidate",
					},
				},
			},
		},
		{
			Name:        "get_stats",
			Description: "Get output processing statistics for this session. Shows total calls, raw bytes, processed bytes, and savings percentage.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
	}
}

func formatAllowed(host string, hp policy.HostPolicy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Allowed commands for %q:\n\n", host)
	if len(hp.AllowedCommands) == 0 {
		b.WriteString("  (none)\n")
		return b.String()
	}
	for _, rule := range hp.AllowedCommands {
		desc := rule.Description
		if desc == "" {
			desc = "(no description)"
		}
		if rule.Command != "" {
			args := "*"
			if rule.ArgsPattern != "" {
				args = rule.ArgsPattern
			}
			fmt.Fprintf(&b, "  %-20s args: %-20s %s\n", rule.Command, args, desc)
		} else if rule.Pattern != "" {
			fmt.Fprintf(&b, "  /%s/  %s\n", rule.Pattern, desc)
		}
	}
	if len(hp.DeniedPatterns) > 0 {
		b.WriteString("\nDenied patterns:\n")
		for _, p := range hp.DeniedPatterns {
			fmt.Fprintf(&b, "  /%s/\n", p)
		}
	}

	// GTFOBins audit
	warnings := policy.AuditPolicy(hp)
	if len(warnings) > 0 {
		b.WriteString("\nGTFOBins warnings:\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "  %s\n", w)
		}
	}

	return b.String()
}

// I/O helpers

func readMessage(reader *bufio.Reader) (*jsonrpcMessage, error) {
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var msg jsonrpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

func respond(id any, result any) *jsonrpcResponse {
	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func respondError(id any, code int, message string) *jsonrpcResponse {
	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	}
}

func writeError(enc *json.Encoder, id any, code int, message string) {
	enc.Encode(respondError(id, code, message))
}
