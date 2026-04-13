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
	"sync/atomic"
	"time"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/cache"
	"github.com/hed0rah/wrapster/internal/hostinfo"
	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/runner"
)

// notifyFunc sends a JSON-RPC notification to the client. Used by tool handlers
// to emit progress updates mid-flight. Must be safe for concurrent use.
type notifyFunc func(method string, params any)

// connState tracks the MCP connection lifecycle.
// CONNECTED -> INITIALIZING -> READY
type connState struct {
	state atomic.Int32 // 0=connected, 1=initializing, 2=ready
}

const (
	stateConnected    int32 = 0
	stateInitializing int32 = 1
	stateReady        int32 = 2
)

func (cs *connState) get() int32           { return cs.state.Load() }
func (cs *connState) set(s int32)          { cs.state.Store(s) }
func (cs *connState) isReady() bool        { return cs.state.Load() == stateReady }

// Version is set at build time via ldflags. Falls back to "dev".
var Version = "dev"

// supportedVersions lists MCP protocol versions this server can speak.
var supportedVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
}

const defaultVersion = "2024-11-05"

// negotiateVersion returns the client's requested version if we support it,
// otherwise falls back to the default. Logs a warning to stderr on mismatch.
func negotiateVersion(clientVersion string) string {
	if clientVersion == "" {
		return defaultVersion
	}
	if supportedVersions[clientVersion] {
		return clientVersion
	}
	fmt.Fprintf(os.Stderr, "mcp: client requested unsupported protocol version %q, using %s\n", clientVersion, defaultVersion)
	return defaultVersion
}

// Serve runs an MCP server over stdio. Blocks until stdin closes.
func Serve(r *runner.Runner) error {
	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	var encMu sync.Mutex
	cr := newCancelRegistry()
	cs := &connState{} // starts at stateConnected

	send := func(resp *jsonrpcResponse) {
		if resp == nil {
			return
		}
		encMu.Lock()
		if err := encoder.Encode(resp); err != nil {
			fmt.Fprintf(os.Stderr, "mcp: write error: %v\n", err)
		}
		encMu.Unlock()
	}

	// notify emits a JSON-RPC notification (no ID) through the same
	// serialized write path as responses. Used for progress updates.
	notify := notifyFunc(func(method string, params any) {
		encMu.Lock()
		encoder.Encode(jsonrpcNotification{JSONRPC: "2.0", Method: method, Params: params})
		encMu.Unlock()
	})

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

		// State machine gate: enforce CONNECTED -> INITIALIZING -> READY.
		if reject := gateMethod(cs, msg); reject != nil {
			send(reject)
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
				send(handleMessage(r, m, cr, cs, notify))
			}(msg)
			continue
		}

		// Non-tool-call requests (initialize, tools/list, ping) are fast;
		// handle synchronously so they don't race with concurrent tool calls.
		send(handleMessage(r, msg, cr, cs, notify))
	}
}

// gateMethod enforces the MCP connection state machine. Returns an error
// response if the method is not legal in the current state, nil otherwise.
// Also advances state on initialize and notifications/initialized.
func gateMethod(cs *connState, msg *jsonrpcMessage) *jsonrpcResponse {
	state := cs.get()

	switch state {
	case stateConnected:
		// only initialize and ping are legal before handshake
		if msg.Method == "initialize" {
			cs.set(stateInitializing)
			return nil
		}
		if msg.Method == "ping" {
			return nil
		}
		return respondError(msg.ID, -32600, "server not initialized: send initialize first")

	case stateInitializing:
		// waiting for notifications/initialized before accepting capability calls
		if msg.Method == "notifications/initialized" {
			cs.set(stateReady)
			return nil
		}
		if msg.Method == "ping" {
			return nil
		}
		return respondError(msg.ID, -32600, "server not ready: send notifications/initialized first")

	default: // stateReady
		return nil
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
	Tools        *toolsCap      `json:"tools,omitempty"`
	Experimental map[string]any `json:"experimental,omitempty"`
}

type toolsCap struct {
	ListChanged bool `json:"listChanged"`
}

// wrapsterExperimental is the static set of wrapster-specific capabilities
// advertised under capabilities.experimental.wrapster per MCP spec.
var wrapsterExperimental = map[string]any{
	"gzip_sse":             true,
	"request_cancellation": true,
	"concurrent_dispatch":  true,
	"output_handles":       true,
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
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations *toolAnnotations `json:"annotations,omitempty"`
}

// toolAnnotations provides advisory hints per MCP spec. Hosts use these for
// UI/security decisions but must not rely on them for enforcement.
type toolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

func boolPtr(b bool) *bool { return &b }

type callToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	Meta      *callMeta      `json:"_meta,omitempty"`
}

type callMeta struct {
	ProgressToken any `json:"progressToken,omitempty"`
}

// progressNotification is the params shape for notifications/progress.
type progressNotification struct {
	ProgressToken any   `json:"progressToken"`
	Progress      int64 `json:"progress"`
	Message       string `json:"message,omitempty"`
}

// jsonrpcNotification is a JSON-RPC notification (no ID, no response expected).
type jsonrpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// startProgress begins emitting notifications/progress every 2s for the given
// context. Returns immediately. The first emission is delayed 1s to skip
// sub-second calls. Stops when ctx is done. Never call after the tool result
// is sent -- cancel ctx first.
func startProgress(ctx context.Context, token any, notify notifyFunc) {
	if token == nil || notify == nil {
		return
	}
	go func() {
		start := time.Now()
		// delay first emission 1s to skip sub-second calls
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return
		}
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		// emit first progress immediately after the 1s gate
		elapsed := time.Since(start).Milliseconds()
		notify("notifications/progress", progressNotification{
			ProgressToken: token,
			Progress:      elapsed,
			Message:       fmt.Sprintf("running (%0.1fs elapsed)", float64(elapsed)/1000),
		})
		for {
			select {
			case <-ticker.C:
				elapsed = time.Since(start).Milliseconds()
				notify("notifications/progress", progressNotification{
					ProgressToken: token,
					Progress:      elapsed,
					Message:       fmt.Sprintf("running (%0.1fs elapsed)", float64(elapsed)/1000),
				})
			case <-ctx.Done():
				return
			}
		}
	}()
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

func handleMessage(r *runner.Runner, msg *jsonrpcMessage, cr *cancelRegistry, cs *connState, notify notifyFunc) *jsonrpcResponse {
	switch msg.Method {
	case "initialize":
		var params initializeParams
		if msg.Params != nil {
			_ = json.Unmarshal(msg.Params, &params)
		}
		version := negotiateVersion(params.ProtocolVersion)
		return respond(msg.ID, initializeResult{
			ProtocolVersion: version,
			Capabilities: capabilities{
				Tools:        &toolsCap{},
				Experimental: map[string]any{"wrapster": wrapsterExperimental},
			},
			ServerInfo: serverInfo{Name: "wrapster", Version: Version},
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
			cancel() // also stops any progress ticker
			cr.deregister(msg.ID)
		}()
		// Start progress notifications if client sent a progressToken.
		if params.Meta != nil && params.Meta.ProgressToken != nil {
			startProgress(ctx, params.Meta.ProgressToken, notify)
		}
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
			return respondError(id, -32602, "command is required")
		}

		if !nocache && r.ResultCache != nil {
			if hit := r.ResultCache.Get("local", command); hit != nil {
				return respond(id, toolResult{
					Content: []contentBlock{{Type: "text", Text: formatCacheHit(hit)}},
				})
			}
		}
		result := r.ExecLocal(ctx, command)
		bufID, truncated := processOutputWithBuf(r, &result)
		cacheResult(r, "local", command, &result)
		resp := execResponse{RunResult: result, BufID: bufID, Truncated: truncated}
		if bufID != "" {
			resp.BufBytes = r.BufStore.Len(bufID)
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		return respond(id, toolResult{
			IsError: !result.Allowed || result.Error != "",
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_exec":
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		nocache, _ := params.Arguments["nocache"].(bool)
		if host == "" || command == "" {
			return respondError(id, -32602, "host and command are required")
		}

		if !nocache && r.ResultCache != nil {
			if hit := r.ResultCache.Get(host, command); hit != nil {
				return respond(id, toolResult{
					Content: []contentBlock{{Type: "text", Text: formatCacheHit(hit)}},
				})
			}
		}
		result := r.Exec(ctx, host, command, nil)
		bufID, truncated := processOutputWithBuf(r, &result)
		cacheResult(r, host, command, &result)
		resp := execResponse{RunResult: result, BufID: bufID, Truncated: truncated}
		if bufID != "" {
			resp.BufBytes = r.BufStore.Len(bufID)
		}
		out, _ := json.MarshalIndent(resp, "", "  ")
		return respond(id, toolResult{
			IsError: !result.Allowed || result.Error != "",
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_validate":
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		if host == "" || command == "" {
			return respondError(id, -32602, "host and command are required")
		}

		result := r.Validate(host, command)
		out, _ := json.MarshalIndent(result, "", "  ")
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: string(out)}},
		})

	case "ssh_list_allowed":
		host, _ := params.Arguments["host"].(string)
		if host == "" {
			return respondError(id, -32602, "host is required")
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
			return respondError(id, -32602, "host and commands are required")
		}
		commands := make([]string, len(commandsRaw))
		for i, c := range commandsRaw {
			s, _ := c.(string)
			if s == "" {
				return respondError(id, -32602, fmt.Sprintf("commands[%d] is empty or not a string", i))
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

	case "host_info":
		host, _ := params.Arguments["host"].(string)
		refresh, _ := params.Arguments["refresh"].(bool)
		if host == "" {
			return respondError(id, -32602, "host is required")
		}
		if r.HostInfoCache == nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "host info cache not enabled"}}})
		}
		if !refresh {
			if info := r.HostInfoCache.Get(host); info != nil {
				return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: info.JSON()}}})
			}
		}
		info, err := hostinfo.Fingerprint(ctx, host, func(ctx context.Context, h, cmd string) (string, string, error) {
			return r.ExecRaw(ctx, h, cmd)
		})
		if err != nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "fingerprint failed: " + err.Error()}}})
		}
		r.HostInfoCache.Put(host, info)
		return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: info.JSON()}}})

	case "get_output":
		bufID, _ := params.Arguments["buf_id"].(string)
		if bufID == "" {
			return respondError(id, -32602, "buf_id is required")
		}
		if r.BufStore == nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "output buffer not enabled"}}})
		}
		offset := 0
		length := 8192
		if v, ok := params.Arguments["offset"].(float64); ok {
			offset = int(v)
		}
		if v, ok := params.Arguments["length"].(float64); ok {
			length = int(v)
		}
		slice := r.BufStore.Slice(bufID, offset, length)
		if slice == "" && r.BufStore.Len(bufID) == 0 {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: fmt.Sprintf("buf_id %q not found", bufID)}}})
		}
		total := r.BufStore.Len(bufID)
		header := fmt.Sprintf("// buf_id=%s offset=%d length=%d total=%d\n", bufID, offset, len(slice), total)
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: header + slice}},
		})

	case "grep_output":
		bufID, _ := params.Arguments["buf_id"].(string)
		pattern, _ := params.Arguments["pattern"].(string)
		if bufID == "" || pattern == "" {
			return respondError(id, -32602, "buf_id and pattern are required")
		}
		if r.BufStore == nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "output buffer not enabled"}}})
		}
		maxLines := 100
		if v, ok := params.Arguments["max_lines"].(float64); ok {
			maxLines = int(v)
		}
		lines, err := r.BufStore.Grep(bufID, pattern, maxLines)
		if err != nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: err.Error()}}})
		}
		if len(lines) == 0 {
			return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: "(no matches)"}}})
		}
		return respond(id, toolResult{
			Content: []contentBlock{{Type: "text", Text: strings.Join(lines, "\n")}},
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

	case "find_files":
		host, _ := params.Arguments["host"].(string)
		query, _ := params.Arguments["query"].(string)
		if host == "" || query == "" {
			return respondError(id, -32602, "host and query are required")
		}
		searchPath := "."
		if v, ok := params.Arguments["path"].(string); ok && v != "" {
			searchPath = v
		}
		maxResults := 50
		if v, ok := params.Arguments["max_results"].(float64); ok && v > 0 {
			maxResults = int(v)
		}

		cmd := findFilesCmd(query, searchPath, maxResults)
		stdout, stderr, err := rawExec(ctx, r, host, cmd)
		if err != nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "exec error: " + err.Error()}}})
		}
		out := strings.TrimRight(stdout, "\n")
		if out == "" {
			out = "(no matches)"
		}
		if stderr != "" {
			out += "\n--- stderr ---\n" + strings.TrimRight(stderr, "\n")
		}
		if len(out) > 4096 && r.BufStore != nil {
			bufID := r.BufStore.Put(out)
			out = fmt.Sprintf("// truncated -- buf_id=%s total=%d\n%s\n[...%d bytes remaining, use get_output]",
				bufID, r.BufStore.Len(bufID), out[:4096], r.BufStore.Len(bufID)-4096)
		}
		return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: out}}})

	case "grep_files":
		host, _ := params.Arguments["host"].(string)
		pattern, _ := params.Arguments["pattern"].(string)
		if host == "" || pattern == "" {
			return respondError(id, -32602, "host and pattern are required")
		}
		searchPath := "."
		if v, ok := params.Arguments["path"].(string); ok && v != "" {
			searchPath = v
		}
		glob, _ := params.Arguments["glob"].(string)
		maxResults := 50
		if v, ok := params.Arguments["max_results"].(float64); ok && v > 0 {
			maxResults = int(v)
		}

		cmd := grepFilesCmd(pattern, searchPath, glob, maxResults)
		stdout, stderr, err := rawExec(ctx, r, host, cmd)
		if err != nil {
			return respond(id, toolResult{IsError: true, Content: []contentBlock{{Type: "text", Text: "exec error: " + err.Error()}}})
		}
		out := strings.TrimRight(stdout, "\n")
		if out == "" {
			out = "(no matches)"
		}
		if stderr != "" {
			out += "\n--- stderr ---\n" + strings.TrimRight(stderr, "\n")
		}
		if len(out) > 4096 && r.BufStore != nil {
			bufID := r.BufStore.Put(out)
			out = fmt.Sprintf("// truncated -- buf_id=%s total=%d\n%s\n[...%d bytes remaining, use get_output]",
				bufID, r.BufStore.Len(bufID), out[:4096], r.BufStore.Len(bufID)-4096)
		}
		return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: out}}})

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

// execResponse wraps RunResult with output-handle metadata added by the server layer.
type execResponse struct {
	runner.RunResult
	BufID     string `json:"buf_id,omitempty"`
	BufBytes  int    `json:"buf_bytes,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// processOutputWithBuf applies output processing and, if output was truncated,
// stores the full content in the BufStore and returns the handle.
func processOutputWithBuf(r *runner.Runner, result *runner.RunResult) (bufID string, truncated bool) {
	if !result.Allowed || (result.Stdout == "" && result.Stderr == "") {
		return "", false
	}

	cfg := r.OutputConfig()
	rawLen := len(result.Stdout) + len(result.Stderr)

	// Store full (ANSI-stripped, pre-truncation) output for the buf handle.
	fullOut := result.Stdout
	fullErr := result.Stderr
	if cfg.ANSIStrip {
		fullOut = output.StripANSI(fullOut)
		fullErr = output.StripANSI(fullErr)
	}

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

	// If truncation happened and we have a BufStore, stash the full content.
	fullLen := len(fullOut) + len(fullErr)
	if fullLen > outLen && r.BufStore != nil {
		combined := fullOut
		if fullErr != "" {
			combined += "\n--- stderr ---\n" + fullErr
		}
		bufID = r.BufStore.Put(combined)
		truncated = true
	}
	return bufID, truncated
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

// rawExec runs a server-constructed command on the given host without policy
// validation. The caller is responsible for building safe commands from
// sanitized inputs (use shellQuote on all user-supplied values).
func rawExec(ctx context.Context, r *runner.Runner, host, cmd string) (string, string, error) {
	if host == "local" {
		return r.ExecRawLocal(ctx, cmd)
	}
	return r.ExecRaw(ctx, host, cmd)
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
// This is safe for POSIX shells (sh, bash, dash). Never use with cmd.exe.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// findFilesCmd builds a shell command that searches for filenames matching query
// under path. Tries fd first (faster, respects .gitignore), falls back to find.
func findFilesCmd(query, path string, maxResults int) string {
	q := shellQuote(query)
	p := shellQuote(path)
	// For find -iname the glob pattern needs *query*; shellQuote("*q*") passes
	// the literal asterisks to find, which interprets them as globs itself.
	iname := shellQuote("*" + query + "*")
	n := fmt.Sprintf("%d", maxResults)
	return fmt.Sprintf(
		"command -v fd >/dev/null 2>&1"+
			" && fd --color=never -H -t f -- %s %s 2>/dev/null | head -%s"+
			" || find %s -iname %s 2>/dev/null | head -%s",
		q, p, n, p, iname, n,
	)
}

// grepFilesCmd builds a shell command that searches file contents for pattern
// under path. Tries rg first, falls back to grep -r.
func grepFilesCmd(pattern, path, glob string, maxResults int) string {
	pat := shellQuote(pattern)
	p := shellQuote(path)
	n := fmt.Sprintf("%d", maxResults)
	if glob != "" {
		g := shellQuote(glob)
		return fmt.Sprintf(
			"command -v rg >/dev/null 2>&1"+
				" && rg --color=never -n -- %s --glob %s %s 2>/dev/null | head -%s"+
				" || grep -rn --color=never --include=%s -- %s %s 2>/dev/null | head -%s",
			pat, g, p, n, g, pat, p, n,
		)
	}
	return fmt.Sprintf(
		"command -v rg >/dev/null 2>&1"+
			" && rg --color=never -n -- %s %s 2>/dev/null | head -%s"+
			" || grep -rn --color=never -- %s %s 2>/dev/null | head -%s",
		pat, p, n, pat, p, n,
	)
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
			Annotations: &toolAnnotations{
				Title:           "Run Local Command",
				DestructiveHint: boolPtr(true),
				OpenWorldHint:   boolPtr(true),
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
			Annotations: &toolAnnotations{
				Title:           "Run Remote Command",
				DestructiveHint: boolPtr(true),
				OpenWorldHint:   boolPtr(true),
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
			Annotations: &toolAnnotations{
				Title:          "Validate Command",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
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
			Annotations: &toolAnnotations{
				Title:          "List Allowed Commands",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
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
			Annotations: &toolAnnotations{
				Title:           "Batch Execute",
				DestructiveHint: boolPtr(true),
				OpenWorldHint:   boolPtr(true),
			},
		},
		{
			Name:        "host_info",
			Description: "Fingerprint a remote host: OS, kernel, shell, package manager, and installed tools. Cached for 30 minutes. Use refresh: true to force re-probe.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":    map[string]any{"type": "string", "description": "Host name as defined in policy"},
					"refresh": map[string]any{"type": "boolean", "description": "Force re-probe even if cached"},
				},
				"required": []string{"host"},
			},
			Annotations: &toolAnnotations{
				Title:          "Host Fingerprint",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
			},
		},
		{
			Name:        "get_output",
			Description: "Read a slice of full command output from a buffer handle. When exec or ssh_exec returns a buf_id, use this to page through the untruncated content.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"buf_id": map[string]any{"type": "string", "description": "Handle returned by exec/ssh_exec"},
					"offset": map[string]any{"type": "integer", "description": "Byte offset (default 0)"},
					"length": map[string]any{"type": "integer", "description": "Max bytes to return (default 8192)"},
				},
				"required": []string{"buf_id"},
			},
			Annotations: &toolAnnotations{
				Title:          "Read Output Buffer",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
			},
		},
		{
			Name:        "grep_output",
			Description: "Search a buffered command output for lines matching a regex. Returns matching lines without loading the full output.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"buf_id":    map[string]any{"type": "string", "description": "Handle returned by exec/ssh_exec"},
					"pattern":   map[string]any{"type": "string", "description": "Regex to match against each line"},
					"max_lines": map[string]any{"type": "integer", "description": "Max matching lines to return (default 100)"},
				},
				"required": []string{"buf_id", "pattern"},
			},
			Annotations: &toolAnnotations{
				Title:          "Search Output Buffer",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
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
			Annotations: &toolAnnotations{
				Title:          "Invalidate Cache",
				IdempotentHint: boolPtr(true),
			},
		},
		{
			Name:        "find_files",
			Description: "Search for files by name on a host. Uses fd if available, falls back to find. Results are filenames only (no content). Use grep_files to search by content.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":        map[string]any{"type": "string", "description": "Target host or 'local'"},
					"query":       map[string]any{"type": "string", "description": "Filename substring to search for (case-insensitive)"},
					"path":        map[string]any{"type": "string", "description": "Directory to search in (default '.')"},
					"max_results": map[string]any{"type": "integer", "description": "Max results to return (default 50)"},
				},
				"required": []string{"host", "query"},
			},
			Annotations: &toolAnnotations{
				Title:        "Find Files",
				ReadOnlyHint: boolPtr(true),
				OpenWorldHint: boolPtr(true),
			},
		},
		{
			Name:        "grep_files",
			Description: "Search file contents on a host for lines matching a regex. Uses rg (ripgrep) if available, falls back to grep -r. Returns matching lines with filename and line number.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":        map[string]any{"type": "string", "description": "Target host or 'local'"},
					"pattern":     map[string]any{"type": "string", "description": "Regex pattern to search for"},
					"path":        map[string]any{"type": "string", "description": "Directory to search in (default '.')"},
					"glob":        map[string]any{"type": "string", "description": "File glob filter, e.g. '*.go' or '*.py' (optional)"},
					"max_results": map[string]any{"type": "integer", "description": "Max matching lines to return (default 50)"},
				},
				"required": []string{"host", "pattern"},
			},
			Annotations: &toolAnnotations{
				Title:         "Search File Contents",
				ReadOnlyHint:  boolPtr(true),
				OpenWorldHint: boolPtr(true),
			},
		},
		{
			Name:        "get_stats",
			Description: "Get output processing statistics for this session. Shows total calls, raw bytes, processed bytes, and savings percentage.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Annotations: &toolAnnotations{
				Title:        "Session Stats",
				ReadOnlyHint: boolPtr(true),
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
