package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
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

func (cs *connState) get() int32 { return cs.state.Load() }
func (cs *connState) set(s int32) { cs.state.Store(s) }

// Version is set at build time via ldflags. Falls back to "dev".
var Version = "dev"

// supportedVersions lists the MCP protocol versions this server speaks, newest
// first. supportedVersions[0] is advertised when a client requests a version we
// do not support, or sends none (spec: reply with a supported version, ideally
// the latest -- not the oldest).
var supportedVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// defaultProtocolVersion is assumed for a Streamable HTTP request that omits the
// MCP-Protocol-Version header after initialization (spec default).
const defaultProtocolVersion = "2025-03-26"

func isSupportedVersion(v string) bool {
	for _, s := range supportedVersions {
		if s == v {
			return true
		}
	}
	return false
}

// negotiateVersion echoes the client's requested version when supported,
// otherwise returns the latest version we support.
func negotiateVersion(clientVersion string) string {
	if isSupportedVersion(clientVersion) {
		return clientVersion
	}
	if clientVersion != "" {
		fmt.Fprintf(os.Stderr, "mcp: client requested unsupported protocol version %q, using %s\n", clientVersion, supportedVersions[0])
	}
	return supportedVersions[0]
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
	cancels map[string]context.CancelFunc
}

func newCancelRegistry() *cancelRegistry {
	return &cancelRegistry{cancels: make(map[string]context.CancelFunc)}
}

// idKey canonicalizes a JSON-RPC id into a type-tagged string so that, e.g.,
// the string "1" and the number 1 never collide in the registry.
func idKey(id any) string {
	if id == nil {
		return "null"
	}
	return fmt.Sprintf("%T:%v", id, id)
}

func (cr *cancelRegistry) register(id any, cancel context.CancelFunc) {
	cr.mu.Lock()
	cr.cancels[idKey(id)] = cancel
	cr.mu.Unlock()
}

func (cr *cancelRegistry) cancel(id any) bool {
	cr.mu.Lock()
	fn, ok := cr.cancels[idKey(id)]
	cr.mu.Unlock()
	if ok {
		fn()
	}
	return ok
}

func (cr *cancelRegistry) deregister(id any) {
	cr.mu.Lock()
	delete(cr.cancels, idKey(id))
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
	Resources    *resourcesCap  `json:"resources,omitempty"`
	Prompts      *promptsCap    `json:"prompts,omitempty"`
	Logging      *loggingCap    `json:"logging,omitempty"`
	Experimental map[string]any `json:"experimental,omitempty"`
}

// loggingCap, when present, advertises that the server emits notifications/message
// log records (used to stream command output chunks). It has no sub-fields.
type loggingCap struct{}

type toolsCap struct {
	ListChanged bool `json:"listChanged"`
}

type resourcesCap struct {
	Subscribe   bool `json:"subscribe"`
	ListChanged bool `json:"listChanged"`
}

type promptsCap struct {
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

// --- Resource types ---

type resourcesListResult struct {
	Resources         []resourceDef    `json:"resources"`
	ResourceTemplates []resourceTmplDef `json:"resourceTemplates,omitempty"`
}

type resourceDef struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type resourceTmplDef struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type resourcesReadParams struct {
	URI string `json:"uri"`
}

type resourcesReadResult struct {
	Contents []resourceContent `json:"contents"`
}

type resourceContent struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type toolDef struct {
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description"`
	InputSchema  map[string]any   `json:"inputSchema"`
	OutputSchema map[string]any   `json:"outputSchema,omitempty"`
	Annotations  *toolAnnotations `json:"annotations,omitempty"`
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
	ProgressToken any    `json:"progressToken"`
	Progress      int64  `json:"progress"`
	Message       string `json:"message,omitempty"`
}

// logMessage is a notifications/message record (the logging capability). Data is
// arbitrary JSON; command output is streamed live as outputChunk values.
type logMessage struct {
	Level  string `json:"level"`
	Logger string `json:"logger,omitempty"`
	Data   any    `json:"data"`
}

// outputChunk is one sanitized slice of streamed command output, tagged by its
// stream so a consumer can keep stdout and stderr distinct.
type outputChunk struct {
	Stream string `json:"stream"`
	Text   string `json:"text"`
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
	Content           []contentBlock `json:"content"`
	StructuredContent any            `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type     string       `json:"type"`
	Text     string       `json:"text,omitempty"`
	Resource *resourceRef `json:"resource,omitempty"`
}

// resourceRef is an embedded resource reference inside a tool result content block.
type resourceRef struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
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
				Resources:    &resourcesCap{},
				Prompts:      &promptsCap{},
				Logging:      &loggingCap{},
				Experimental: map[string]any{"wrapster": wrapsterExperimental},
			},
			ServerInfo: serverInfo{Name: "wrapster", Version: Version},
		})

	case "notifications/initialized":
		return nil // notification, no response

	case "logging/setLevel":
		// Accept and acknowledge. We declare the logging capability to stream
		// output as notifications/message; per-level server-side filtering is not
		// required for correctness, so the requested level is accepted and noted.
		return respond(msg.ID, struct{}{})

	case "tools/list":
		return respond(msg.ID, toolsListResult{Tools: toolDefinitions()})

	case "resources/list":
		return respond(msg.ID, resourcesList(r))

	case "resources/read":
		var params resourcesReadParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return respondError(msg.ID, -32602, "invalid params: "+err.Error())
		}
		if params.URI == "" {
			return respondError(msg.ID, -32602, "uri is required")
		}
		result, err := resourcesRead(r, params.URI)
		if err != nil {
			return respondError(msg.ID, -32002, err.Error())
		}
		return respond(msg.ID, result)

	case "prompts/list":
		return respond(msg.ID, promptsListResult{Prompts: promptDefinitions()})

	case "prompts/get":
		var params promptsGetParams
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			return respondError(msg.ID, -32602, "invalid params: "+err.Error())
		}
		if params.Name == "" {
			return respondError(msg.ID, -32602, "name is required")
		}
		result, err := getPrompt(params)
		if err != nil {
			return respondError(msg.ID, -32602, err.Error())
		}
		return respond(msg.ID, result)

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
		// On a progressToken opt-in, start progress ticks (timeout resilience)
		// and attach a live-output sink so command output streams as
		// notifications/message. This is additive -- the full result still
		// returns in the CallToolResult. notify is the real channel on stdio and
		// the SSE channel on Streamable HTTP; elsewhere it is dropped.
		if params.Meta != nil && params.Meta.ProgressToken != nil {
			startProgress(ctx, params.Meta.ProgressToken, notify)
			ctx = output.WithSink(ctx, func(stream string, chunk []byte) {
				notify("notifications/message", logMessage{
					Level:  "info",
					Logger: "wrapster.exec",
					Data:   outputChunk{Stream: stream, Text: string(chunk)},
				})
			})
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
		return respond(id, buildExecToolResult(r, result, bufID, truncated))

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
		return respond(id, buildExecToolResult(r, result, bufID, truncated))

	case "ssh_validate":
		host, _ := params.Arguments["host"].(string)
		command, _ := params.Arguments["command"].(string)
		if host == "" || command == "" {
			return respondError(id, -32602, "host and command are required")
		}

		result := r.Validate(host, command)
		out, _ := json.Marshal(result)
		return respond(id, toolResult{
			Content:           []contentBlock{{Type: "text", Text: string(out)}},
			StructuredContent: result,
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

		out, _ := json.Marshal(br)
		hasError := br.Failed > 0 || br.Blocked > 0
		return respond(id, toolResult{
			IsError:           hasError,
			Content:           []contentBlock{{Type: "text", Text: string(out)}},
			StructuredContent: br,
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

	case "reach":
		host, _ := params.Arguments["host"].(string)
		if host == "" {
			return respondError(id, -32602, "host is required")
		}
		port := 0
		if v, ok := params.Arguments["port"].(float64); ok {
			port = int(v)
		}
		res := r.Reach(ctx, host, port)
		out, _ := json.Marshal(res)
		return respond(id, toolResult{
			IsError:           !res.Reachable,
			Content:           []contentBlock{{Type: "text", Text: string(out)}},
			StructuredContent: res,
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
		out = truncateForModel(out, r)
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
		out = truncateForModel(out, r)
		return respond(id, toolResult{Content: []contentBlock{{Type: "text", Text: out}}})

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

// buildExecToolResult creates a tool response for exec/ssh_exec.
// When output was truncated and stored in BufStore, returns a multi-block
// response: compact summary text + resource reference to buf://<id>.
// When output fits without truncation: single text block.
func buildExecToolResult(r *runner.Runner, result runner.RunResult, bufID string, truncated bool) toolResult {
	isErr := !result.Allowed || result.Error != ""
	resp := execResponse{RunResult: result, BufID: bufID, Truncated: truncated}
	if bufID != "" {
		resp.BufBytes = r.BufStore.Len(bufID)
	}
	out, _ := json.Marshal(resp)
	blocks := []contentBlock{{Type: "text", Text: string(out)}}

	// multi-block: append a resource reference so hosts can fetch full output
	if truncated && bufID != "" {
		preview := r.BufStore.Slice(bufID, 0, 500)
		blocks = append(blocks, contentBlock{
			Type: "resource",
			Resource: &resourceRef{
				URI:      "buf://" + bufID,
				MimeType: "text/plain",
				Text:     preview,
			},
		})
	}

	return toolResult{IsError: isErr, Content: blocks}
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
	out, _ := json.Marshal(r)
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
// truncateForModel stores oversized output in the buffer store and returns a
// model-facing preview trimmed to a UTF-8 boundary, pointing at the buf://
// resource for the remainder.
func truncateForModel(out string, r *runner.Runner) string {
	const previewMax = 4096
	if len(out) <= previewMax || r.BufStore == nil {
		return out
	}
	bufID := r.BufStore.Put(out)
	total := r.BufStore.Len(bufID)
	cut := previewMax
	for cut > 0 && out[cut]&0xC0 == 0x80 { // back off any UTF-8 continuation byte
		cut--
	}
	return fmt.Sprintf("// truncated -- buf_id=%s total=%d\n%s\n[...%d bytes remaining, read resource buf://%s]",
		bufID, total, out[:cut], total-cut, bufID)
}

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
	tools := []toolDef{
		{
			Name:        "exec",
			Description: "Use this to run a shell command on the local machine. Security filters block shell escapes, destructive ops, and exfiltration. Long output is truncated with a buf:// resource URI for paging.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{
						"type":        "string",
						"description": "Shell command to run",
					},
					"nocache": map[string]any{
						"type":        "boolean",
						"description": "Set true to skip cache and force re-execution",
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
			Description: "Use this to run a policy-allowed command on a remote host via SSH. Returns stdout, stderr, and exit code. Truncated output includes a buf:// resource URI. Use ssh_validate first if unsure whether a command is allowed.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host from policy (read host://{name}/allowed to see what's permitted)",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command to run on the remote host",
					},
					"nocache": map[string]any{
						"type":        "boolean",
						"description": "Set true to skip cache and force re-execution",
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
			Description: "Use this to dry-run a command against the policy without executing it. Returns allowed/denied with reason. Prefer this before ssh_exec when you need to check permission first.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host from policy",
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
			Name:        "batch_exec",
			Description: "Use this to run multiple commands in one call. Each command is validated individually. SSH commands share a pooled connection for lower latency. Use host='local' for local execution.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Target host, or 'local' for local execution",
					},
					"commands": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Commands to execute sequentially",
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
			Description: "Use this to probe a host's OS, kernel, shell, package manager, and installed tools. Results are cached (30min). Also available as host://{name}/info resource for cached reads. Set refresh=true to force re-probe.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":    map[string]any{"type": "string", "description": "Host from policy to fingerprint"},
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
			Name:        "reach",
			Description: "Use this to check whether a policy host's TCP port is reachable, without running a command. Fast diagnostic (5s) for connection failures: tells you if the port is open, refused, or timing out. Defaults to the host's configured SSH port; pass 'port' to probe a different one.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{"type": "string", "description": "Policy host name to probe"},
					"port": map[string]any{"type": "integer", "description": "TCP port (default: host's configured SSH port, else 22)"},
				},
				"required": []string{"host"},
			},
			Annotations: &toolAnnotations{
				Title:          "Check Reachability",
				ReadOnlyHint:   boolPtr(true),
				IdempotentHint: boolPtr(true),
				OpenWorldHint:  boolPtr(true),
			},
		},
		{
			Name:        "grep_output",
			Description: "Use this to search a buffered output for lines matching a regex. When exec/ssh_exec returns a buf_id, use this instead of reading the full buffer. Returns only matching lines.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"buf_id":    map[string]any{"type": "string", "description": "Buffer handle from exec/ssh_exec response"},
					"pattern":   map[string]any{"type": "string", "description": "Regex pattern to match against each line"},
					"max_lines": map[string]any{"type": "integer", "description": "Max matching lines (default 100)"},
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
			Description: "Use this when you need fresh results from a previously cached command. Specify host+command for a single entry, or omit both to flush the entire cache.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host": map[string]any{
						"type":        "string",
						"description": "Host of the entry to invalidate (omit to flush all)",
					},
					"command": map[string]any{
						"type":        "string",
						"description": "Command of the entry to invalidate (omit to flush all)",
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
			Description: "Use this to locate files by name on a host. Returns paths only (no content). Use grep_files when you need to search file contents instead.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":        map[string]any{"type": "string", "description": "Target host or 'local'"},
					"query":       map[string]any{"type": "string", "description": "Filename substring (case-insensitive)"},
					"path":        map[string]any{"type": "string", "description": "Directory to search (default '.')"},
					"max_results": map[string]any{"type": "integer", "description": "Max results (default 50)"},
				},
				"required": []string{"host", "query"},
			},
			Annotations: &toolAnnotations{
				Title:         "Find Files",
				ReadOnlyHint:  boolPtr(true),
				OpenWorldHint: boolPtr(true),
			},
		},
		{
			Name:        "grep_files",
			Description: "Use this to search file contents on a host for lines matching a regex. Returns filename:line_number:match. Use find_files when you only need filenames.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host":        map[string]any{"type": "string", "description": "Target host or 'local'"},
					"pattern":     map[string]any{"type": "string", "description": "Regex pattern to search for"},
					"path":        map[string]any{"type": "string", "description": "Directory to search (default '.')"},
					"glob":        map[string]any{"type": "string", "description": "File filter glob, e.g. '*.go'"},
					"max_results": map[string]any{"type": "integer", "description": "Max matching lines (default 50)"},
				},
				"required": []string{"host", "pattern"},
			},
			Annotations: &toolAnnotations{
				Title:         "Search File Contents",
				ReadOnlyHint:  boolPtr(true),
				OpenWorldHint: boolPtr(true),
			},
		},
	}
	// 2025-06-18 added a top-level Tool.title distinct from the programmatic
	// name; mirror the annotation title there so newer clients get the canonical
	// display field while older clients keep reading annotations.title.
	for i := range tools {
		if tools[i].Annotations != nil {
			tools[i].Title = tools[i].Annotations.Title
		}
	}
	return tools
}

// --- Resource implementation ---

// resourcesList returns all available resources and URI templates.
func resourcesList(r *runner.Runner) resourcesListResult {
	resources := []resourceDef{
		{
			URI:         "stats://session",
			Name:        "Session Stats",
			Description: "Output processing statistics for this session",
			MimeType:    "application/json",
		},
		{
			URI:         "policy://current",
			Name:        "Active Policy",
			Description: "Summary of the active security policy",
			MimeType:    "application/json",
		},
		{
			URI:         "hosts://",
			Name:        "Host Inventory",
			Description: "All configured hosts with connection metadata (name, address, port, user, trusted, command count)",
			MimeType:    "application/json",
		},
	}

	// add a resource per configured host
	if r.Policy != nil {
		for name := range r.Policy.Hosts {
			resources = append(resources, resourceDef{
				URI:      "host://" + name + "/allowed",
				Name:     name + " allowed commands",
				MimeType: "text/plain",
			})
			resources = append(resources, resourceDef{
				URI:      "host://" + name + "/info",
				Name:     name + " host info",
				MimeType: "application/json",
			})
		}
	}

	// dynamic buf:// entries
	if r.BufStore != nil {
		for _, id := range r.BufStore.IDs() {
			resources = append(resources, resourceDef{
				URI:      "buf://" + id,
				Name:     "Output buffer " + id,
				MimeType: "text/plain",
			})
		}
	}

	templates := []resourceTmplDef{
		{
			URITemplate: "host://{name}/allowed",
			Name:        "Host allowed commands",
			Description: "Allowed commands for a policy-defined host",
			MimeType:    "text/plain",
		},
		{
			URITemplate: "host://{name}/info",
			Name:        "Host fingerprint",
			Description: "Cached OS/kernel/tools fingerprint for a host",
			MimeType:    "application/json",
		},
		{
			URITemplate: "buf://{id}",
			Name:        "Output buffer",
			Description: "Full command output stored after truncation",
			MimeType:    "text/plain",
		},
	}

	return resourcesListResult{Resources: resources, ResourceTemplates: templates}
}

// resourcesRead resolves a URI and returns its contents.
func resourcesRead(r *runner.Runner, uri string) (*resourcesReadResult, error) {
	switch {
	case uri == "stats://session":
		return readStatsResource(r)
	case uri == "policy://current":
		return readPolicyResource(r)
	case uri == "hosts://":
		return readHostsResource(r)
	case strings.HasPrefix(uri, "host://"):
		return readHostResource(r, uri)
	case strings.HasPrefix(uri, "buf://"):
		return readBufResource(r, uri)
	default:
		return nil, fmt.Errorf("unknown resource URI: %s", uri)
	}
}

func readStatsResource(r *runner.Runner) (*resourcesReadResult, error) {
	if r.OutputStats == nil {
		return nil, fmt.Errorf("output stats not enabled")
	}
	s := r.OutputStats.Snapshot()
	out, _ := json.Marshal(map[string]any{
		"calls":       s.Calls,
		"raw_bytes":   s.RawBytes,
		"output_bytes": s.OutBytes,
		"savings_pct": fmt.Sprintf("%.1f", s.SavingsPct()),
	})
	return &resourcesReadResult{
		Contents: []resourceContent{{URI: "stats://session", MimeType: "application/json", Text: string(out)}},
	}, nil
}

func readPolicyResource(r *runner.Runner) (*resourcesReadResult, error) {
	if r.Policy == nil {
		return nil, fmt.Errorf("no policy loaded")
	}
	summary := map[string]any{
		"local_mode": r.Policy.Local.Mode,
	}
	hosts := map[string]any{}
	for name, hp := range r.Policy.Hosts {
		cmds := make([]string, 0, len(hp.AllowedCommands))
		for _, rule := range hp.AllowedCommands {
			if rule.Command != "" {
				cmds = append(cmds, rule.Command)
			} else if rule.Pattern != "" {
				cmds = append(cmds, "/"+rule.Pattern+"/")
			}
		}
		hosts[name] = map[string]any{
			"user":             hp.User,
			"allowed_commands": cmds,
			"denied_patterns":  hp.DeniedPatterns,
		}
	}
	summary["hosts"] = hosts
	out, _ := json.Marshal(summary)
	return &resourcesReadResult{
		Contents: []resourceContent{{URI: "policy://current", MimeType: "application/json", Text: string(out)}},
	}, nil
}

func readHostsResource(r *runner.Runner) (*resourcesReadResult, error) {
	if r.Policy == nil {
		return nil, fmt.Errorf("no policy loaded")
	}
	type hostEntry struct {
		Name           string `json:"name"`
		Hostname       string `json:"hostname,omitempty"`
		Port           int    `json:"port"`
		User           string `json:"user,omitempty"`
		Trusted        bool   `json:"trusted"`
		ShellOperators bool   `json:"shell_operators"`
		CommandCount   int    `json:"command_count"`
		Description    string `json:"description,omitempty"`
	}
	names := make([]string, 0, len(r.Policy.Hosts))
	for name := range r.Policy.Hosts {
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]hostEntry, 0, len(names))
	for _, name := range names {
		hp := r.Policy.Hosts[name]
		port := hp.Port
		if port == 0 {
			port = 22
		}
		entries = append(entries, hostEntry{
			Name:           name,
			Hostname:       hp.Hostname,
			Port:           port,
			User:           hp.User,
			Trusted:        hp.Trusted,
			ShellOperators: hp.AllowShellOperators,
			CommandCount:   len(hp.AllowedCommands),
			Description:    hp.Description,
		})
	}
	out, _ := json.Marshal(map[string]any{"hosts": entries})
	return &resourcesReadResult{
		Contents: []resourceContent{{URI: "hosts://", MimeType: "application/json", Text: string(out)}},
	}, nil
}

func readHostResource(r *runner.Runner, uri string) (*resourcesReadResult, error) {
	// parse host://<name>/<subpath>
	path := strings.TrimPrefix(uri, "host://")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid host URI: %s (expected host://<name>/allowed or host://<name>/info)", uri)
	}
	name, sub := parts[0], parts[1]

	switch sub {
	case "allowed":
		hp := r.ListAllowed(name)
		text := formatAllowed(name, hp)
		return &resourcesReadResult{
			Contents: []resourceContent{{URI: uri, MimeType: "text/plain", Text: text}},
		}, nil

	case "info":
		if r.HostInfoCache == nil {
			return nil, fmt.Errorf("host info cache not enabled")
		}
		info := r.HostInfoCache.Get(name)
		if info == nil {
			return &resourcesReadResult{
				Contents: []resourceContent{{URI: uri, MimeType: "application/json", Text: `{"status":"not cached, use host_info tool with refresh:true to probe"}`}},
			}, nil
		}
		return &resourcesReadResult{
			Contents: []resourceContent{{URI: uri, MimeType: "application/json", Text: info.JSON()}},
		}, nil

	default:
		return nil, fmt.Errorf("unknown host sub-resource: %s (expected 'allowed' or 'info')", sub)
	}
}

func readBufResource(r *runner.Runner, uri string) (*resourcesReadResult, error) {
	if r.BufStore == nil {
		return nil, fmt.Errorf("output buffer not enabled")
	}

	// parse buf://<id> with optional ?offset=N&length=M
	raw := strings.TrimPrefix(uri, "buf://")
	id := raw
	offset := 0
	length := 0 // 0 = full content

	if qIdx := strings.Index(raw, "?"); qIdx >= 0 {
		id = raw[:qIdx]
		query := raw[qIdx+1:]
		for _, param := range strings.Split(query, "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "offset":
				fmt.Sscanf(kv[1], "%d", &offset)
			case "length":
				fmt.Sscanf(kv[1], "%d", &length)
			}
		}
	}

	total := r.BufStore.Len(id)
	if total == 0 {
		return nil, fmt.Errorf("buf_id %q not found", id)
	}

	var text string
	if length > 0 {
		text = r.BufStore.Slice(id, offset, length)
	} else {
		text = r.BufStore.Slice(id, 0, total)
	}

	return &resourcesReadResult{
		Contents: []resourceContent{{URI: "buf://" + id, MimeType: "text/plain", Text: text}},
	}, nil
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

// --- Prompts implementation ---

type promptsListResult struct {
	Prompts []promptDef `json:"prompts"`
}

type promptDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Arguments   []promptArg `json:"arguments,omitempty"`
}

type promptArg struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type promptsGetParams struct {
	Name      string         `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type promptsGetResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []promptMessage `json:"messages"`
}

type promptMessage struct {
	Role    string       `json:"role"`
	Content promptContent `json:"content"`
}

type promptContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func promptDefinitions() []promptDef {
	return []promptDef{
		{
			Name:        "diagnose-host",
			Description: "Run standard diagnostic commands on a host and interpret the results",
			Arguments: []promptArg{
				{Name: "host", Description: "Host to diagnose (from policy)", Required: true},
			},
		},
		{
			Name:        "compare-hosts",
			Description: "Fingerprint two hosts and compare their configurations",
			Arguments: []promptArg{
				{Name: "host_a", Description: "First host to compare", Required: true},
				{Name: "host_b", Description: "Second host to compare", Required: true},
			},
		},
		{
			Name:        "safety-review",
			Description: "Validate a command against policy and review it for security risks",
			Arguments: []promptArg{
				{Name: "host", Description: "Target host", Required: true},
				{Name: "command", Description: "Command to review", Required: true},
			},
		},
	}
}

func getPrompt(params promptsGetParams) (*promptsGetResult, error) {
	switch params.Name {
	case "diagnose-host":
		host := params.Arguments["host"]
		if host == "" {
			return nil, fmt.Errorf("argument 'host' is required")
		}
		return &promptsGetResult{
			Description: "Diagnose " + host,
			Messages: []promptMessage{
				{
					Role: "user",
					Content: promptContent{
						Type: "text",
						Text: fmt.Sprintf(
							"Diagnose the host %q. Run the following commands and interpret the results:\n\n"+
								"1. `uptime` -- check load and how long it has been running\n"+
								"2. `df -h` -- check disk usage, flag anything above 80%%\n"+
								"3. `free -m` -- check memory pressure\n"+
								"4. `last -5` -- check recent logins for anything unusual\n\n"+
								"Start by reading host://%s/allowed to see what commands are available, "+
								"then use host_info to fingerprint the OS. Adapt commands if the host "+
								"uses a different package manager or init system. Summarize findings "+
								"with actionable recommendations.",
							host, host),
					},
				},
			},
		}, nil

	case "compare-hosts":
		a := params.Arguments["host_a"]
		b := params.Arguments["host_b"]
		if a == "" || b == "" {
			return nil, fmt.Errorf("arguments 'host_a' and 'host_b' are required")
		}
		return &promptsGetResult{
			Description: fmt.Sprintf("Compare %s vs %s", a, b),
			Messages: []promptMessage{
				{
					Role: "user",
					Content: promptContent{
						Type: "text",
						Text: fmt.Sprintf(
							"Compare the hosts %q and %q.\n\n"+
								"1. Use host_info on both to fingerprint OS, kernel, shell, and tools\n"+
								"2. Read host://%s/allowed and host://%s/allowed to compare permitted commands\n"+
								"3. Run `uname -a` and `uptime` on both\n\n"+
								"Present a side-by-side comparison table, highlight differences, "+
								"and note any configuration drift that could cause issues.",
							a, b, a, b),
					},
				},
			},
		}, nil

	case "safety-review":
		host := params.Arguments["host"]
		command := params.Arguments["command"]
		if host == "" || command == "" {
			return nil, fmt.Errorf("arguments 'host' and 'command' are required")
		}
		return &promptsGetResult{
			Description: fmt.Sprintf("Safety review: %s on %s", command, host),
			Messages: []promptMessage{
				{
					Role: "user",
					Content: promptContent{
						Type: "text",
						Text: fmt.Sprintf(
							"Review the safety of running `%s` on host %q.\n\n"+
								"1. Use ssh_validate to check if the policy allows it\n"+
								"2. Read host://%s/allowed to understand the full allowlist context\n"+
								"3. Analyze the command for:\n"+
								"   - GTFOBins risk (could it be used to escalate privileges?)\n"+
								"   - Data exfiltration potential\n"+
								"   - Destructive side effects\n"+
								"   - Shell injection vectors\n\n"+
								"Provide a verdict: SAFE, CAUTION, or DANGEROUS, with reasoning.",
							command, host, host),
					},
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown prompt: %s", params.Name)
	}
}
