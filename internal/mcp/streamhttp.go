package mcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hed0rah/wrapster/internal/runner"
)

// StreamableServer runs an MCP server over the Streamable HTTP transport
// (MCP 2025-03-26) on a single POST/DELETE /mcp endpoint. Each POST carries one
// JSON-RPC message and gets the JSON-RPC response back as application/json.
//
// ponytail: JSON responses only -- per-request SSE streaming is not
// implemented, so progress notifications are dropped (they are optional by
// spec). Wire a real notifier + text/event-stream response if a client ever
// needs live progress.
type StreamableServer struct {
	runner    *runner.Runner
	addr      string
	authToken string

	mu       sync.Mutex
	sessions map[string]*httpSession
}

// httpSession is the per-client state keyed by the Mcp-Session-Id header.
type httpSession struct {
	cancels *cancelRegistry
	state   *connState
}

// NewStreamableServer builds a server bound to addr (":8080" implies localhost).
// authToken, when non-empty, requires "Authorization: Bearer <authToken>" on
// every request.
func NewStreamableServer(r *runner.Runner, addr, authToken string) *StreamableServer {
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return &StreamableServer{
		runner:    r,
		addr:      addr,
		authToken: authToken,
		sessions:  make(map[string]*httpSession),
	}
}

func (s *StreamableServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", s.handle)

	auth := "disabled"
	if s.authToken != "" {
		auth = "bearer token required"
	}
	fmt.Printf("wrapster: MCP streamable-http server on http://%s/mcp (auth: %s)\n", s.addr, auth)

	srv := &http.Server{Addr: s.addr, Handler: mux}
	return srv.ListenAndServe()
}

func (s *StreamableServer) handle(w http.ResponseWriter, r *http.Request) {
	// DNS-rebinding guard: a browser-set Origin must be loopback. Non-browser
	// MCP clients send no Origin and are allowed.
	origin := r.Header.Get("Origin")
	if !loopbackOrigin(origin) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id, Mcp-Protocol-Version")
	w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.authOK(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r)
	case http.MethodDelete:
		sid := r.Header.Get("Mcp-Session-Id")
		s.mu.Lock()
		delete(s.sessions, sid)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		// GET (server-initiated SSE stream) is optional and not offered.
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *StreamableServer) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		writeJSON(w, &jsonrpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
		return
	}

	// Resolve the session. An initialize with no session header opens a new one
	// and the assigned id is returned in the Mcp-Session-Id response header.
	sid := r.Header.Get("Mcp-Session-Id")
	var sess *httpSession
	if msg.Method == "initialize" && sid == "" {
		sid = generateSessionID()
		sess = &httpSession{cancels: newCancelRegistry(), state: &connState{}}
		s.mu.Lock()
		s.sessions[sid] = sess
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sid)
	} else {
		// Per the Streamable HTTP spec a non-initialize request must carry a
		// session id. Distinguish a missing header (400 Bad Request) from a live
		// header naming an unknown/expired session (404, which tells the client
		// to re-initialize).
		if sid == "" {
			http.Error(w, "missing Mcp-Session-Id header", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		sess = s.sessions[sid]
		s.mu.Unlock()
		if sess == nil {
			http.Error(w, "unknown Mcp-Session-Id (re-initialize)", http.StatusNotFound)
			return
		}
		// 2025-06-18 requires the MCP-Protocol-Version header on post-init
		// requests; reject an explicitly unsupported value. Absent is tolerated
		// and assumed to be the spec default (defaultProtocolVersion).
		if pv := r.Header.Get("MCP-Protocol-Version"); pv != "" && !isSupportedVersion(pv) {
			http.Error(w, "unsupported MCP-Protocol-Version", http.StatusBadRequest)
			return
		}
	}

	// Lifecycle gate: CONNECTED -> INITIALIZING -> READY.
	if reject := gateMethod(sess.state, &msg); reject != nil {
		writeJSON(w, reject)
		return
	}

	// notifications/cancelled cancels an in-flight tool call (mirrors stdio Serve).
	if msg.Method == "notifications/cancelled" {
		var p struct {
			RequestID any `json:"requestId"`
		}
		if msg.Params != nil {
			_ = json.Unmarshal(msg.Params, &p)
		}
		if p.RequestID != nil {
			sess.cancels.cancel(p.RequestID)
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Notifications and responses (no id) get a 202 with no body.
	if msg.ID == nil {
		go handleMessage(s.runner, &msg, sess.cancels, sess.state, dropNotify)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// A request runs in this handler goroutine; net/http serves other POSTs
	// (including notifications/cancelled) concurrently, so a long tool call can
	// still be cancelled mid-flight.
	resp := handleMessage(s.runner, &msg, sess.cancels, sess.state, dropNotify)
	writeJSON(w, resp)
}

func (s *StreamableServer) authOK(r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(s.authToken)) == 1
}

// loopbackOrigin reports whether a browser Origin header targets the local
// machine. An empty Origin (non-browser client) is allowed.
func loopbackOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, resp *jsonrpcResponse) {
	if resp == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	data, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// dropNotify discards progress notifications on the JSON response path.
var dropNotify = notifyFunc(func(string, any) {})
