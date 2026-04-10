package mcp

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/hed0rah/wrapster/internal/runner"
)

// gzipSSEWriter wraps a gzip.Writer + ResponseWriter so that Flush() drains
// the gzip compressor (BSYNC flush) before flushing the underlying HTTP layer.
// This is required for SSE: each event must be immediately decodable by the client.
type gzipSSEWriter struct {
	gz *gzip.Writer
	w  http.ResponseWriter
	f  http.Flusher
}

func (g *gzipSSEWriter) Header() http.Header         { return g.w.Header() }
func (g *gzipSSEWriter) Write(b []byte) (int, error) { return g.gz.Write(b) }
func (g *gzipSSEWriter) WriteHeader(code int)        { g.w.WriteHeader(code) }

func (g *gzipSSEWriter) Flush() {
	g.gz.Flush() // sync flush -- compressor state survives, output decodable
	g.f.Flush()  // push bytes to the client over HTTP
}

// SSEServer runs an MCP server over HTTP with Server-Sent Events transport.
// Implements the legacy (2024-11-05) SSE spec: GET /sse for event stream,
// POST /message?sessionId=X for client requests.
type SSEServer struct {
	runner   *runner.Runner
	addr     string
	mu       sync.Mutex
	sessions map[string]*sseSession
}

type sseSession struct {
	id     string
	ch     chan []byte
	ctx    context.Context
	cancel context.CancelFunc
}

func NewSSEServer(r *runner.Runner, addr string) *SSEServer {
	// Default to localhost if only port given.
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return &SSEServer{
		runner:   r,
		addr:     addr,
		sessions: make(map[string]*sseSession),
	}
}

func (s *SSEServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", s.handleSSE)
	mux.HandleFunc("/message", s.handleMessage)

	fmt.Fprintf(io.Discard, "") // ensure io is used
	fmt.Printf("wrapster: MCP SSE server listening on %s\n", s.addr)

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

func (s *SSEServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Wrap with gzip if the client supports it. Must happen before any header writes.
	var fw http.Flusher = flusher
	var ww http.ResponseWriter = w
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		gw := &gzipSSEWriter{gz: gz, w: w, f: flusher}
		ww = gw
		fw = gw
	}

	sessionID := generateSessionID()
	ctx, cancel := context.WithCancel(r.Context())

	sess := &sseSession{
		id:     sessionID,
		ch:     make(chan []byte, 64),
		ctx:    ctx,
		cancel: cancel,
	}

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		cancel()
	}()

	ww.Header().Set("Content-Type", "text/event-stream")
	ww.Header().Set("Cache-Control", "no-cache")
	ww.Header().Set("Connection", "keep-alive")
	ww.Header().Set("X-Accel-Buffering", "no")
	ww.Header().Set("Access-Control-Allow-Origin", "*")

	// Send endpoint event with full URL -- some clients require absolute URL.
	scheme := "http"
	host := r.Host
	if host == "" {
		host = s.addr
	}
	endpointURL := fmt.Sprintf("%s://%s/message?sessionId=%s", scheme, host, sessionID)
	fmt.Fprintf(ww, "event: endpoint\ndata: %s\n\n", endpointURL)
	fw.Flush()

	for {
		select {
		case msg := <-sess.ch:
			fmt.Fprintf(ww, "event: message\ndata: %s\n\n", msg)
			fw.Flush()
		case <-ctx.Done():
			return
		}
	}
}

func (s *SSEServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	s.mu.Unlock()

	if !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var msgVal jsonrpcMessage
	if err := json.Unmarshal(body, &msgVal); err != nil {
		http.Error(w, "parse error", http.StatusBadRequest)
		return
	}
	msg := &msgVal

	// Return 202 immediately per spec.
	w.WriteHeader(http.StatusAccepted)

	// Handle in a goroutine; push response to the SSE stream.
	go func() {
		response := handleMessage(s.runner, msg)
		if response != nil {
			data, err := json.Marshal(response)
			if err != nil {
				return
			}
			select {
			case sess.ch <- data:
			case <-sess.ctx.Done():
			}
		}
	}()
}

func generateSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
