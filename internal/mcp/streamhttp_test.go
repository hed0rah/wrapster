package mcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// post sends a JSON-RPC body to the streamable-http handler and returns the
// response plus body.
func post(t *testing.T, url, body, sid, auth string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(data)
}

func TestStreamableHandshake(t *testing.T) {
	s := NewStreamableServer(testRunner(t), ":0", "")
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	defer srv.Close()

	// initialize -> 200 and a session id
	resp, body := post(t, srv.URL, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize status = %d, want 200", resp.StatusCode)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize did not return Mcp-Session-Id")
	}
	if !strings.Contains(body, "serverInfo") {
		t.Errorf("initialize body missing serverInfo: %s", body)
	}

	// tools/list before notifications/initialized is gated
	if _, body := post(t, srv.URL, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, sid, ""); !strings.Contains(body, "error") {
		t.Errorf("tools/list before init should be gated, got: %s", body)
	}

	// notifications/initialized -> 202
	if resp, _ := post(t, srv.URL, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, sid, ""); resp.StatusCode != http.StatusAccepted {
		t.Errorf("notifications/initialized status = %d, want 202", resp.StatusCode)
	}

	// tools/list now works
	if resp, body := post(t, srv.URL, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`, sid, ""); resp.StatusCode != http.StatusOK || !strings.Contains(body, "tools") {
		t.Errorf("tools/list status = %d body = %s", resp.StatusCode, body)
	}

	// unknown session -> 404
	if resp, _ := post(t, srv.URL, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`, "bogus", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session status = %d, want 404", resp.StatusCode)
	}
}

func TestStreamableAuth(t *testing.T) {
	s := NewStreamableServer(testRunner(t), ":0", "sekret")
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	defer srv.Close()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`

	if resp, _ := post(t, srv.URL, body, "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token status = %d, want 401", resp.StatusCode)
	}
	if resp, _ := post(t, srv.URL, body, "", "Bearer nope"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token status = %d, want 401", resp.StatusCode)
	}
	if resp, _ := post(t, srv.URL, body, "", "Bearer sekret"); resp.StatusCode != http.StatusOK {
		t.Errorf("correct token status = %d, want 200", resp.StatusCode)
	}
}

func TestLoopbackOrigin(t *testing.T) {
	cases := map[string]bool{
		"":                      true, // non-browser client
		"http://localhost:3000": true,
		"http://127.0.0.1":      true,
		"http://[::1]:9000":     true,
		"http://evil.example":   false,
		"https://example.com":   false,
	}
	for origin, want := range cases {
		if got := loopbackOrigin(origin); got != want {
			t.Errorf("loopbackOrigin(%q) = %v, want %v", origin, got, want)
		}
	}
}
