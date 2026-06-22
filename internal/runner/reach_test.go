package runner

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/hed0rah/wrapster/internal/policy"
)

// TestReach exercises the TCP reachability probe: a live listener is reachable,
// a closed port is not, an unknown host is rejected, and a port override wins.
func TestReach(t *testing.T) {
	// live listener -> reachable
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	upPort := ln.Addr().(*net.TCPAddr).Port

	// a port we open then immediately close -> nothing listening -> refused
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downPort := ln2.Addr().(*net.TCPAddr).Port
	ln2.Close()

	r := &Runner{Policy: &policy.Policy{
		Hosts: map[string]policy.HostPolicy{
			"up":     {Hostname: "127.0.0.1", Port: upPort},
			"closed": {Hostname: "127.0.0.1", Port: downPort},
			// configured port is closed, but a test below overrides it to upPort
			"override": {Hostname: "127.0.0.1", Port: downPort},
		},
	}}
	ctx := context.Background()

	if res := r.Reach(ctx, "up", 0); !res.Reachable {
		t.Errorf("up: expected reachable, got %+v", res)
	}
	if res := r.Reach(ctx, "closed", 0); res.Reachable {
		t.Errorf("closed: expected unreachable, got %+v", res)
	}
	if res := r.Reach(ctx, "override", upPort); !res.Reachable {
		t.Errorf("override: expected reachable via port override, got %+v", res)
	}

	res := r.Reach(ctx, "ghost", 0)
	if res.Reachable || !strings.Contains(res.Error, "unknown host") {
		t.Errorf("ghost: expected unknown-host error, got %+v", res)
	}
}
