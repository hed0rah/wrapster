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

func TestDiscover(t *testing.T) {
	// a listener on loopback so at least 127.0.0.1 is found on its port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	r := &Runner{}
	ctx := context.Background()

	res, err := r.Discover(ctx, "127.0.0.0/30", port) // 4 addresses incl. 127.0.0.1
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if res.Scanned != 4 {
		t.Errorf("scanned = %d, want 4", res.Scanned)
	}
	found := false
	for _, h := range res.Found {
		if h.Address == "127.0.0.1" && h.Port == port {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find 127.0.0.1:%d, got %+v", port, res.Found)
	}

	// ranges larger than /24 are refused.
	if _, err := r.Discover(ctx, "10.0.0.0/16", port); err == nil {
		t.Error("expected an error for a range larger than /24")
	}
	// IPv6 is refused.
	if _, err := r.Discover(ctx, "::1/128", port); err == nil {
		t.Error("expected an error for an IPv6 range")
	}
}
