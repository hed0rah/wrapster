package runner

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hed0rah/wrapster/internal/policy"
)

// TestExecLocalStreamsAndSanitizes verifies plain output round-trips through the
// streaming sink and that escape sequences in output are stripped end-to-end.
func TestExecLocalStreamsAndSanitizes(t *testing.T) {
	lc := policy.LocalConfig{}

	res, err := execLocal(context.Background(), "echo hello", lc)
	if err != nil {
		t.Fatalf("execLocal: %v", err)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("stdout = %q, want to contain hello", res.Stdout)
	}

	// cmd.exe cannot easily emit a raw ESC byte; the escape path is unix-only.
	if runtime.GOOS != "windows" {
		res, err := execLocal(context.Background(), `printf 'a\033[31mb\033[0m'`, lc)
		if err != nil {
			t.Fatalf("execLocal: %v", err)
		}
		if res.Stdout != "ab" {
			t.Errorf("sanitized stdout = %q, want %q", res.Stdout, "ab")
		}
	}
}

// TestExecLocalTimeoutReturnsPromptly verifies that a command exceeding the
// timeout is cancelled and reaped within the WaitDelay bound (it does not hang),
// exercising the process-tree kill path.
func TestExecLocalTimeoutReturnsPromptly(t *testing.T) {
	lc := policy.LocalConfig{Timeout: policy.Duration(500 * time.Millisecond)}
	cmd := "sleep 10"
	if runtime.GOOS == "windows" {
		cmd = "ping -n 12 127.0.0.1"
	}

	start := time.Now()
	res, err := execLocal(context.Background(), cmd, lc)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("execLocal error: %v", err)
	}
	if !res.TimedOut {
		t.Errorf("expected TimedOut=true, got %+v", res)
	}
	// 500ms timeout + up to 3s WaitDelay; must be well under that, never hang.
	if elapsed > 5*time.Second {
		t.Errorf("timed-out command took %v to return (kill path may be hanging)", elapsed)
	}
}
