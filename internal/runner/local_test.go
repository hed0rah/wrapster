package runner

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/hed0rah/wrapster/internal/policy"
)

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
