package runner

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/hed0rah/wrapster/internal/policy"
)

// localResult mirrors ssh.Result for local commands.
type localResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// execLocal runs a command on the local machine using the system shell.
func execLocal(ctx context.Context, command string, lc policy.LocalConfig) (*localResult, error) {
	timeout := lc.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	if lc.WorkDir != "" {
		cmd.Dir = lc.WorkDir
	}

	// Merge environment.
	if len(lc.Environment) > 0 {
		env := os.Environ()
		for k, v := range lc.Environment {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	maxOut := lc.MaxOutputBytes
	if maxOut <= 0 {
		maxOut = 1 << 20 // 1 MiB
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, limit: maxOut}
	cmd.Stderr = &limitedWriter{w: &stderr, limit: maxOut}

	err := cmd.Run()

	result := &localResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		return result, nil
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, err
		}
	}

	return result, nil
}

// limitedWriter wraps a writer and stops writing after limit bytes.
// Duplicated from ssh/client.go to avoid import cycle.
type limitedWriter struct {
	w       io.Writer
	limit   int
	written int
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.written
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := lw.w.Write(p)
	lw.written += n
	return n, err
}

