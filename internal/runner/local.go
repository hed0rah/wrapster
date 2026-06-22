package runner

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/proc"
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
	timeout := lc.Timeout.Std()
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
	proc.SetProcGroup(cmd) // on timeout, kill the whole tree, not just the shell

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

	// Streaming sinks: os/exec drains stdout/stderr into these as the process
	// runs, sanitizing and byte-capping on the fly instead of buffering raw to
	// completion. nil callback -> accumulate only (the MCP layer wires a live
	// chunk consumer for streaming).
	stdout := output.NewStreamWriter(lc.MaxOutputBytes, output.SinkFor(ctx, "stdout"))
	stderr := output.NewStreamWriter(lc.MaxOutputBytes, output.SinkFor(ctx, "stderr"))
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	stdout.Close()
	stderr.Close()

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
