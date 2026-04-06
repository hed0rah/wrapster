package runner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/filter"
	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/ssh"
)

// RunResult is the full outcome of a command attempt.
type RunResult struct {
	Allowed    bool             `json:"allowed"`
	Reason     string           `json:"reason"`
	Stdout     string           `json:"stdout,omitempty"`
	Stderr     string           `json:"stderr,omitempty"`
	ExitCode   int              `json:"exit_code,omitempty"`
	TimedOut   bool             `json:"timed_out,omitempty"`
	DurationMs int64            `json:"duration_ms,omitempty"`
	Error      string           `json:"error,omitempty"`
	Findings   []filter.Finding `json:"findings,omitempty"`
}

// Runner holds shared state for executing validated commands.
type Runner struct {
	Policy       *policy.Policy
	Logger       *audit.Logger
	Filters      *filter.Chain
	OutputStats  *output.Tracker
}

// OutputConfig returns the output processing config from the policy.
func (r *Runner) OutputConfig() output.Config {
	p := r.Policy.Output
	return output.Config{
		ANSIStrip: p.ANSIStrip,
		Truncate: output.TruncateConfig{
			Enabled:   p.Truncate.Enabled,
			MaxChars:  p.Truncate.MaxChars,
			HeadLines: p.Truncate.HeadLines,
			TailLines: p.Truncate.TailLines,
		},
		Stats: p.Stats,
	}
}

// Exec validates and runs a command on a remote host via SSH.
func (r *Runner) Exec(ctx context.Context, host, command string, extraSSHArgs []string) RunResult {
	resolved := r.Policy.ResolvedPolicy(host)
	validation := policy.ValidateCommand(command, resolved, policy.ModeAllowlist)

	if !validation.Allowed {
		r.Logger.Log(audit.Entry{
			Host:    host,
			Command: command,
			Allowed: false,
			Reason:  validation.Reason,
		})
		return RunResult{
			Allowed: false,
			Reason:  validation.Reason,
		}
	}

	// Filter chain -- catches exploit techniques that pass policy.
	if r.Filters != nil {
		findings := r.Filters.Block(command)
		if len(findings) > 0 {
			reason := formatFindings(findings)
			r.Logger.Log(audit.Entry{
				Host:    host,
				Command: command,
				Allowed: false,
				Reason:  reason,
			})
			return RunResult{
				Allowed:  false,
				Reason:   reason,
				Findings: findings,
			}
		}
	}

	sshHost := host
	if resolved.Hostname != "" {
		sshHost = resolved.Hostname
	}

	start := time.Now()
	result, err := ssh.Exec(ctx, ssh.ExecOptions{
		Host:         sshHost,
		Command:      command,
		Policy:       resolved,
		ExtraSSHArgs: extraSSHArgs,
	})
	elapsed := time.Since(start)

	if err != nil {
		r.Logger.Log(audit.Entry{
			Host:       host,
			Command:    command,
			Allowed:    true,
			Reason:     validation.Reason,
			DurationMs: elapsed.Milliseconds(),
		})
		return RunResult{
			Allowed:    true,
			Reason:     validation.Reason,
			DurationMs: elapsed.Milliseconds(),
			Error:      err.Error(),
		}
	}

	exitCode := result.ExitCode
	r.Logger.Log(audit.Entry{
		Host:       host,
		Command:    command,
		Allowed:    true,
		Reason:     validation.Reason,
		ExitCode:   &exitCode,
		TimedOut:   result.TimedOut,
		OutputHash: audit.HashOutput(result.Stdout, result.Stderr),
		DurationMs: elapsed.Milliseconds(),
	})

	return RunResult{
		Allowed:    true,
		Reason:     validation.Reason,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		ExitCode:   result.ExitCode,
		TimedOut:   result.TimedOut,
		DurationMs: elapsed.Milliseconds(),
	}
}

// ExecLocal validates and runs a command on the local machine.
func (r *Runner) ExecLocal(ctx context.Context, command string) RunResult {
	lc := r.Policy.Local

	mode := policy.ModeGuardrail
	if lc.Mode == "allowlist" {
		mode = policy.ModeAllowlist
	}

	// Build a synthetic HostPolicy for the validator.
	hp := policy.HostPolicy{
		AllowedCommands:     lc.AllowedCommands,
		DeniedPatterns:      lc.DeniedPatterns,
		AllowShellOperators: lc.AllowShellOperators,
		Timeout:             lc.Timeout,
		MaxOutputBytes:      lc.MaxOutputBytes,
	}

	validation := policy.ValidateCommand(command, hp, mode)
	if !validation.Allowed {
		r.Logger.Log(audit.Entry{
			Host:    "local",
			Command: command,
			Allowed: false,
			Reason:  validation.Reason,
		})
		return RunResult{
			Allowed: false,
			Reason:  validation.Reason,
		}
	}

	// Filter chain.
	if r.Filters != nil {
		findings := r.Filters.Block(command)
		if len(findings) > 0 {
			reason := formatFindings(findings)
			r.Logger.Log(audit.Entry{
				Host:    "local",
				Command: command,
				Allowed: false,
				Reason:  reason,
			})
			return RunResult{
				Allowed:  false,
				Reason:   reason,
				Findings: findings,
			}
		}
	}

	start := time.Now()
	result, err := execLocal(ctx, command, lc)
	elapsed := time.Since(start)

	if err != nil {
		r.Logger.Log(audit.Entry{
			Host:       "local",
			Command:    command,
			Allowed:    true,
			Reason:     validation.Reason,
			DurationMs: elapsed.Milliseconds(),
		})
		return RunResult{
			Allowed:    true,
			Reason:     validation.Reason,
			DurationMs: elapsed.Milliseconds(),
			Error:      err.Error(),
		}
	}

	exitCode := result.ExitCode
	r.Logger.Log(audit.Entry{
		Host:       "local",
		Command:    command,
		Allowed:    true,
		Reason:     validation.Reason,
		ExitCode:   &exitCode,
		TimedOut:   result.TimedOut,
		OutputHash: audit.HashOutput(result.Stdout, result.Stderr),
		DurationMs: elapsed.Milliseconds(),
	})

	return RunResult{
		Allowed:    true,
		Reason:     validation.Reason,
		Stdout:     result.Stdout,
		Stderr:     result.Stderr,
		ExitCode:   result.ExitCode,
		TimedOut:   result.TimedOut,
		DurationMs: elapsed.Milliseconds(),
	}
}

// Validate checks a command without executing it (includes filters).
func (r *Runner) Validate(host, command string) RunResult {
	resolved := r.Policy.ResolvedPolicy(host)
	validation := policy.ValidateCommand(command, resolved, policy.ModeAllowlist)

	if !validation.Allowed {
		return RunResult{
			Allowed: false,
			Reason:  validation.Reason,
		}
	}

	if r.Filters != nil {
		findings := r.Filters.Block(command)
		if len(findings) > 0 {
			return RunResult{
				Allowed:  false,
				Reason:   formatFindings(findings),
				Findings: findings,
			}
		}
	}

	return RunResult{
		Allowed: validation.Allowed,
		Reason:  validation.Reason,
	}
}

// BatchResult holds results for a batch of commands.
type BatchResult struct {
	Results    []RunResult `json:"results"`
	TotalMs    int64       `json:"total_ms"`
	Succeeded  int         `json:"succeeded"`
	Failed     int         `json:"failed"`
	Blocked    int         `json:"blocked"`
}

// BatchExec runs multiple commands on a remote host sequentially.
// Each command is individually validated. With ControlMaster enabled,
// all commands share a single SSH connection.
func (r *Runner) BatchExec(ctx context.Context, host string, commands []string, extraSSHArgs []string) BatchResult {
	start := time.Now()
	br := BatchResult{
		Results: make([]RunResult, len(commands)),
	}
	for i, cmd := range commands {
		br.Results[i] = r.Exec(ctx, host, cmd, extraSSHArgs)
		res := br.Results[i]
		if !res.Allowed {
			br.Blocked++
		} else if res.Error != "" || res.ExitCode != 0 {
			br.Failed++
		} else {
			br.Succeeded++
		}
	}
	br.TotalMs = time.Since(start).Milliseconds()
	return br
}

// BatchExecLocal runs multiple commands locally in sequence.
func (r *Runner) BatchExecLocal(ctx context.Context, commands []string) BatchResult {
	start := time.Now()
	br := BatchResult{
		Results: make([]RunResult, len(commands)),
	}
	for i, cmd := range commands {
		br.Results[i] = r.ExecLocal(ctx, cmd)
		res := br.Results[i]
		if !res.Allowed {
			br.Blocked++
		} else if res.Error != "" || res.ExitCode != 0 {
			br.Failed++
		} else {
			br.Succeeded++
		}
	}
	br.TotalMs = time.Since(start).Milliseconds()
	return br
}

// ListAllowed returns the resolved policy for a host.
func (r *Runner) ListAllowed(host string) policy.HostPolicy {
	return r.Policy.ResolvedPolicy(host)
}

func formatFindings(findings []filter.Finding) string {
	if len(findings) == 1 {
		f := findings[0]
		return fmt.Sprintf("BLOCKED by %s filter: %s technique detected (%s)", f.Module, f.Function, f.Detail)
	}
	var parts []string
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("%s/%s", f.Module, f.Function))
	}
	return fmt.Sprintf("BLOCKED by security filters: %d techniques detected (%s)", len(findings), strings.Join(parts, ", "))
}
