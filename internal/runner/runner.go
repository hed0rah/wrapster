package runner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/bufstore"
	"github.com/hed0rah/wrapster/internal/cache"
	"github.com/hed0rah/wrapster/internal/filter"
	"github.com/hed0rah/wrapster/internal/hostinfo"
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
	// Cached is true when this result was served from the result cache.
	Cached    bool   `json:"cached,omitempty"`
	CacheHash string `json:"cache_hash,omitempty"`
}

// Runner holds shared state for executing validated commands.
type Runner struct {
	Policy        *policy.Policy
	Logger        *audit.Logger
	Filters       *filter.Chain
	OutputStats   *output.Tracker
	ResultCache   *cache.ResultCache
	BufStore      *bufstore.Store
	HostInfoCache *hostinfo.Cache
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

// ReachResult reports TCP reachability of a host.
type ReachResult struct {
	Host       string `json:"host"`            // policy host name probed
	Address    string `json:"address"`         // resolved host:port actually dialed
	Reachable  bool   `json:"reachable"`       // true if the TCP handshake completed
	DurationMs int64  `json:"duration_ms"`     // time spent dialing
	Error      string `json:"error,omitempty"` // dial error (refused, timeout, ...)
}

// Reach probes TCP reachability of a policy host. It resolves the host's
// hostname and port from the policy (port override optional), then attempts a
// TCP connect. It is limited to policy-defined hosts -- a connect-only probe,
// no data is sent. This is a fast diagnostic (default 5s) versus a full SSH
// attempt: it answers "is the port open" without the multi-second SSH timeout.
func (r *Runner) Reach(ctx context.Context, host string, port int) ReachResult {
	res := ReachResult{Host: host}
	if r.Policy == nil {
		res.Error = "no policy loaded"
		return res
	}
	if _, ok := r.Policy.Hosts[host]; !ok {
		res.Error = fmt.Sprintf("unknown host %q (reach is limited to policy hosts)", host)
		return res
	}

	resolved := r.Policy.ResolvedPolicy(host)
	target := host
	if resolved.Hostname != "" {
		target = resolved.Hostname
	}
	if port == 0 {
		port = resolved.Port
	}
	if port == 0 {
		port = 22
	}
	res.Address = net.JoinHostPort(target, strconv.Itoa(port))

	timeout := 5 * time.Second
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", res.Address)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	conn.Close()
	res.Reachable = true
	return res
}

// DiscoveredHost is an address found accepting connections during a scan.
type DiscoveredHost struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// DiscoverResult is the outcome of a subnet scan.
type DiscoverResult struct {
	CIDR       string           `json:"cidr"`
	Port       int              `json:"port"`
	Scanned    int              `json:"scanned"`
	Found      []DiscoveredHost `json:"found"`
	DurationMs int64            `json:"duration_ms"`
}

// Discover scans an IPv4 subnet for hosts accepting TCP on a port (default 22)
// to seed the policy host inventory. It is connect-only (no data is sent) and
// bounded: at most a /24 (256 addresses), a short per-host timeout, and limited
// concurrency. It refuses larger ranges -- this is lab discovery, not a scanner.
func (r *Runner) Discover(ctx context.Context, cidr string, port int) (DiscoverResult, error) {
	if port == 0 {
		port = 22
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return DiscoverResult{}, fmt.Errorf("invalid cidr %q: %w", cidr, err)
	}
	if ipnet.IP.To4() == nil {
		return DiscoverResult{}, fmt.Errorf("only IPv4 ranges are supported")
	}
	if ones, bits := ipnet.Mask.Size(); bits-ones > 8 {
		return DiscoverResult{}, fmt.Errorf("range too large: %s (limit is a /24, 256 addresses)", cidr)
	}

	var ips []string
	for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	res := DiscoverResult{CIDR: cidr, Port: port, Scanned: len(ips)}
	start := time.Now()
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	addrPort := strconv.Itoa(port)

	sem := make(chan struct{}, 32) // bound concurrency
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, addrPort))
			if err != nil {
				return
			}
			conn.Close()
			mu.Lock()
			res.Found = append(res.Found, DiscoveredHost{Address: ip, Port: port})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	res.DurationMs = time.Since(start).Milliseconds()
	sort.Slice(res.Found, func(i, j int) bool { return res.Found[i].Address < res.Found[j].Address })
	return res, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// Exec validates and runs a command on a remote host via SSH.
func (r *Runner) Exec(ctx context.Context, host, command string, extraSSHArgs []string) RunResult {
	resolved := r.Policy.ResolvedPolicy(host)
	mode := policy.ModeAllowlist
	if resolved.Trusted {
		// trusted host: full shell. guardrail validation keeps the hard-denies
		// and the filter chain, but allows pipes, redirects, and substitution.
		mode = policy.ModeGuardrail
		resolved.AllowShellOperators = true
	}
	validation := policy.ValidateCommand(command, resolved, mode)

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
		findings := r.Filters.Block(policy.NormalizeForMatch(command))
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
		findings := r.Filters.Block(policy.NormalizeForMatch(command))
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
	mode := policy.ModeAllowlist
	if resolved.Trusted {
		// trusted host: full shell. guardrail validation keeps the hard-denies
		// and the filter chain, but allows pipes, redirects, and substitution.
		mode = policy.ModeGuardrail
		resolved.AllowShellOperators = true
	}
	validation := policy.ValidateCommand(command, resolved, mode)

	if !validation.Allowed {
		return RunResult{
			Allowed: false,
			Reason:  validation.Reason,
		}
	}

	if r.Filters != nil {
		findings := r.Filters.Block(policy.NormalizeForMatch(command))
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
	Results   []RunResult `json:"results"`
	TotalMs   int64       `json:"total_ms"`
	Succeeded int         `json:"succeeded"`
	Failed    int         `json:"failed"`
	Blocked   int         `json:"blocked"`
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

// ExecRawLocal runs a command on the local machine without policy validation.
// Intended for internal use (e.g. find_files, grep_files tools) where the
// caller constructs the command from sanitized inputs.
func (r *Runner) ExecRawLocal(ctx context.Context, command string) (string, string, error) {
	result, err := execLocal(ctx, command, r.Policy.Local)
	if err != nil {
		return "", "", err
	}
	return result.Stdout, result.Stderr, nil
}

// ExecRaw runs a command on a host and returns (stdout, stderr, error) without
// policy validation. Intended for internal probing (e.g. host_info fingerprinting)
// where the caller is responsible for constructing safe commands.
func (r *Runner) ExecRaw(ctx context.Context, host, command string) (string, string, error) {
	resolved := r.Policy.ResolvedPolicy(host)
	sshHost := host
	if resolved.Hostname != "" {
		sshHost = resolved.Hostname
	}
	result, err := ssh.Exec(ctx, ssh.ExecOptions{
		Host:    sshHost,
		Command: command,
		Policy:  resolved,
	})
	if err != nil {
		return "", "", err
	}
	return result.Stdout, result.Stderr, nil
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
