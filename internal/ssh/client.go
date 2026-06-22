package ssh

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/proc"
)

// Result holds the outcome of a remote command execution.
type Result struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

// ExecOptions configures a single command execution.
type ExecOptions struct {
	Host         string
	Command      string
	Policy       policy.HostPolicy
	ExtraSSHArgs []string
}

// Exec runs a validated command on a remote host via the system ssh binary.
// This delegates to the real OpenSSH client so we get agent forwarding,
// ProxyJump, config file support, etc. for free.
func Exec(ctx context.Context, opts ExecOptions) (*Result, error) {
	timeout := opts.Policy.Timeout.Std()
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := buildSSHArgs(opts)
	args = append(args, wrapWithEnv(opts.Command, opts.Policy.Environment))

	sshBin := findSSH()
	cmd := exec.CommandContext(ctx, sshBin, args...)
	proc.SetProcGroup(cmd) // on timeout, kill the local ssh process tree
	// Ensure SSH has the environment it needs. On Windows, Claude Desktop
	// and other MCP hosts may spawn us with a minimal env that's missing
	// system vars SSH depends on (like SystemRoot for DLL loading).
	cmd.Env = ensureSSHEnv(os.Environ())

	// Streaming sinks over the local ssh child's pipes: sanitize and byte-cap on
	// the fly rather than buffering raw to completion. Same model as local exec
	// (it is just another exec.Cmd); nil callback accumulates only.
	stdout := output.NewStreamWriter(opts.Policy.MaxOutputBytes, nil)
	stderr := output.NewStreamWriter(opts.Policy.MaxOutputBytes, nil)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	stdout.Close()
	stderr.Close()

	result := &Result{
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
			// Include stderr in the error for diagnostics
			return nil, fmt.Errorf("ssh exec failed: %w (stderr: %s)", err, stderr.String())
		}
	}

	return result, nil
}

// controlDir is the directory for SSH ControlMaster sockets.
// Unix only -- Windows OpenSSH does not support ControlMaster.
var controlDir string

func init() {
	if runtime.GOOS == "windows" {
		return
	}
	controlDir = os.TempDir() + "/wrapster-ssh"
	os.MkdirAll(controlDir, 0700)
}

// controlSocketPath returns the ControlPath for a given host+user+port.
func controlSocketPath(host, user string, port int) string {
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s/%s@%s:%d", controlDir, user, host, port)
}

// ClosePool terminates all active ControlMaster connections.
// Call on shutdown for clean cleanup.
func ClosePool() {
	if controlDir == "" {
		return
	}
	entries, err := os.ReadDir(controlDir)
	if err != nil {
		return
	}
	sshBin := findSSH()
	for _, e := range entries {
		sock := controlDir + "/" + e.Name()
		// -O exit tells the master to shut down gracefully
		cmd := exec.Command(sshBin, "-o", "ControlPath="+sock, "-O", "exit", "dummy")
		cmd.Run() // best-effort
	}
	os.RemoveAll(controlDir)
}

func buildSSHArgs(opts ExecOptions) []string {
	var args []string

	// Disable pseudo-terminal allocation, batch mode.
	args = append(args, "-T")
	args = append(args, "-o", "BatchMode=yes")

	// Connection multiplexing (Unix only).
	// ControlMaster=auto: become master if none exists, reuse if one does.
	// ControlPersist=60: master stays alive 60s after last connection closes.
	if controlDir != "" {
		sock := controlSocketPath(opts.Host, opts.Policy.User, opts.Policy.Port)
		args = append(args, "-o", "ControlMaster=auto")
		args = append(args, "-o", "ControlPath="+sock)
		args = append(args, "-o", "ControlPersist=60")
	}

	// Connection settings from policy.
	if opts.Policy.User != "" {
		args = append(args, "-l", opts.Policy.User)
	}
	if opts.Policy.Port != 0 {
		args = append(args, "-p", strconv.Itoa(opts.Policy.Port))
	}
	if opts.Policy.IdentityFile != "" {
		expanded := expandHome(opts.Policy.IdentityFile)
		args = append(args, "-i", expanded)
	}

	// SSH options from policy.
	for k, v := range opts.Policy.SSHOptions {
		args = append(args, "-o", k+"="+v)
	}

	// extra args from CLI (validated -- no host/command injection possible
	// since host is positional and command is the final arg).
	args = append(args, opts.ExtraSSHArgs...)

	// Host is always second-to-last (before the command).
	args = append(args, opts.Host)

	return args
}

// wrapWithEnv prepends export statements to a command when environment vars
// are configured. Values can reference existing vars (e.g. "$PATH") which the
// remote shell expands at execution time.
func wrapWithEnv(command string, env map[string]string) string {
	if len(env) == 0 {
		return command
	}
	// Sort keys for deterministic output (nice for audit logs).
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		// Single-quote the value to prevent local expansion, but allow
		// remote $VAR references by using double quotes on the remote side.
		// we use export K=V with no quoting tricks -- the value is meant
		// to be interpreted by the remote shell (that's the whole point).
		parts = append(parts, fmt.Sprintf("export %s=%s", k, env[k]))
	}
	parts = append(parts, command)
	return strings.Join(parts, "; ")
}

// ensureSSHEnv makes sure the environment has the vars SSH needs to run.
// On Windows, if SystemRoot is missing, SSH can't load DLLs and exits 255.
func ensureSSHEnv(env []string) []string {
	if runtime.GOOS != "windows" {
		return env
	}

	has := make(map[string]bool)
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok {
			has[strings.ToUpper(k)] = true
		}
	}

	home, _ := os.UserHomeDir()

	// Windows OpenSSH needs these to load DLLs, find config, and write temp files.
	// MCP hosts like Claude Desktop often spawn processes with minimal environments.
	defaults := map[string]string{
		"SYSTEMROOT":  `C:\Windows`,
		"USERPROFILE": home,
		"APPDATA":     home + `\AppData\Roaming`,
		"PROGRAMDATA": `C:\ProgramData`,
		"TEMP":        home + `\AppData\Local\Temp`,
		"TMP":         home + `\AppData\Local\Temp`,
	}
	for k, v := range defaults {
		if !has[strings.ToUpper(k)] && v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// findSSH locates the ssh binary. On Windows, the system OpenSSH at
// C:\Windows\System32\OpenSSH\ssh.exe is preferred since it's always
// available regardless of PATH (Claude Desktop, MCP servers, etc. may
// not inherit Git bash's PATH).
func findSSH() string {
	if runtime.GOOS == "windows" {
		candidates := []string{
			`C:\Windows\System32\OpenSSH\ssh.exe`,
			`C:\Program Files\Git\usr\bin\ssh.exe`,
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				return c
			}
		}
	}
	// On Unix or if Windows candidates fail, use PATH lookup.
	return "ssh"
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return home + path[1:]
		}
	}
	return path
}
