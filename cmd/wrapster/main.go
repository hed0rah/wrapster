package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hed0rah/wrapster/internal/audit"
	"github.com/hed0rah/wrapster/internal/bufstore"
	"github.com/hed0rah/wrapster/internal/cache"
	"github.com/hed0rah/wrapster/internal/filter"
	"github.com/hed0rah/wrapster/internal/hostinfo"
	"github.com/hed0rah/wrapster/internal/mcp"
	"github.com/hed0rah/wrapster/internal/output"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/runner"
	"github.com/hed0rah/wrapster/internal/ssh"
	"github.com/hed0rah/wrapster/internal/wizard"
)

const usage = `wrapster -- secure command gateway for LLMs

Usage:
  wrapster [flags] <host> <command>       SSH exec (allowlist mode)
  wrapster [flags] local <command>        Local exec (guardrail mode)

Modes:
  wrapster config                         Interactive TUI config wizard (alias: setup)
  wrapster --mcp                          MCP server over stdio
  wrapster --mcp-sse :8080                MCP server over HTTP SSE
  wrapster --watch 30s <host> <cmd>       Poll a command on an interval

Flags:
  -p, --policy <path>       Policy file (default: ./policy.yaml, then ~/.config/wrapster/policy.yaml)
  -a, --audit  <path>       Audit log file (default: stderr)
  -j, --json                Output result as JSON
  -n, --dry-run             Validate command without executing
  -l, --list                List allowed commands for a host
  -s, --ssh-args <args>     Extra SSH args (comma-separated)
  -w, --watch <interval>    Poll interval (e.g. 30s, 1m, 5m)
      --mcp                 MCP server over stdio
      --mcp-sse <addr>      MCP server over HTTP SSE (e.g. :8080, 127.0.0.1:8080)
      --cache-ttl <dur>     Result cache TTL (default: 30s)
      --hostinfo-ttl <dur>  Host info cache TTL (default: 30m)
      --bufstore-max <n>    Max output buffer entries (default: 64)
      --version             Show version and exit
  -h, --help                Show this help

Examples:
  wrapster prod-web "uptime"
  wrapster local "ls -la"
  wrapster --json local "docker ps"
  wrapster --mcp --policy ./policy.yaml
  wrapster --mcp-sse :8080 --policy ./policy.yaml
`

type config struct {
	policyPath   string
	auditPath    string
	jsonOutput   bool
	dryRun       bool
	listMode     bool
	mcpMode      bool
	mcpSSEAddr   string
	sshArgs      []string
	watch        time.Duration
	host         string
	command      string
	cacheTTL     time.Duration
	hostinfoTTL  time.Duration
	bufstoreMax  int
	showVersion  bool
}

func main() {
	// `config` / `setup` are reserved first words (like the `local` host) that
	// launch the interactive wizard; intercept before the flag parser treats
	// them as a host.
	if args := os.Args[1:]; len(args) > 0 && (args[0] == "config" || args[0] == "setup") {
		policyPath := ""
		rest := args[1:]
		for i := 0; i < len(rest); i++ {
			if (rest[i] == "-p" || rest[i] == "--policy") && i+1 < len(rest) {
				policyPath = rest[i+1]
				i++
			}
		}
		if err := wizard.Run(wizard.Options{PolicyPath: policyPath}); err != nil {
			fatal("config", err)
		}
		return
	}

	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, usage)
		os.Exit(2)
	}

	if cfg.showVersion {
		fmt.Printf("wrapster %s\n", mcp.Version)
		return
	}

	pol, err := loadPolicyFromPaths(cfg.policyPath)
	if err != nil {
		fatal("policy", err)
	}

	logger, err := audit.NewLogger(cfg.auditPath)
	if err != nil {
		fatal("audit", err)
	}
	defer logger.Close()
	defer ssh.ClosePool()

	// Build filter chain from policy config.
	filterCfg := toFilterConfig(pol.Filters)
	if pol.Local.WorkDir != "" {
		filterCfg.WorkDir = pol.Local.WorkDir
	}
	chain, err := filter.Build(filterCfg)
	if err != nil {
		fatal("filters", err)
	}

	// apply tuning defaults
	cacheTTL := 30 * time.Second
	if cfg.cacheTTL > 0 {
		cacheTTL = cfg.cacheTTL
	}
	hostinfoTTL := 30 * time.Minute
	if cfg.hostinfoTTL > 0 {
		hostinfoTTL = cfg.hostinfoTTL
	}
	bufstoreMax := 0 // 0 = use default inside bufstore.New
	if cfg.bufstoreMax > 0 {
		bufstoreMax = cfg.bufstoreMax
	}

	r := &runner.Runner{
		Policy:        pol,
		Logger:        logger,
		Filters:       chain,
		OutputStats:   &output.Tracker{},
		ResultCache:   cache.New(cacheTTL),
		BufStore:      bufstore.New(bufstoreMax),
		HostInfoCache: hostinfo.New(hostinfoTTL),
	}

	// --mcp mode (stdio)
	if cfg.mcpMode {
		if err := mcp.Serve(r); err != nil {
			fatal("mcp", err)
		}
		return
	}

	// --mcp-sse mode (HTTP)
	if cfg.mcpSSEAddr != "" {
		srv := mcp.NewSSEServer(r, cfg.mcpSSEAddr)
		if err := srv.ListenAndServe(); err != nil {
			fatal("mcp-sse", err)
		}
		return
	}

	// CLI modes require a host.
	if cfg.listMode {
		resolved := pol.ResolvedPolicy(cfg.host)
		printAllowed(cfg.host, resolved)
		return
	}

	if cfg.dryRun {
		result := r.Validate(cfg.host, cfg.command)
		if cfg.jsonOutput {
			out, _ := json.Marshal(map[string]any{
				"allowed": result.Allowed,
				"reason":  result.Reason,
				"dry_run": true,
			})
			fmt.Println(string(out))
		} else if result.Allowed {
			fmt.Printf("ALLOWED (dry-run): %s\n", result.Reason)
		} else {
			fmt.Fprintf(os.Stderr, "DENIED: %s\n", result.Reason)
		}
		if !result.Allowed {
			os.Exit(1)
		}
		return
	}

	if cfg.watch > 0 {
		runWatch(cfg, r)
		return
	}

	// Single execution -- local or SSH.
	var result runner.RunResult
	if cfg.host == "local" {
		result = r.ExecLocal(context.Background(), cfg.command)
	} else {
		result = r.Exec(context.Background(), cfg.host, cfg.command, cfg.sshArgs)
	}
	printResult(cfg, result)

	if !result.Allowed || result.Error != "" {
		os.Exit(1)
	}
	os.Exit(result.ExitCode)
}

func runWatch(cfg *config, r *runner.Runner) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(cfg.watch)
	defer ticker.Stop()

	run := func() {
		result := r.Exec(ctx, cfg.host, cfg.command, cfg.sshArgs)
		printResult(cfg, result)
	}

	run()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func printResult(cfg *config, result runner.RunResult) {
	if !result.Allowed {
		if cfg.jsonOutput {
			out, _ := json.Marshal(result)
			fmt.Println(string(out))
		} else {
			fmt.Fprintf(os.Stderr, "DENIED: %s\n", result.Reason)
		}
		return
	}

	if result.Error != "" {
		if cfg.jsonOutput {
			out, _ := json.Marshal(result)
			fmt.Println(string(out))
		} else {
			fmt.Fprintf(os.Stderr, "wrapster: exec error: %s\n", result.Error)
		}
		return
	}

	if cfg.jsonOutput {
		out, _ := json.Marshal(result)
		fmt.Println(string(out))
	} else {
		if result.Stdout != "" {
			fmt.Print(result.Stdout)
		}
		if result.Stderr != "" {
			fmt.Fprint(os.Stderr, result.Stderr)
		}
		if result.TimedOut {
			fmt.Fprintln(os.Stderr, "[wrapster: command timed out]")
		}
	}
}

func parseArgs(args []string) (*config, error) {
	cfg := &config{}
	positional := []string{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			fmt.Print(usage)
			os.Exit(0)
		case arg == "--version":
			cfg.showVersion = true
		case arg == "-p" || arg == "--policy":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--policy requires a path")
			}
			cfg.policyPath = args[i]
		case arg == "-a" || arg == "--audit":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--audit requires a path")
			}
			cfg.auditPath = args[i]
		case arg == "-s" || arg == "--ssh-args":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--ssh-args requires arguments")
			}
			cfg.sshArgs = strings.Split(args[i], ",")
		case arg == "-w" || arg == "--watch":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--watch requires a duration (e.g. 30s, 1m)")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, fmt.Errorf("--watch: invalid duration %q: %w", args[i], err)
			}
			if d < 5*time.Second {
				return nil, fmt.Errorf("--watch: minimum interval is 5s")
			}
			cfg.watch = d
		case arg == "--cache-ttl":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--cache-ttl requires a duration (e.g. 30s, 5m)")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, fmt.Errorf("--cache-ttl: invalid duration %q: %w", args[i], err)
			}
			cfg.cacheTTL = d
		case arg == "--hostinfo-ttl":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--hostinfo-ttl requires a duration (e.g. 30m, 1h)")
			}
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, fmt.Errorf("--hostinfo-ttl: invalid duration %q: %w", args[i], err)
			}
			cfg.hostinfoTTL = d
		case arg == "--bufstore-max":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--bufstore-max requires a number")
			}
			n := 0
			if _, err := fmt.Sscanf(args[i], "%d", &n); err != nil || n <= 0 {
				return nil, fmt.Errorf("--bufstore-max: must be a positive integer, got %q", args[i])
			}
			cfg.bufstoreMax = n
		case arg == "--mcp":
			cfg.mcpMode = true
		case arg == "--mcp-sse":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--mcp-sse requires an address (e.g. :8080)")
			}
			cfg.mcpSSEAddr = args[i]
		case arg == "-j" || arg == "--json":
			cfg.jsonOutput = true
		case arg == "-n" || arg == "--dry-run":
			cfg.dryRun = true
		case arg == "-l" || arg == "--list":
			cfg.listMode = true
		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("unknown flag: %s", arg)
		default:
			positional = append(positional, arg)
		}
	}

	if cfg.showVersion || cfg.mcpMode || cfg.mcpSSEAddr != "" {
		return cfg, nil
	}

	if cfg.listMode {
		if len(positional) < 1 {
			return nil, fmt.Errorf("--list requires a host argument")
		}
		cfg.host = positional[0]
		return cfg, nil
	}

	if len(positional) < 2 {
		return nil, fmt.Errorf("requires <host> and <command> arguments")
	}

	cfg.host = positional[0]
	cfg.command = strings.Join(positional[1:], " ")
	return cfg, nil
}

// toFilterConfig converts the policy FilterConfig to the filter package's config.
func toFilterConfig(pf policy.FilterConfig) filter.FilterConfig {
	fc := filter.FilterConfig{
		GTFOBins: filter.ModuleConfig{
			Enabled: pf.GTFOBins.Enabled,
			Block:   pf.GTFOBins.Block,
			Warn:    pf.GTFOBins.Warn,
		},
		Destructive: filter.ModuleConfig{
			Enabled: pf.Destructive.Enabled,
		},
		Exfil: filter.ModuleConfig{
			Enabled: pf.Exfil.Enabled,
		},
	}
	for _, c := range pf.Custom {
		fc.Custom = append(fc.Custom, filter.CustomModuleRef{
			Name:    c.Name,
			Enabled: c.Enabled,
			Path:    c.Path,
		})
	}
	return fc
}

func loadPolicyFromPaths(explicit string) (*policy.Policy, error) {
	if explicit != "" {
		return policy.LoadPolicy(explicit)
	}

	candidates := []string{"policy.yaml"}
	home, err := os.UserHomeDir()
	if err == nil {
		candidates = append(candidates, home+"/.config/wrapster/policy.yaml")
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return policy.LoadPolicy(path)
		}
	}

	return nil, fmt.Errorf("no policy file found (tried: %s)", strings.Join(candidates, ", "))
}

func printAllowed(host string, hp policy.HostPolicy) {
	fmt.Printf("Allowed commands for %q:\n\n", host)
	if len(hp.AllowedCommands) == 0 {
		fmt.Println("  (none)")
		return
	}
	for _, rule := range hp.AllowedCommands {
		desc := rule.Description
		if desc == "" {
			desc = "(no description)"
		}
		if rule.Command != "" {
			args := "*"
			if rule.ArgsPattern != "" {
				args = rule.ArgsPattern
			}
			fmt.Printf("  %-20s args: %-20s %s\n", rule.Command, args, desc)
		} else if rule.Pattern != "" {
			fmt.Printf("  /%s/  %s\n", rule.Pattern, desc)
		}
	}
	if len(hp.DeniedPatterns) > 0 {
		fmt.Printf("\nDenied patterns:\n")
		for _, p := range hp.DeniedPatterns {
			fmt.Printf("  /%s/\n", p)
		}
	}

	warnings := policy.AuditPolicy(hp)
	if len(warnings) > 0 {
		fmt.Printf("\nSecurity warnings:\n")
		for _, w := range warnings {
			fmt.Printf("  %s\n", w)
		}
	}
}

func fatal(ctx string, err error) {
	fmt.Fprintf(os.Stderr, "wrapster: %s: %v\n", ctx, err)
	os.Exit(1)
}
