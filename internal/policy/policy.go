package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is the top-level configuration.
type Policy struct {
	Defaults HostPolicy            `yaml:"defaults"`
	Hosts    map[string]HostPolicy `yaml:"hosts"`
	Local    LocalConfig           `yaml:"local"`
	Filters  FilterConfig          `yaml:"filters"`
	Output   OutputConfig          `yaml:"output"`
}

// OutputConfig controls post-processing of command output.
type OutputConfig struct {
	ANSIStrip bool                 `yaml:"ansi_strip"`
	Truncate  OutputTruncateConfig `yaml:"truncate"`
	Stats     bool                 `yaml:"stats"`
}

// OutputTruncateConfig controls head+tail truncation.
type OutputTruncateConfig struct {
	Enabled   bool `yaml:"enabled"`
	MaxChars  int  `yaml:"max_chars"`
	HeadLines int  `yaml:"head_lines"`
	TailLines int  `yaml:"tail_lines"`
}

// Duration is a time.Duration that round-trips through YAML as a human string
// like "30s". yaml.v3 has no native time.Duration support -- it emits raw
// nanoseconds and fails to parse "30s" -- so a named type with custom
// (un)marshalling is required for the documented policy format to both load and
// be re-emitted by the config wizard.
type Duration time.Duration

// Std returns the value as a standard library time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil {
		if s == "" {
			*d = 0
			return nil
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	// Fall back to a bare number (nanoseconds), matching yaml.v3's raw form.
	var n int64
	if err := node.Decode(&n); err != nil {
		return fmt.Errorf(`duration must be a string like "30s" or a number of nanoseconds`)
	}
	*d = Duration(n)
	return nil
}

// LocalConfig governs local command execution (the "exec" MCP tool).
type LocalConfig struct {
	// Mode: "guardrail" (default) allows everything unless filters catch it.
	// "allowlist" requires explicit allowed_commands.
	Mode string `yaml:"mode"`

	// Optional working directory restriction.
	WorkDir string `yaml:"work_dir"`

	// Command policy (only used in allowlist mode).
	AllowedCommands []CommandRule `yaml:"allowed_commands"`
	DeniedPatterns  []string     `yaml:"denied_patterns"`

	// Shell operators allowed by default for local (LLMs need pipes, etc.)
	AllowShellOperators bool `yaml:"allow_shell_operators"`

	// Environment vars injected into local commands.
	Environment map[string]string `yaml:"environment"`

	Timeout        Duration      `yaml:"timeout,omitempty"`
	MaxOutputBytes int           `yaml:"max_output_bytes"`
}

// FilterConfig controls which filter modules are active.
type FilterConfig struct {
	GTFOBins    FilterModuleConfig `yaml:"gtfobins"`
	Destructive FilterModuleConfig `yaml:"destructive"`
	Exfil       FilterModuleConfig `yaml:"exfil"`
	Custom      []CustomFilterRef  `yaml:"custom"`
}

// FilterModuleConfig is the per-module toggle and options.
type FilterModuleConfig struct {
	Enabled bool     `yaml:"enabled"`
	Block   []string `yaml:"block"`
	Warn    []string `yaml:"warn"`
}

// CustomFilterRef references a custom rule file.
type CustomFilterRef struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// HostPolicy defines what's allowed on a specific host (or as defaults).
type HostPolicy struct {
	// SSH connection settings
	Hostname     string            `yaml:"hostname"` // actual IP/hostname (if key is an alias)
	User         string            `yaml:"user"`
	Port         int               `yaml:"port"`
	IdentityFile string            `yaml:"identity_file"`
	SSHOptions   map[string]string `yaml:"ssh_options"`

	// Command policy
	AllowedCommands []CommandRule `yaml:"allowed_commands"`
	DeniedPatterns  []string     `yaml:"denied_patterns"`

	// Execution limits
	MaxOutputBytes int           `yaml:"max_output_bytes"`
	Timeout        Duration      `yaml:"timeout,omitempty"`

	// shell injection protection -- set to true to allow pipes, semicolons, etc.
	AllowShellOperators bool `yaml:"allow_shell_operators"`

	// remote environment -- explicit env vars set before command execution.
	// Values can reference $PATH etc. to extend rather than replace.
	Environment map[string]string `yaml:"environment"`
}

// CommandRule defines a single allowed command pattern.
type CommandRule struct {
	// Exact command match (before arguments).
	Command string `yaml:"command"`

	// Regex pattern for the full command string. Mutually exclusive with Command.
	Pattern string `yaml:"pattern"`

	// Description for audit logs and help output.
	Description string `yaml:"description"`

	// Optional argument validation regex. Only used with Command (not Pattern).
	ArgsPattern string `yaml:"args_pattern"`

	compiled        *regexp.Regexp
	argsCompiled    *regexp.Regexp
}

// Compile pre-compiles regex patterns. Call after loading.
func (r *CommandRule) Compile() error {
	if r.Pattern != "" {
		re, err := regexp.Compile("^" + r.Pattern + "$")
		if err != nil {
			return fmt.Errorf("bad pattern %q: %w", r.Pattern, err)
		}
		r.compiled = re
	}
	if r.ArgsPattern != "" {
		re, err := regexp.Compile("^" + r.ArgsPattern + "$")
		if err != nil {
			return fmt.Errorf("bad args_pattern %q: %w", r.ArgsPattern, err)
		}
		r.argsCompiled = re
	}
	return nil
}

// Matches returns true if the full command string matches this rule.
func (r *CommandRule) Matches(fullCommand string) bool {
	if r.compiled != nil {
		return r.compiled.MatchString(fullCommand)
	}

	parts := strings.SplitN(strings.TrimSpace(fullCommand), " ", 2)
	cmd := parts[0]
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	if cmd != r.Command {
		return false
	}

	if r.argsCompiled != nil {
		return r.argsCompiled.MatchString(args)
	}

	// If no args pattern specified and command matches, allow any args.
	return true
}

// LoadPolicy reads and parses a policy YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	// Reserved name check.
	if _, exists := p.Hosts["local"]; exists {
		return nil, fmt.Errorf(`"local" is a reserved host name (used for local execution)`)
	}

	// Compile all regex patterns.
	if err := compileRules(&p.Defaults); err != nil {
		return nil, fmt.Errorf("in defaults: %w", err)
	}
	for name, hp := range p.Hosts {
		if err := compileRules(&hp); err != nil {
			return nil, fmt.Errorf("in host %q: %w", name, err)
		}
		p.Hosts[name] = hp
	}

	// Compile local allowed_commands if present.
	for i := range p.Local.AllowedCommands {
		if err := p.Local.AllowedCommands[i].Compile(); err != nil {
			return nil, fmt.Errorf("in local: %w", err)
		}
	}
	// Validate local denied_patterns.
	for _, pat := range p.Local.DeniedPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			return nil, fmt.Errorf("in local.denied_patterns: bad pattern %q: %w", pat, err)
		}
	}

	// Default local mode.
	if p.Local.Mode == "" {
		p.Local.Mode = "guardrail"
	}
	// Default: allow shell operators for local (LLMs need pipes, redirects, etc.)
	if p.Local.Mode == "guardrail" && !p.Local.AllowShellOperators {
		p.Local.AllowShellOperators = true
	}

	// Default output config: strip ANSI, truncate large output.
	if !p.Output.ANSIStrip && p.Output.Truncate == (OutputTruncateConfig{}) && !p.Output.Stats {
		p.Output = OutputConfig{
			ANSIStrip: true,
			Truncate: OutputTruncateConfig{
				Enabled:   true,
				MaxChars:  8192,
				HeadLines: 64,
				TailLines: 16,
			},
			Stats: true,
		}
	}

	return &p, nil
}

func compileRules(hp *HostPolicy) error {
	for i := range hp.AllowedCommands {
		if err := hp.AllowedCommands[i].Compile(); err != nil {
			return err
		}
	}
	// Validate denied_patterns at load time so bad regex fails fast.
	for _, pat := range hp.DeniedPatterns {
		if _, err := regexp.Compile(pat); err != nil {
			return fmt.Errorf("bad denied_pattern %q: %w", pat, err)
		}
	}
	return nil
}

// ResolvedPolicy merges defaults with host-specific overrides.
func (p *Policy) ResolvedPolicy(host string) HostPolicy {
	// Start from the defaults, but deep-copy every reference-typed field so a
	// resolved policy never aliases -- and never mutates -- the shared defaults.
	// ResolvedPolicy runs concurrently on the MCP dispatch path, so the merges
	// below must not race on shared maps/slices or bleed one host's rules into
	// another's.
	resolved := p.Defaults
	resolved.SSHOptions = copyStringMap(p.Defaults.SSHOptions)
	resolved.Environment = copyStringMap(p.Defaults.Environment)
	resolved.AllowedCommands = append([]CommandRule(nil), p.Defaults.AllowedCommands...)
	resolved.DeniedPatterns = append([]string(nil), p.Defaults.DeniedPatterns...)

	hp, ok := p.Hosts[host]
	if !ok {
		return resolved
	}

	if hp.Hostname != "" {
		resolved.Hostname = hp.Hostname
	}
	if hp.User != "" {
		resolved.User = hp.User
	}
	if hp.Port != 0 {
		resolved.Port = hp.Port
	}
	if hp.IdentityFile != "" {
		resolved.IdentityFile = hp.IdentityFile
	}
	if hp.MaxOutputBytes != 0 {
		resolved.MaxOutputBytes = hp.MaxOutputBytes
	}
	if hp.Timeout != 0 {
		resolved.Timeout = hp.Timeout
	}
	if hp.AllowShellOperators {
		resolved.AllowShellOperators = true
	}

	// SSH options: merge, host overrides win.
	if len(hp.SSHOptions) > 0 {
		if resolved.SSHOptions == nil {
			resolved.SSHOptions = make(map[string]string)
		}
		for k, v := range hp.SSHOptions {
			resolved.SSHOptions[k] = v
		}
	}

	// Environment: merge, host overrides win.
	if len(hp.Environment) > 0 {
		if resolved.Environment == nil {
			resolved.Environment = make(map[string]string)
		}
		for k, v := range hp.Environment {
			resolved.Environment[k] = v
		}
	}

	// Commands: host rules are appended to defaults (both apply).
	resolved.AllowedCommands = append(resolved.AllowedCommands, hp.AllowedCommands...)
	resolved.DeniedPatterns = append(resolved.DeniedPatterns, hp.DeniedPatterns...)

	return resolved
}

// copyStringMap returns a shallow copy of m, or nil if m is nil.
func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
