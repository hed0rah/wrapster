package policy

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// compiledDeniedCache caches compiled denied_patterns regexes by pattern string.
// Patterns are compiled once and reused across all calls, avoiding repeated
// regexp.Compile overhead in ValidateCommand hot paths (especially batch_exec).
var compiledDeniedCache sync.Map // key: string, value: *regexp.Regexp

func cachedCompile(pat string) (*regexp.Regexp, error) {
	if v, ok := compiledDeniedCache.Load(pat); ok {
		return v.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	compiledDeniedCache.Store(pat, re)
	return re, nil
}

// ValidationMode controls how commands are checked.
type ValidationMode int

const (
	// ModeAllowlist denies unless the command matches an allowed_commands rule.
	ModeAllowlist ValidationMode = iota
	// ModeGuardrail allows everything unless it hits a deny pattern or hard deny.
	// Used for local execution where filters provide the safety net.
	ModeGuardrail
)

// Shell metacharacters that enable injection when unsanitized.
var shellOperatorPattern = regexp.MustCompile(`[;|&` + "`" + `$(){}]|&&|\|\|`)

// hardDenyRule pairs a raw pattern (for error messages) with its compiled
// form (used only on the slow path when the fused regex below has already
// confirmed a match).
type hardDenyRule struct {
	raw string
	re  *regexp.Regexp
}

// Dangerous patterns that are always denied regardless of policy or mode.
// Kept as individual rules so the deny reason can name the specific pattern
// that triggered, but only consulted when hardDenyFused has matched.
var hardDenyRules = []hardDenyRule{
	{raw: `\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?/`},     // rm -rf /
	{raw: `>\s*/dev/sd[a-z]`},                        // write to raw disk
	{raw: `\bdd\b.*of=/dev/`},                        // dd to device
	{raw: `\bmkfs\b`},                                // format filesystem
	{raw: `:\(\)\s*\{\s*:\|:&\s*\}\s*;:`},            // fork bomb
	{raw: `/etc/(passwd|shadow|sudoers)`},            // sensitive files
	{raw: `\bchmod\s+.*777\b`},                       // world-writable
	{raw: `\bcurl\b.*\|\s*(ba)?sh`},                  // curl | sh
	{raw: `\bwget\b.*\|\s*(ba)?sh`},                  // wget | sh
}

// hardDenyFused alternates every hardDenyRule pattern so a single DFA pass
// answers "does any dangerous pattern match?" instead of running 9 sequential
// MatchString calls. The slow-path lookup over hardDenyRules only runs when
// this match is positive (a rare path).
var hardDenyFused = func() *regexp.Regexp {
	parts := make([]string, len(hardDenyRules))
	for i := range hardDenyRules {
		hardDenyRules[i].re = regexp.MustCompile(hardDenyRules[i].raw)
		parts[i] = "(?:" + hardDenyRules[i].raw + ")"
	}
	return regexp.MustCompile(strings.Join(parts, "|"))
}()

// ValidationResult holds the outcome of command validation.
type ValidationResult struct {
	Allowed     bool
	Reason      string
	MatchedRule *CommandRule
}

// ValidateCommand checks a command against policy. In ModeAllowlist, the command
// must match an allowed_commands rule. In ModeGuardrail, the command is allowed
// unless it hits a hard deny or user-defined deny pattern.
func ValidateCommand(cmd string, hp HostPolicy, mode ValidationMode) ValidationResult {
	cmd = strings.TrimSpace(cmd)

	if cmd == "" {
		return ValidationResult{Allowed: false, Reason: "empty command"}
	}

	// Hard denies -- always blocked, no override, regardless of mode.
	// One fused DFA pass replaces N sequential matches; only when it hits
	// do we walk the rules to identify which pattern triggered.
	if hardDenyFused.MatchString(cmd) {
		matched := "dangerous pattern"
		for i := range hardDenyRules {
			if hardDenyRules[i].re.MatchString(cmd) {
				matched = hardDenyRules[i].raw
				break
			}
		}
		return ValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("hard-denied: matches dangerous pattern %q", matched),
		}
	}

	// Shell operator check.
	if !hp.AllowShellOperators && shellOperatorPattern.MatchString(cmd) {
		return ValidationResult{
			Allowed: false,
			Reason:  "shell operators (;|&`$(){}) are not allowed -- set allow_shell_operators: true in policy to permit",
		}
	}

	// User-defined denied patterns -- apply in both modes.
	for _, pat := range hp.DeniedPatterns {
		re, err := cachedCompile(pat)
		if err != nil {
			return ValidationResult{
				Allowed: false,
				Reason:  fmt.Sprintf("bad denied_pattern %q in policy: %v", pat, err),
			}
		}
		if re.MatchString(cmd) {
			return ValidationResult{
				Allowed: false,
				Reason:  fmt.Sprintf("denied: matches pattern %q", pat),
			}
		}
	}

	// In guardrail mode, if we reach here the command is allowed.
	// Filters (not policy) provide the remaining safety net.
	if mode == ModeGuardrail {
		return ValidationResult{
			Allowed: true,
			Reason:  "allowed (guardrail mode)",
		}
	}

	// Allowlist mode -- must match at least one rule.
	for i := range hp.AllowedCommands {
		rule := &hp.AllowedCommands[i]
		if rule.Matches(cmd) {
			return ValidationResult{
				Allowed:     true,
				Reason:      fmt.Sprintf("matched rule: %s", ruleLabel(rule)),
				MatchedRule: rule,
			}
		}
	}

	return ValidationResult{
		Allowed: false,
		Reason:  "no matching allowed_commands rule (deny by default)",
	}
}

// LookupGTFOBin checks if a binary name is in the GTFOBins database.
func LookupGTFOBin(name string) (GTFOBinRisk, bool) {
	risk, ok := GTFOBins[name]
	return risk, ok
}

// AuditPolicy checks all allowed commands against GTFOBins and returns warnings.
func AuditPolicy(hp HostPolicy) []string {
	var warnings []string
	seen := make(map[string]bool)

	for _, rule := range hp.AllowedCommands {
		name := rule.Command
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true

		risk, ok := LookupGTFOBin(name)
		if !ok {
			continue
		}

		switch risk.Level {
		case "critical":
			warnings = append(warnings, fmt.Sprintf(
				"CRITICAL: '%s' has known shell escape / reverse-shell techniques -- capabilities: %s",
				name, strings.Join(risk.Capabilities, ", ")))
		case "high":
			warnings = append(warnings, fmt.Sprintf(
				"HIGH: '%s' can write files or download content -- capabilities: %s",
				name, strings.Join(risk.Capabilities, ", ")))
		case "medium":
			warnings = append(warnings, fmt.Sprintf(
				"MEDIUM: '%s' can read arbitrary files -- capabilities: %s",
				name, strings.Join(risk.Capabilities, ", ")))
		}
	}

	return warnings
}

func ruleLabel(r *CommandRule) string {
	if r.Description != "" {
		return r.Description
	}
	if r.Command != "" {
		return r.Command
	}
	return r.Pattern
}
