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
var shellOperatorPattern = regexp.MustCompile(`[;|&` + "`" + `$(){}<>\r\n]|&&|\|\|`)

// segmentSplitter splits a command on shell control operators so each segment
// can be validated independently in allowlist mode.
var segmentSplitter = regexp.MustCompile(`(?:&&|\|\||[;|&\n\r])`)

// cmdSubstPattern detects command/process substitution, which is rejected in
// allowlist mode because it hides an un-validated sub-command.
var cmdSubstPattern = regexp.MustCompile(`\$\(|` + "`" + `|<\(|>\(`)

// splitSegments returns the non-empty, trimmed operator-separated segments of cmd.
func splitSegments(cmd string) []string {
	parts := segmentSplitter.Split(cmd, -1)
	out := parts[:0]
	for _, s := range parts {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ifsPattern matches ${IFS}/$IFS, used to replace whitespace and fragment
// keywords so that \s-based deny patterns no longer match.
var ifsPattern = regexp.MustCompile(`\$\{?IFS\}?`)

// normalizeForMatch rewrites ${IFS}/$IFS to a space so the hard-deny patterns
// cannot be split by it. Used only for matching; the unmodified command is what
// executes (the remote shell performs the same expansion, so this is faithful).
func normalizeForMatch(cmd string) string {
	return ifsPattern.ReplaceAllString(cmd, " ")
}

// obfuscationPattern matches evasion-only constructs rejected in EVERY mode:
// ANSI-C quoting ($'\x72\x6d') and IFS reassignment (IFS=,) exist only to
// smuggle bytes past a string validator and have no legitimate use here.
var obfuscationPattern = regexp.MustCompile(`\$'|(^|[;|&\s])IFS\s*=`)

// fragmentPattern matches keyword-splitting tricks rejected in ALLOWLIST mode:
// mid-word empty strings (r''m), backslash escapes (r\m), and comma brace
// expansion ({rm,-rf,/}). These only exist to defeat an allowlist.
var fragmentPattern = regexp.MustCompile(`[A-Za-z]['"]{2}[A-Za-z]|[A-Za-z]\\[A-Za-z]|\{[^}]*,[^}]*\}`)

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
	{raw: `\bfind\b[^|;&]*\s-delete\b`}, // find ... -delete (recursive wipe). rm is handled by dangerousRm.
	{raw: `\bmv\b[^|;&]*\s/dev/null\b`}, // mv a tree onto /dev/null
	{raw: `>\s*/dev/(sd[a-z]|nvme\d+n\d+|vd[a-z]|xvd[a-z]|mmcblk\d+|mapper/|mem|kmsg|port)`}, // write to device
	{raw: `\bdd\b.*\bof\s*=\s*/dev/`},                               // dd to device
	{raw: `\b(mkfs|mke2fs|mkswap|newfs)\b`},                         // format filesystem
	{raw: `[\w:]*\(\)\s*\{\s*[\w:]*\s*\|\s*[\w:]*\s*&`},             // fork bomb (named or :)
	{raw: `/dev/(tcp|udp)/`},                                        // bash net redirect (reverse shell)
	{raw: `/etc/(passwd|shadow|sudoers)`},                           // sensitive files
	{raw: `(>|>>|\btee\b[^|;&]*?)\s*/etc/(crontab|cron\.|hosts)\b`}, // write to system cron/hosts
	{raw: `\bchmod\s+.*777\b`},                                      // world-writable (octal)
	{raw: `\bchmod\s+.*[oa]\+w`},                                    // world-writable (symbolic)
	{raw: `\b(curl|wget|fetch)\b.*\|&?\s*(sudo\s+)?(sh|bash|dash|zsh|ksh|fish|python[0-9.]*|perl|ruby|node)\b`}, // download | interpreter
}

// hardDenyFused alternates every hardDenyRule pattern so a single DFA pass
// answers "does any dangerous pattern match?" instead of running 9 sequential
// MatchString calls. The slow-path lookup over hardDenyRules only runs when
// this match is positive (a rare path).
var hardDenyFused = func() *regexp.Regexp {
	parts := make([]string, len(hardDenyRules))
	for i := range hardDenyRules {
		hardDenyRules[i].re = regexp.MustCompile("(?i)" + hardDenyRules[i].raw)
		parts[i] = "(?:" + hardDenyRules[i].raw + ")"
	}
	return regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
}()

// rm with BOTH recursive and force flags (any order or position) aimed at a
// system path, home, root, or a bare glob is catastrophic. Expressed in code
// because it is an AND of three conditions a single RE2 pattern cannot express
// (this is what catches flag-after-target forms like `rm /etc -rf`).
var (
	rmCmdPat       = regexp.MustCompile(`(?i)\brm\b`)
	rmRecursivePat = regexp.MustCompile(`(?i)(^|\s)(-[a-z]*r[a-z]*|--recursive)\b`)
	rmDangerTgtPat = regexp.MustCompile(`(?i)(\s|=)(/|~|\$HOME)(\s|$|[;)(&|<>'"` + "`" + `])|(\s|=)/(etc|usr|var|bin|boot|lib|lib64|root|home|sys|proc|opt|srv)/?(\*|\s|$|[;)(&|<>'"` + "`" + `])|--no-preserve-root`)
)

func dangerousRm(cmd string) bool {
	// catastrophic = a recursive delete aimed at root, a home, or a system
	// top-level directory. force (-f) is irrelevant to the danger so it is not
	// required; a bare `*` glob is intentionally NOT flagged (too common in
	// legitimate cleanup like `rm -rf build/*`).
	if !rmCmdPat.MatchString(cmd) || !rmRecursivePat.MatchString(cmd) {
		return false
	}
	return rmDangerTgtPat.MatchString(cmd)
}

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

	// Bound input size before any regex or splitting. Real commands are tiny;
	// RE2 is linear, but linear in megabytes is still a CPU-DoS on a shared hub,
	// so reject an oversized command outright instead of validating it.
	const maxCommandLen = 1 << 16 // 64 KiB
	if len(cmd) > maxCommandLen {
		return ValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("command too long: %d bytes (limit %d)", len(cmd), maxCommandLen),
		}
	}

	// Reject evasion-only constructs (ANSI-C quoting, IFS reassignment) in every
	// mode -- they exist only to smuggle bytes past string validation.
	if obfuscationPattern.MatchString(cmd) {
		return ValidationResult{
			Allowed: false,
			Reason:  "rejected: ANSI-C quoting ($'...') or IFS reassignment (command obfuscation)",
		}
	}

	// Hard denies -- always blocked, no override, regardless of mode (an
	// accident/catastrophe net that holds even in trusted mode). Matched against
	// the ${IFS}-normalized command so whitespace tricks cannot fragment a rule.
	// One fused DFA pass replaces N sequential matches; only when it hits do we
	// walk the rules to identify which pattern triggered.
	norm := normalizeForMatch(cmd)
	if hardDenyFused.MatchString(norm) {
		matched := "dangerous pattern"
		for i := range hardDenyRules {
			if hardDenyRules[i].re.MatchString(norm) {
				matched = hardDenyRules[i].raw
				break
			}
		}
		return ValidationResult{
			Allowed: false,
			Reason:  fmt.Sprintf("hard-denied: matches dangerous pattern %q", matched),
		}
	}
	if dangerousRm(norm) {
		return ValidationResult{
			Allowed: false,
			Reason:  "hard-denied: recursive force rm targeting a system path, home, or root",
		}
	}

	// Shell operator check.
	if !hp.AllowShellOperators && shellOperatorPattern.MatchString(cmd) {
		return ValidationResult{
			Allowed: false,
			Reason:  "shell operators, redirects, or newlines are not allowed -- set allow_shell_operators: true in policy to permit",
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
	// Reject keyword-fragmenting obfuscation that only exists to defeat an
	// allowlist (empty-string r''m, backslash r\m, brace {rm,-rf,/}).
	if fragmentPattern.MatchString(cmd) {
		return ValidationResult{
			Allowed: false,
			Reason:  "obfuscation (empty-string, backslash, or brace expansion) is not allowed in allowlist mode",
		}
	}
	// Command substitution can smuggle an un-allowlisted sub-command inside an
	// allowed one and cannot be validated per-segment, so reject it outright.
	if cmdSubstPattern.MatchString(cmd) {
		return ValidationResult{
			Allowed: false,
			Reason:  "command substitution ($(), backticks, process substitution) is not allowed in allowlist mode",
		}
	}

	// A Pattern rule is matched against the full command string verbatim
	// (operators and all), so honor those before splitting into segments.
	for i := range hp.AllowedCommands {
		rule := &hp.AllowedCommands[i]
		if rule.compiled != nil && rule.Matches(cmd) {
			return ValidationResult{
				Allowed:     true,
				Reason:      fmt.Sprintf("matched rule: %s", ruleLabel(rule)),
				MatchedRule: rule,
			}
		}
	}

	// Otherwise every operator-separated segment must independently match an
	// allowed_commands rule. This stops an allowlisted prefix (e.g. "uptime")
	// from dragging trailing commands through when allow_shell_operators is on.
	segments := splitSegments(cmd)
	if len(segments) == 0 {
		return ValidationResult{Allowed: false, Reason: "no matching allowed_commands rule (deny by default)"}
	}
	var firstRule *CommandRule
	for _, seg := range segments {
		matched := false
		for i := range hp.AllowedCommands {
			rule := &hp.AllowedCommands[i]
			if rule.Matches(seg) {
				matched = true
				if firstRule == nil {
					firstRule = rule
				}
				break
			}
		}
		if !matched {
			return ValidationResult{
				Allowed: false,
				Reason:  fmt.Sprintf("no matching allowed_commands rule for segment %q (deny by default)", seg),
			}
		}
	}

	return ValidationResult{
		Allowed:     true,
		Reason:      fmt.Sprintf("all %d segment(s) matched allowed_commands", len(segments)),
		MatchedRule: firstRule,
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
