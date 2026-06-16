package filter

import "regexp"

// SQL DELETE without a WHERE clause is detected in Scan because RE2 has no
// negative lookahead.
var (
	deleteFromPattern  = regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)
	whereClausePattern = regexp.MustCompile(`(?i)\bWHERE\b`)
)

// DestructiveFilter catches commands that destroy data, corrupt filesystems,
// or make irreversible changes.
type DestructiveFilter struct {
	rules []rule
}

func NewDestructive() *DestructiveFilter {
	defs := []struct {
		pattern  string
		function string
		severity string
		desc     string
	}{
		// Filesystem destruction. Patterns covered by policy hardDeny
		// (rm -rf /, mkfs, dd of=/dev/, > /dev/sd*, chmod 777, fork bomb)
		// are intentionally absent here -- hardDeny runs first and would
		// have already blocked them, so re-checking on every passing
		// command is wasted work.
		{`\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r`, "destructive", "critical",
			"recursive force delete"},
		{`\bshred\b`, "destructive", "high",
			"secure file destruction"},
		{`\bwipefs\b`, "destructive", "critical",
			"wipe filesystem signatures"},

		// Permissions (chmod 777 handled by hardDeny)
		{`\bchmod\s+.*a\+[rwx]`, "destructive", "high",
			"adding permissions for all users"},

		// SQL destructive operations
		{`\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b`, "destructive", "critical",
			"SQL DROP statement"},
		{`\bTRUNCATE\s+TABLE\b`, "destructive", "critical",
			"SQL TRUNCATE"},
		{`\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1`, "destructive", "critical",
			"SQL DELETE all rows"},
		{`\bALTER\s+TABLE\b.*\bDROP\b`, "destructive", "high",
			"SQL ALTER TABLE DROP column"},

		// Git destructive
		{`\bgit\s+push\b.*--force\b`, "destructive", "high",
			"git force push"},
		{`\bgit\s+reset\s+--hard\b`, "destructive", "high",
			"git hard reset"},
		{`\bgit\s+clean\s+-[a-zA-Z]*f`, "destructive", "high",
			"git clean with force"},

		// Container/infra destruction
		{`\bdocker\s+system\s+prune\b`, "destructive", "high",
			"docker system prune"},
		{`\bdocker\s+rm\s+-f\b`, "destructive", "high",
			"docker force remove"},
		{`\bkubectl\s+delete\b.*--all\b`, "destructive", "critical",
			"kubectl delete all"},

		// Process killing
		{`\bkill\s+-9\s+-1\b`, "destructive", "critical",
			"kill all processes"},
		{`\bkillall\b`, "destructive", "high",
			"kill processes by name"},
	}

	f := &DestructiveFilter{}
	for _, d := range defs {
		// Patterns are compile-time constants; a bad one is a programmer bug that
		// must fail loudly here, never be silently dropped (a missing rule).
		re := regexp.MustCompile("(?i)" + d.pattern)
		f.rules = append(f.rules, rule{
			function: d.function,
			pattern:  re,
			rawPat:   d.pattern,
			detail:   d.desc,
			severity: d.severity,
		})
	}
	return f
}

func (f *DestructiveFilter) Name() string { return "destructive" }

func (f *DestructiveFilter) Scan(command string) []Finding {
	var findings []Finding
	for _, r := range f.rules {
		if r.pattern.MatchString(command) {
			findings = append(findings, Finding{
				Module:   "destructive",
				Function: r.function,
				Pattern:  r.rawPat,
				Detail:   r.detail,
				Severity: r.severity,
			})
		}
	}

	// "DELETE FROM ..." with no WHERE clause (RE2 has no negative lookahead).
	if deleteFromPattern.MatchString(command) && !whereClausePattern.MatchString(command) {
		findings = append(findings, Finding{
			Module:   "destructive",
			Function: "destructive",
			Pattern:  `\bDELETE\s+FROM\b without WHERE`,
			Detail:   "SQL DELETE without WHERE clause",
			Severity: "high",
		})
	}
	return findings
}
