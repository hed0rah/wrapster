package filter

import "regexp"

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
		// Filesystem destruction
		{`\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?/`, "destructive", "critical",
			"rm with force on root path"},
		{`\brm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r`, "destructive", "critical",
			"recursive force delete"},
		{`\bmkfs\b`, "destructive", "critical",
			"filesystem format"},
		{`\bdd\b.*\bof=/dev/`, "destructive", "critical",
			"dd write to device"},
		{`>\s*/dev/sd[a-z]`, "destructive", "critical",
			"redirect to raw disk"},
		{`\bshred\b`, "destructive", "high",
			"secure file destruction"},
		{`\bwipefs\b`, "destructive", "critical",
			"wipe filesystem signatures"},

		// Permissions
		{`\bchmod\s+.*777\b`, "destructive", "high",
			"world-writable permissions"},
		{`\bchmod\s+.*a\+[rwx]`, "destructive", "high",
			"adding permissions for all users"},

		// Fork bomb
		{`:\(\)\s*\{\s*:\|:&\s*\}\s*;:`, "destructive", "critical",
			"fork bomb"},

		// SQL destructive operations
		{`\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b`, "destructive", "critical",
			"SQL DROP statement"},
		{`\bTRUNCATE\s+TABLE\b`, "destructive", "critical",
			"SQL TRUNCATE"},
		{`\bDELETE\s+FROM\b.*\bWHERE\s+1\s*=\s*1`, "destructive", "critical",
			"SQL DELETE all rows"},
		{`\bDELETE\s+FROM\b(?!.*\bWHERE\b)`, "destructive", "high",
			"SQL DELETE without WHERE clause"},
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
		re, err := regexp.Compile("(?i)" + d.pattern)
		if err != nil {
			continue
		}
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
	return findings
}
