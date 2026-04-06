package filter

import (
	"path/filepath"
	"regexp"
	"strings"
)

// WorkdirFilter checks commands for path references outside a configured root.
// Not a security boundary -- just a guardrail to keep LLMs focused on one
// project directory. Catches absolute paths, .. traversal, and cd outside root.
type WorkdirFilter struct {
	root    string // absolute, cleaned path
	absPath *regexp.Regexp
	cdCmd   *regexp.Regexp
}

// NewWorkdirFilter creates a filter that flags paths outside root.
// root should be an absolute path.
func NewWorkdirFilter(root string) *WorkdirFilter {
	clean := filepath.Clean(root)
	return &WorkdirFilter{
		root: clean,
		// matches absolute paths: /foo, C:\foo, C:/foo
		absPath: regexp.MustCompile(`(?:^|\s)((?:/[a-zA-Z0-9._-]+)+|[A-Z]:[/\\][^\s]*)(?:\s|$)`),
		// matches cd commands
		cdCmd: regexp.MustCompile(`\bcd\s+(\S+)`),
	}
}

func (w *WorkdirFilter) Name() string { return "workdir" }

func (w *WorkdirFilter) Scan(command string) []Finding {
	var findings []Finding

	// check for .. traversal
	if strings.Contains(command, "..") {
		findings = append(findings, Finding{
			Module:   "workdir",
			Function: "traversal",
			Pattern:  "..",
			Detail:   "path traversal outside work directory",
			Severity: "high",
		})
	}

	// check absolute paths in the command
	for _, match := range w.absPath.FindAllStringSubmatch(command, -1) {
		path := match[1]
		if !w.isInside(path) {
			findings = append(findings, Finding{
				Module:   "workdir",
				Function: "path-escape",
				Pattern:  path,
				Detail:   "absolute path outside work directory: " + path,
				Severity: "high",
			})
		}
	}

	// check cd target specifically
	for _, match := range w.cdCmd.FindAllStringSubmatch(command, -1) {
		target := match[1]
		if target == ".." || strings.HasPrefix(target, "../") {
			// already caught by traversal check above, skip duplicate
			continue
		}
		if filepath.IsAbs(target) && !w.isInside(target) {
			// already caught by absolute path check, skip duplicate
			continue
		}
		// cd to ~ or - is an escape
		if target == "~" || target == "-" || strings.HasPrefix(target, "~/") {
			findings = append(findings, Finding{
				Module:   "workdir",
				Function: "cd-escape",
				Pattern:  "cd " + target,
				Detail:   "cd outside work directory",
				Severity: "high",
			})
		}
	}

	return findings
}

// isInside checks if a path is within the configured root.
func (w *WorkdirFilter) isInside(path string) bool {
	clean := filepath.Clean(path)
	// normalize separators for comparison
	cleanFwd := filepath.ToSlash(clean)
	rootFwd := filepath.ToSlash(w.root)

	if cleanFwd == rootFwd {
		return true
	}
	return strings.HasPrefix(cleanFwd, rootFwd+"/")
}
