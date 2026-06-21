package filter

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
)

//go:embed gtfobins.json
var gtfobinsData []byte

// GTFObinsFilter detects known shell escapes and exploit techniques
// from the GTFOBins knowledge base. Combines universal exploit-class
// patterns with per-binary signatures extracted from code examples.
type GTFObinsFilter struct {
	universal []rule
	perBinary map[string][]rule
}

type rule struct {
	function string
	pattern  *regexp.Regexp
	rawPat   string
	detail   string
	severity string
}

func NewGTFObins() (*GTFObinsFilter, error) {
	f := &GTFObinsFilter{
		perBinary: make(map[string][]rule),
	}
	f.universal = compileUniversal()
	if err := f.loadData(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *GTFObinsFilter) Name() string { return "gtfobins" }

func (f *GTFObinsFilter) Scan(command string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	bin := extractBinary(command)

	for _, r := range f.universal {
		if r.pattern.MatchString(command) && !seen[r.rawPat] {
			seen[r.rawPat] = true
			findings = append(findings, Finding{
				Module:   "gtfobins",
				Function: r.function,
				Pattern:  r.rawPat,
				Detail:   r.detail,
				Severity: r.severity,
			})
		}
	}

	if rules, ok := f.perBinary[bin]; ok {
		for _, r := range rules {
			if r.pattern.MatchString(command) && !seen[r.rawPat] {
				seen[r.rawPat] = true
				findings = append(findings, Finding{
					Module:   "gtfobins",
					Function: r.function,
					Pattern:  r.rawPat,
					Detail:   r.detail,
					Severity: r.severity,
				})
			}
		}
	}

	return findings
}

// wrapperBins are loader/launcher binaries that prefix a real command; they are
// skipped so per-binary signatures fire on the actual program (e.g. the python
// rules should still match `sudo env timeout 5 python ...`).
var wrapperBins = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nice": true, "ionice": true,
	"nohup": true, "setsid": true, "stdbuf": true, "timeout": true,
	"busybox": true, "command": true, "time": true,
}

var numArgPat = regexp.MustCompile(`^\d+[a-zA-Z]?$`)

func extractBinary(command string) string {
	parts := strings.Fields(strings.TrimSpace(command))
	for i := 0; i < len(parts); i++ {
		bin := parts[i]
		if idx := strings.LastIndex(bin, "/"); idx >= 0 {
			bin = bin[idx+1:]
		}
		// skip wrapper binaries, their flags, env VAR=VAL assignments, and a
		// wrapper's numeric argument (e.g. `timeout 5`, `nice -n 10`).
		if wrapperBins[bin] || strings.HasPrefix(parts[i], "-") ||
			strings.Contains(parts[i], "=") || numArgPat.MatchString(parts[i]) {
			continue
		}
		return bin
	}
	return ""
}

// --- GTFOBins data loader ---

type gtfobinsDB struct {
	Binaries []gtfobinsBinary `json:"binaries"`
}

type gtfobinsBinary struct {
	Name       string         `json:"name"`
	Techniques []gtfobinsTech `json:"techniques"`
}

type gtfobinsTech struct {
	Function string `json:"function"`
	Code     string `json:"code"`
}

func (f *GTFObinsFilter) loadData() error {
	var db gtfobinsDB
	if err := json.Unmarshal(gtfobinsData, &db); err != nil {
		return err
	}

	for _, bin := range db.Binaries {
		for _, tech := range bin.Techniques {
			if tech.Code == "" {
				continue
			}
			pat := codeToPattern(bin.Name, tech)
			if pat == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + pat)
			if err != nil {
				continue
			}
			f.perBinary[bin.Name] = append(f.perBinary[bin.Name], rule{
				function: tech.Function,
				pattern:  re,
				rawPat:   pat,
				detail:   tech.Code,
				severity: functionSeverity(tech.Function),
			})
		}
	}
	return nil
}

func codeToPattern(binary string, tech gtfobinsTech) string {
	code := tech.Code
	fn := tech.Function

	shellRe := regexp.MustCompile(`/bin/(sh|bash|dash|zsh|csh|ksh|fish)`)

	switch {
	case fn == "shell" || fn == "inherit":
		return shellPatternFromCode(binary, code)
	case fn == "reverse-shell" || fn == "bind-shell":
		return reverseShellPatternFromCode(binary, code)
	case fn == "file-write":
		return fileWritePatternFromCode(binary, code)
	case fn == "download" || fn == "upload":
		return dataExfilPatternFromCode(binary, code)
	case fn == "library-load":
		return libraryLoadPatternFromCode(binary, code)
	case fn == "file-read":
		if shellRe.MatchString(code) {
			return shellPatternFromCode(binary, code)
		}
		return ""
	default:
		return ""
	}
}

func shellPatternFromCode(binary string, code string) string {
	esc := regexp.QuoteMeta(binary)

	indicators := []struct {
		needle  string
		pattern string
	}{
		{`:!`, esc + `\b.*-c\s+.*:!`},
		{`:py`, esc + `\b.*-c\s+.*:(py|lua)`},
		{`os.system`, esc + `\b.*\bos\.system\s*\(`},
		{`os.execl`, esc + `\b.*\bos\.exec`},
		{`pty.spawn`, esc + `\b.*\bpty\.spawn\s*\(`},
		{`subprocess`, esc + `\b.*\bsubprocess\.(call|run|Popen)\s*\(`},
		{`Process.spawn`, esc + `\b.*Process\.spawn`},
		{`system(`, esc + `\b.*\bsystem\s*\(`},
		{`system "`, esc + `\b.*\bsystem\s*["']`},
		{`os.execute`, esc + `\b.*\bos\.execute\s*\(`},
		{`shell_exec`, esc + `\b.*\b(shell_exec|passthru|popen)\s*\(`},
		{`-exec`, esc + `\s+.*-exec\s+.*\b(sh|bash|dash|zsh|env)\b`},
		{`child_process`, esc + `\b.*child_process`},
		{`Runtime.getRuntime`, esc + `\b.*Runtime.*exec`},
		{`spawn`, esc + `\b.*\bspawn\s`},
	}

	for _, p := range indicators {
		if strings.Contains(code, p.needle) {
			return p.pattern
		}
	}

	shellRe := regexp.MustCompile(`/bin/(sh|bash|dash|zsh|csh|ksh|fish)`)
	if shellRe.MatchString(code) {
		return esc + `\b.*\b/bin/(sh|bash|dash|zsh|csh|ksh|fish)\b`
	}
	return ""
}

func reverseShellPatternFromCode(binary string, code string) string {
	esc := regexp.QuoteMeta(binary)
	indicators := []struct {
		needle  string
		pattern string
	}{
		{`/dev/tcp/`, esc + `\b.*/dev/tcp/`},
		{`socket`, esc + `\b.*socket.*connect`},
		{`-e /bin`, esc + `\b.*-e\s+/bin/(sh|bash)`},
		{`mkfifo`, `mkfifo.*\b` + esc + `\b`},
		{`pty.spawn`, esc + `\b.*\bpty\.spawn`},
		{`TCPSocket`, esc + `\b.*TCPSocket`},
		{`fsockopen`, esc + `\b.*fsockopen`},
	}
	for _, p := range indicators {
		if strings.Contains(code, p.needle) {
			return p.pattern
		}
	}
	return ""
}

func fileWritePatternFromCode(binary string, code string) string {
	esc := regexp.QuoteMeta(binary)
	indicators := []struct {
		needle  string
		pattern string
	}{
		{`/etc/passwd`, esc + `\b.*/etc/(passwd|shadow|sudoers|crontab)`},
		{`/etc/shadow`, esc + `\b.*/etc/(passwd|shadow|sudoers|crontab)`},
		{`/etc/sudoers`, esc + `\b.*/etc/(passwd|shadow|sudoers|crontab)`},
		{`authorized_keys`, esc + `\b.*authorized_keys`},
	}
	for _, p := range indicators {
		if strings.Contains(code, p.needle) {
			return p.pattern
		}
	}
	return ""
}

func dataExfilPatternFromCode(binary string, code string) string {
	esc := regexp.QuoteMeta(binary)
	indicators := []struct {
		needle  string
		pattern string
	}{
		{`http://`, esc + `\b.*https?://`},
		{`https://`, esc + `\b.*https?://`},
		{`ftp://`, esc + `\b.*ftp://`},
		{`TCPServer`, esc + `\b.*TCPServer`},
		{`http.server`, esc + `\b.*http\.server`},
		{`SimpleHTTPServer`, esc + `\b.*SimpleHTTPServer`},
	}
	for _, p := range indicators {
		if strings.Contains(code, p.needle) {
			return p.pattern
		}
	}
	return ""
}

func libraryLoadPatternFromCode(binary string, code string) string {
	esc := regexp.QuoteMeta(binary)
	if strings.Contains(code, "cdll.LoadLibrary") || strings.Contains(code, "ctypes") {
		return esc + `\b.*\b(cdll\.LoadLibrary|ctypes)`
	}
	if strings.Contains(code, "dlopen") {
		return esc + `\b.*\bdlopen\b`
	}
	return ""
}

func functionSeverity(fn string) string {
	switch fn {
	case "shell", "reverse-shell", "bind-shell", "inherit":
		return "critical"
	case "file-write", "download", "upload", "library-load":
		return "high"
	case "file-read", "command":
		return "medium"
	default:
		return "medium"
	}
}
