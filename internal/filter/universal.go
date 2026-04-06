package filter

import "regexp"

// compileUniversal returns patterns that catch exploit classes regardless of
// which binary is being invoked.
func compileUniversal() []rule {
	defs := []struct {
		pattern  string
		function string
		severity string
		desc     string
	}{
		// === SHELL SPAWNING ===
		{`\b(exec|system|spawn)\s*\(\s*["']/bin/(sh|bash|dash|zsh)`, "shell", "critical",
			"shell spawn via exec/system/spawn call"},
		{`\bos\.(system|execl?e?|popen)\s*\(`, "shell", "critical",
			"Python os.system/exec/popen"},
		{`\bpty\.spawn\s*\(`, "shell", "critical",
			"Python pty.spawn"},
		{`\bsubprocess\.(call|run|Popen|check_output)\s*\(`, "shell", "critical",
			"Python subprocess"},
		{`\b__import__\s*\(\s*['"]os['"]`, "shell", "critical",
			"Python __import__('os') evasion"},
		{`\bProcess\.spawn\b`, "shell", "critical",
			"Ruby Process.spawn"},
		{`\bKernel\.exec\b`, "shell", "critical",
			"Ruby Kernel.exec"},
		{`\bIO\.popen\b`, "shell", "critical",
			"Ruby IO.popen"},
		{`\bexec\s+["']/bin/(sh|bash)`, "shell", "critical",
			"Perl exec /bin/sh"},
		{`\bos\.execute\s*\(`, "shell", "critical",
			"Lua os.execute"},
		{`\bio\.popen\s*\(`, "shell", "critical",
			"Lua io.popen"},
		{`\b(shell_exec|passthru|popen|proc_open)\s*\(`, "shell", "critical",
			"PHP shell execution"},
		{`Runtime.*\.exec\s*\(`, "shell", "critical",
			"Java Runtime.exec"},
		{`ProcessBuilder`, "shell", "critical",
			"Java ProcessBuilder"},
		{`child_process`, "shell", "critical",
			"Node.js child_process"},
		{`\.exec\s*\(\s*["']/bin/(sh|bash)`, "shell", "critical",
			"Node.js exec(/bin/sh)"},
		{`-c\s+['"]?\s*:!`, "shell", "critical",
			"vim :! shell escape"},
		{`-c\s+['"]?\s*:(py|lua|ruby|perl)\b`, "shell", "critical",
			"vim embedded language execution"},
		{`\bless\b.*!`, "shell", "high",
			"less ! shell escape"},
		{`\bfind\b.*-exec\s+.*\b(sh|bash|dash|zsh|env)\b`, "shell", "critical",
			"find -exec shell"},
		{`\b[mgn]?awk\b.*\bsystem\s*\(`, "shell", "critical",
			"awk system() call"},
		{`\bexpect\b.*\bspawn\b`, "shell", "critical",
			"expect spawn"},
		{`\b(strace|ltrace)\b.*-e\s+inject`, "shell", "critical",
			"strace/ltrace injection"},
		{`\|\s*(sh|bash|dash|zsh|ksh)\b`, "shell", "critical",
			"pipe to shell"},

		// === REVERSE SHELLS ===
		{`/dev/tcp/`, "reverse-shell", "critical",
			"bash /dev/tcp reverse shell"},
		{`\bnc\b.*-e\s+/bin/(sh|bash)`, "reverse-shell", "critical",
			"netcat reverse shell"},
		{`\bncat\b.*-e\s+/bin/(sh|bash)`, "reverse-shell", "critical",
			"ncat reverse shell"},
		{`\bsocat\b.*exec.*sh`, "reverse-shell", "critical",
			"socat reverse shell"},
		{`\bmkfifo\b`, "reverse-shell", "critical",
			"named pipe (mkfifo) -- common reverse shell component"},
		{`socket\.socket.*connect`, "reverse-shell", "critical",
			"socket connect (reverse shell indicator)"},

		// === DATA EXFILTRATION ===
		{`\bcurl\b.*\|\s*(sh|bash)`, "download", "critical",
			"curl pipe to shell (remote code execution)"},
		{`\bwget\b.*\|\s*(sh|bash)`, "download", "critical",
			"wget pipe to shell (remote code execution)"},
		{`\bhttp\.server\b`, "upload", "high",
			"Python HTTP server (potential data exfil)"},
		{`SimpleHTTPServer`, "upload", "high",
			"Python SimpleHTTPServer (potential data exfil)"},

		// === PRIVILEGE ESCALATION ===
		{`\bsetuid\s*\(\s*0\s*\)`, "privilege-escalation", "critical",
			"setuid(0) call"},
		{`\bsetreuid\b`, "privilege-escalation", "critical",
			"setreuid call"},

		// === SENSITIVE FILE ACCESS ===
		{`/etc/shadow`, "file-read", "high",
			"access to /etc/shadow"},
		{`/etc/sudoers`, "file-read", "high",
			"access to /etc/sudoers"},
		{`\.ssh/id_(rsa|dsa|ecdsa|ed25519)`, "file-read", "high",
			"access to SSH private keys"},
		{`authorized_keys`, "file-write", "critical",
			"SSH authorized_keys modification"},

		// === EVASION ===
		{`\bbase64\s+-d\b.*\|\s*(sh|bash)`, "shell", "critical",
			"base64 decoded payload piped to shell"},
		{`\becho\b.*\|\s*base64\s+-d\s*\|\s*(sh|bash)`, "shell", "critical",
			"encoded shell payload"},
		{`\beval\b.*\$\(`, "shell", "high",
			"eval with command substitution"},
	}

	rules := make([]rule, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile("(?i)" + d.pattern)
		if err != nil {
			continue
		}
		rules = append(rules, rule{
			function: d.function,
			pattern:  re,
			rawPat:   d.pattern,
			detail:   d.desc,
			severity: d.severity,
		})
	}
	return rules
}
