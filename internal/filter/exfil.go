package filter

import (
	"net"
	"regexp"
	"strings"
)

// External-destination patterns. These replace negative-lookahead rules (which
// RE2 silently dropped); the captured host is post-filtered via isLocalHost.
var (
	urlDestPattern = regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|;&\n]*?\bhttps?://([^/\s'"]+)`)
	sshDestPattern = regexp.MustCompile(`(?i)\b(?:scp|rsync)\b[^|;&\n]*?\s[^\s'"]*@([^:/\s'"]+)`)
	dnsTxtPattern  = regexp.MustCompile(`(?i)\bdig\b[^|;&\n]*\bTXT\b[^|;&\n]*@([^\s'"]+)`)
)

// ExfilFilter detects data exfiltration attempts: outbound transfers
// to non-local IPs, HTTP server spawning, DNS tunneling indicators.
type ExfilFilter struct {
	rules  []rule
	ipPat  *regexp.Regexp
}

func NewExfil() *ExfilFilter {
	defs := []struct {
		pattern  string
		function string
		severity string
		desc     string
	}{
		// HTTP/FTP outbound from common tools. External-URL/host detection for
		// curl/wget/scp/rsync is done in Scan (urlDestPattern/sshDestPattern)
		// because RE2 has no negative lookahead.
		{`\bftp\b`, "exfil", "medium",
			"FTP usage"},

		// Netcat listeners / connections
		{`\bnc\b.*-l`, "exfil", "high",
			"netcat listener"},
		{`\bncat\b.*-l`, "exfil", "high",
			"ncat listener"},
		{`\bsocat\b.*TCP-LISTEN`, "exfil", "high",
			"socat TCP listener"},

		// HTTP servers (data exfil via serving)
		{`python.*\bhttp\.server\b`, "exfil", "high",
			"Python HTTP server"},
		{`python.*SimpleHTTPServer`, "exfil", "high",
			"Python SimpleHTTPServer"},
		{`\bphp\b.*-S\s`, "exfil", "high",
			"PHP built-in server"},
		{`\bruby\b.*-run.*httpd`, "exfil", "high",
			"Ruby HTTP server"},

		// DNS tunneling indicators. The dig TXT external-resolver case is handled
		// in Scan (dnsTxtPattern); RE2 cannot express the negative lookahead.
		{`\bnslookup\b.*-type=TXT`, "exfil", "medium",
			"nslookup TXT query"},

		// Encoded data piped to network tools
		{`\bbase64\b.*\|\s*(curl|wget|nc|ncat)`, "exfil", "critical",
			"base64 data piped to network tool"},
	}

	f := &ExfilFilter{
		ipPat: regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`),
	}
	for _, d := range defs {
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

func (f *ExfilFilter) Name() string { return "exfil" }

func (f *ExfilFilter) Scan(command string) []Finding {
	var findings []Finding
	for _, r := range f.rules {
		if r.pattern.MatchString(command) {
			findings = append(findings, Finding{
				Module:   "exfil",
				Function: r.function,
				Pattern:  r.rawPat,
				Detail:   r.detail,
				Severity: r.severity,
			})
		}
	}

	// External-destination detection (replaces the old negative-lookahead rules
	// that RE2 silently dropped): match tool + destination, then post-filter
	// local hosts in code.
	for _, dc := range []struct {
		re     *regexp.Regexp
		detail string
	}{
		{urlDestPattern, "outbound transfer to external URL"},
		{sshDestPattern, "scp/rsync to external host"},
		{dnsTxtPattern, "DNS TXT query to external resolver (possible tunneling)"},
	} {
		if m := dc.re.FindStringSubmatch(command); m != nil && !isLocalHost(m[1]) {
			findings = append(findings, Finding{
				Module:   "exfil",
				Function: "exfil",
				Pattern:  dc.re.String(),
				Detail:   dc.detail + ": " + m[1],
				Severity: "high",
			})
		}
	}

	// Check for non-local IP addresses in commands that use network tools
	if containsNetworkTool(command) {
		matches := f.ipPat.FindAllString(command, -1)
		for _, ip := range matches {
			if !isLocalIP(ip) {
				findings = append(findings, Finding{
					Module:   "exfil",
					Function: "exfil",
					Pattern:  "non-local IP in network command",
					Detail:   "external IP " + ip + " detected in network command",
					Severity: "high",
				})
				break // one finding per command is enough
			}
		}
	}

	return findings
}

func containsNetworkTool(cmd string) bool {
	tools := []string{"curl", "wget", "nc", "ncat", "socat", "scp", "rsync", "ssh", "ftp", "sftp"}
	lower := strings.ToLower(cmd)
	for _, t := range tools {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	// Covers IPv4 and IPv6 loopback, RFC1918 / ULA private ranges, unspecified
	// (0.0.0.0 / ::), and link-local. RFC1918 is treated as local to avoid
	// flagging routine internal administration.
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
}

// isLocalHost reports whether a URL/scp host component refers to the local
// machine or a private host (so it is not flagged as exfiltration).
func isLocalHost(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	// strip a :port suffix for host:port (but not for bare IPv6 literals)
	if strings.Count(host, ":") == 1 {
		host = host[:strings.Index(host, ":")]
	}
	switch host {
	case "", "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return true
	}
	if net.ParseIP(host) != nil {
		return isLocalIP(host)
	}
	return strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost")
}
