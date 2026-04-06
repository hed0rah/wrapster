package filter

import (
	"net"
	"regexp"
	"strings"
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
		// HTTP/FTP outbound from common tools
		{`\bcurl\b.*https?://(?!127\.|localhost|0\.0\.0\.0)`, "exfil", "high",
			"curl to external URL"},
		{`\bwget\b.*https?://(?!127\.|localhost|0\.0\.0\.0)`, "exfil", "high",
			"wget to external URL"},
		{`\bscp\b.*@(?!127\.|localhost)`, "exfil", "high",
			"scp to external host"},
		{`\brsync\b.*@(?!127\.|localhost)`, "exfil", "high",
			"rsync to external host"},
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

		// DNS tunneling indicators
		{`\bdig\b.*TXT.*@(?!127\.|localhost)`, "exfil", "high",
			"DNS TXT query (potential DNS tunneling)"},
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
	locals := []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "0.0.0.0/32"}
	for _, cidr := range locals {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
