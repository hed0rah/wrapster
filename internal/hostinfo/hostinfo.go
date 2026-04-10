// Package hostinfo fingerprints a remote host over SSH and caches the result.
// The host_info MCP tool uses this to give the model compact OS/environment
// context without running a dozen probing commands individually.
package hostinfo

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// Info is the cached host fingerprint.
type Info struct {
	Host       string    `json:"host"`
	OS         string    `json:"os,omitempty"`         // e.g. "Ubuntu 24.04 LTS"
	Kernel     string    `json:"kernel,omitempty"`     // e.g. "6.8.0-51-generic x86_64"
	Shell      string    `json:"shell,omitempty"`      // e.g. "/bin/bash"
	PkgManager string    `json:"pkg_manager,omitempty"` // e.g. "apt"
	Tools      []string  `json:"tools,omitempty"`      // installed tools detected
	CachedAt   time.Time `json:"cached_at"`
}

// ExecFunc is the signature of a function that runs a command on a host and
// returns (stdout, stderr, error). Injected so this package stays free of SSH deps.
type ExecFunc func(ctx context.Context, host, command string) (stdout, stderr string, err error)

// Cache stores host fingerprints keyed by host name.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*Info
	ttl     time.Duration
}

// New returns a Cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return &Cache{entries: make(map[string]*Info), ttl: ttl}
}

// Get returns a cached Info if present and not expired. Returns nil otherwise.
func (c *Cache) Get(host string) *Info {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, ok := c.entries[host]
	if !ok || time.Since(info.CachedAt) > c.ttl {
		return nil
	}
	return info
}

// Put stores a fingerprint.
func (c *Cache) Put(host string, info *Info) {
	c.mu.Lock()
	info.CachedAt = time.Now()
	c.entries[host] = info
	c.mu.Unlock()
}

// Invalidate removes a host's fingerprint.
func (c *Cache) Invalidate(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// Fingerprint runs the probe bundle on the host and returns structured Info.
// Errors from individual probes are ignored -- partial data is still useful.
func Fingerprint(ctx context.Context, host string, exec ExecFunc) (*Info, error) {
	info := &Info{Host: host}

	// OS release
	out, _, _ := exec(ctx, host, `cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|NAME|VERSION_ID)' | head -3`)
	info.OS = parseOSRelease(out)
	if info.OS == "" {
		// fallback for non-Linux (BSD, macOS)
		out, _, _ = exec(ctx, host, `uname -s -r 2>/dev/null`)
		info.OS = strings.TrimSpace(out)
	}

	// Kernel + arch
	out, _, _ = exec(ctx, host, `uname -r -m 2>/dev/null`)
	info.Kernel = strings.TrimSpace(out)

	// Login shell
	out, _, _ = exec(ctx, host, `echo $SHELL`)
	info.Shell = strings.TrimSpace(out)

	// Package manager -- first match wins
	out, _, _ = exec(ctx, host, `for pm in apt dnf yum pacman apk brew zypper; do which $pm 2>/dev/null && break; done`)
	if path := strings.TrimSpace(out); path != "" {
		parts := strings.Split(path, "/")
		info.PkgManager = parts[len(parts)-1]
	}

	// Common tools -- check presence in one shot
	out, _, _ = exec(ctx, host,
		`for t in python3 python node go cargo docker kubectl helm rg fd git make gcc; do which $t 2>/dev/null && echo $t; done`)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.Contains(line, "/") {
			// `which` prints full path; `echo $t` prints name -- keep names
			info.Tools = append(info.Tools, line)
		} else if line != "" {
			parts := strings.Split(line, "/")
			info.Tools = append(info.Tools, parts[len(parts)-1])
		}
	}
	// deduplicate tools list
	info.Tools = dedup(info.Tools)

	return info, nil
}

// JSON returns the info serialised as indented JSON.
func (i *Info) JSON() string {
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b)
}

func parseOSRelease(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	// fallback: NAME + VERSION_ID
	var name, ver string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "NAME=") {
			name = strings.Trim(strings.TrimPrefix(line, "NAME="), `"`)
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			ver = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	if name != "" {
		if ver != "" {
			return name + " " + ver
		}
		return name
	}
	return ""
}

func dedup(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
