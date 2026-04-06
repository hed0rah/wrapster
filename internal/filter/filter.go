// Package filter provides a modular, configurable command inspection system.
// Filters are named modules of detection patterns (e.g. GTFOBins exploit
// signatures, destructive command detection, data exfil detection). A Chain
// runs all active filters and applies severity thresholds to decide whether
// to block or warn.
package filter

// Finding describes a detected pattern in a command.
type Finding struct {
	Module   string `json:"module"`   // filter module name: "gtfobins", "destructive", etc.
	Function string `json:"function"` // exploit class: "shell", "reverse-shell", "file-write", ...
	Pattern  string `json:"pattern"`  // the regex that matched
	Detail   string `json:"detail"`   // human-readable description or example code
	Severity string `json:"severity"` // "critical", "high", "medium", "low"
}

// Filter is a loadable detection module.
type Filter interface {
	Name() string
	Scan(command string) []Finding
}

// Chain is an ordered list of active filters with severity-based blocking.
type Chain struct {
	filters         []Filter
	blockSeverities map[string]bool
}

// NewChain creates a Chain that blocks findings at the given severity levels.
// Default block severities if none provided: critical, high.
func NewChain(filters []Filter, blockSeverities []string) *Chain {
	bs := map[string]bool{"critical": true, "high": true}
	if len(blockSeverities) > 0 {
		bs = make(map[string]bool, len(blockSeverities))
		for _, s := range blockSeverities {
			bs[s] = true
		}
	}
	return &Chain{filters: filters, blockSeverities: bs}
}

// Scan runs all filters and returns every finding.
func (c *Chain) Scan(command string) []Finding {
	var all []Finding
	for _, f := range c.filters {
		all = append(all, f.Scan(command)...)
	}
	return all
}

// Block returns only findings that meet the blocking severity threshold.
func (c *Chain) Block(command string) []Finding {
	all := c.Scan(command)
	var blocked []Finding
	for _, f := range all {
		if c.blockSeverities[f.Severity] {
			blocked = append(blocked, f)
		}
	}
	return blocked
}
