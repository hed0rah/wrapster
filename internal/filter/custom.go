package filter

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// CustomFilter loads user-defined detection rules from a YAML file.
type CustomFilter struct {
	name  string
	rules []rule
}

// CustomRuleFile is the top-level structure of a custom rules YAML.
type CustomRuleFile struct {
	Rules []CustomRuleDef `yaml:"rules"`
}

// CustomRuleDef is a single user-defined detection rule.
type CustomRuleDef struct {
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Function string `yaml:"function"` // "destructive", "shell", "exfil", etc.
	Severity string `yaml:"severity"` // "critical", "high", "medium", "low"
	Message  string `yaml:"message"`
}

func LoadCustom(name, path string) (*CustomFilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading custom rules %q: %w", path, err)
	}

	var file CustomRuleFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing custom rules %q: %w", path, err)
	}

	f := &CustomFilter{name: name}
	for _, def := range file.Rules {
		re, err := regexp.Compile("(?i)" + def.Pattern)
		if err != nil {
			return nil, fmt.Errorf("bad pattern in rule %q: %w", def.Name, err)
		}
		sev := def.Severity
		if sev == "" {
			sev = "high"
		}
		fn := def.Function
		if fn == "" {
			fn = "custom"
		}
		detail := def.Message
		if detail == "" {
			detail = def.Name
		}
		f.rules = append(f.rules, rule{
			function: fn,
			pattern:  re,
			rawPat:   def.Pattern,
			detail:   detail,
			severity: sev,
		})
	}

	return f, nil
}

func (f *CustomFilter) Name() string { return "custom:" + f.name }

func (f *CustomFilter) Scan(command string) []Finding {
	var findings []Finding
	for _, r := range f.rules {
		if r.pattern.MatchString(command) {
			findings = append(findings, Finding{
				Module:   f.Name(),
				Function: r.function,
				Pattern:  r.rawPat,
				Detail:   r.detail,
				Severity: r.severity,
			})
		}
	}
	return findings
}
