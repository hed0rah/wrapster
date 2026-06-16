package policyio

import (
	"os"
	"path/filepath"
	"time"

	"github.com/hed0rah/wrapster/internal/policy"
	"gopkg.in/yaml.v3"
)

// MarshalYAML marshals a policy to YAML bytes. Because policy.Duration
// implements MarshalYAML, timeouts serialize as "30s" automatically.
func MarshalYAML(p *policy.Policy) ([]byte, error) {
	return yaml.Marshal(p)
}

// DefaultPolicy returns a sensible starter policy for the config wizard.
func DefaultPolicy() *policy.Policy {
	return &policy.Policy{
		Defaults: policy.HostPolicy{},
		Hosts:    make(map[string]policy.HostPolicy),
		Local: policy.LocalConfig{
			Mode:    "guardrail",
			Timeout: policy.Duration(30 * time.Second),
		},
		Filters: policy.FilterConfig{
			GTFOBins: policy.FilterModuleConfig{
				Enabled: true,
				Block:   []string{"shell", "reverse-shell", "bind-shell", "inherit"},
			},
			Destructive: policy.FilterModuleConfig{
				Enabled: true,
			},
			Exfil: policy.FilterModuleConfig{
				Enabled: false,
			},
		},
		Output: policy.OutputConfig{
			ANSIStrip: true,
			Truncate: policy.OutputTruncateConfig{
				Enabled:   true,
				MaxChars:  8192,
				HeadLines: 64,
				TailLines: 16,
			},
			Stats: true,
		},
	}
}

// LoadForEdit loads a policy for editing. If path is not empty, it calls
// policy.LoadPolicy(path). Otherwise, it searches "./policy.yaml" then
// "~/.config/wrapster/policy.yaml" and loads the first that exists.
// If none found, returns DefaultPolicy with nil error.
func LoadForEdit(path string) (*policy.Policy, error) {
	if path != "" {
		return policy.LoadPolicy(path)
	}

	// Search in current directory first.
	if _, err := os.Stat("policy.yaml"); err == nil {
		return policy.LoadPolicy("policy.yaml")
	}

	// Search in user config directory.
	home, err := os.UserHomeDir()
	if err == nil {
		configPath := filepath.Join(home, ".config", "wrapster", "policy.yaml")
		if _, err := os.Stat(configPath); err == nil {
			return policy.LoadPolicy(configPath)
		}
	}

	// None found; return defaults.
	return DefaultPolicy(), nil
}

// TargetPath represents a candidate save location.
type TargetPath struct {
	Path  string
	Label string
}

// TargetPaths returns the two candidate save locations: current directory
// and user config (~/.config/wrapster). Skips the home location if
// os.UserHomeDir errors.
func TargetPaths() []TargetPath {
	paths := []TargetPath{
		{
			Path:  "policy.yaml",
			Label: "current directory",
		},
	}

	home, err := os.UserHomeDir()
	if err == nil {
		paths = append(paths, TargetPath{
			Path:  filepath.Join(home, ".config", "wrapster", "policy.yaml"),
			Label: "user config (~/.config/wrapster)",
		})
	}

	return paths
}
