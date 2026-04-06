package filter

import "fmt"

// ModuleConfig is the per-module configuration from the policy file.
type ModuleConfig struct {
	Enabled bool     `yaml:"enabled"`
	Block   []string `yaml:"block"` // function names to hard-block
	Warn    []string `yaml:"warn"`  // function names to log-but-allow
	Path    string   `yaml:"path"`  // for custom modules: file path
}

// FilterConfig is the top-level filter configuration from the policy file.
type FilterConfig struct {
	GTFOBins    ModuleConfig       `yaml:"gtfobins"`
	Destructive ModuleConfig       `yaml:"destructive"`
	Exfil       ModuleConfig       `yaml:"exfil"`
	Custom      []CustomModuleRef  `yaml:"custom"`
	WorkDir     string             `yaml:"-"` // set programmatically from local.work_dir
}

// CustomModuleRef references a custom rule file.
type CustomModuleRef struct {
	Name    string `yaml:"name"`
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

// DefaultConfig returns sensible defaults matching the behavior before
// the modular filter system existed.
func DefaultConfig() FilterConfig {
	return FilterConfig{
		GTFOBins:    ModuleConfig{Enabled: true, Block: []string{"shell", "reverse-shell", "bind-shell", "inherit"}},
		Destructive: ModuleConfig{Enabled: true},
		Exfil:       ModuleConfig{Enabled: false},
	}
}

// Build constructs a Chain from a FilterConfig.
// If cfg is zero-value (all fields empty), uses DefaultConfig.
func Build(cfg FilterConfig) (*Chain, error) {
	if isZeroConfig(cfg) {
		cfg = DefaultConfig()
	}

	var filters []Filter

	if cfg.GTFOBins.Enabled {
		gf, err := NewGTFObins()
		if err != nil {
			return nil, fmt.Errorf("gtfobins filter: %w", err)
		}
		filters = append(filters, gf)
	}

	if cfg.Destructive.Enabled {
		filters = append(filters, NewDestructive())
	}

	if cfg.Exfil.Enabled {
		filters = append(filters, NewExfil())
	}

	if cfg.WorkDir != "" {
		filters = append(filters, NewWorkdirFilter(cfg.WorkDir))
	}

	for _, ref := range cfg.Custom {
		if !ref.Enabled || ref.Path == "" {
			continue
		}
		name := ref.Name
		if name == "" {
			name = ref.Path
		}
		cf, err := LoadCustom(name, ref.Path)
		if err != nil {
			return nil, fmt.Errorf("custom filter %q: %w", name, err)
		}
		filters = append(filters, cf)
	}

	return NewChain(filters, nil), nil
}

func isZeroConfig(cfg FilterConfig) bool {
	return !cfg.GTFOBins.Enabled && !cfg.Destructive.Enabled && !cfg.Exfil.Enabled && len(cfg.Custom) == 0 &&
		len(cfg.GTFOBins.Block) == 0 && len(cfg.GTFOBins.Warn) == 0
}
