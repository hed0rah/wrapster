package mcpconfig

import (
	"os"
	"os/exec"
	"path/filepath"
)

// Probe provides filesystem and path-lookup access for detection.
type Probe struct {
	// Stat checks if a file or directory exists.
	Stat func(string) (os.FileInfo, error)
	// LookPath searches for an executable in PATH.
	LookPath func(string) (string, error)
}

// DefaultProbe returns a Probe using standard filesystem and PATH operations.
func DefaultProbe() Probe {
	return Probe{
		Stat:     os.Stat,
		LookPath: exec.LookPath,
	}
}

// Detection represents the detection results for a single client.
type Detection struct {
	Client       Client
	ConfigExists bool
	DirExists    bool
	BinaryOnPath bool
	Path         string
}

// Installed returns true if the client appears to be installed
// (config exists, or config dir exists, or binary is on PATH).
func (d Detection) Installed() bool {
	return d.ConfigExists || d.DirExists || d.BinaryOnPath
}

// DetectAll runs detection for all registered clients and returns results in Registry order.
// Clients whose path resolution errors are still included with DirExists and BinaryOnPath only.
func DetectAll(env Env, ctx PathCtx, p Probe) []Detection {
	var results []Detection

	for _, client := range Registry() {
		detection := Detection{Client: client}

		// Resolve path; if it errors, skip path-based checks.
		path, pathErr := client.ConfigPath(env, ctx)
		if pathErr == nil {
			detection.Path = path

			// ConfigExists: Stat the config file itself.
			if _, err := p.Stat(path); err == nil {
				detection.ConfigExists = true
			}

			// DirExists: Stat the directory containing the config file.
			if _, err := p.Stat(filepath.Dir(path)); err == nil {
				detection.DirExists = true
			}
		}

		// BinaryOnPath: check if any of the client's LookPath binaries exist.
		for _, bin := range client.LookPath {
			if _, err := p.LookPath(bin); err == nil {
				detection.BinaryOnPath = true
				break
			}
		}

		results = append(results, detection)
	}

	return results
}
