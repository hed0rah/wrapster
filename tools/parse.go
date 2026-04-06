//go:build ignore

// Parses the GTFOBins repo into a structured JSON knowledge base.
// Usage: go run gtfobins/parse.go /path/to/GTFOBins.github.io/_gtfobins
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Raw GTFOBins YAML structure
type gtfoEntry struct {
	Comment   string                     `yaml:"comment"`
	Functions map[string][]gtfoTechnique `yaml:"functions"`
}

type gtfoTechnique struct {
	Code     string         `yaml:"code"`
	Comment  string         `yaml:"comment"`
	Contexts map[string]any `yaml:"contexts"`
	From     string         `yaml:"from"`
}

// Our output format
type Binary struct {
	Name        string   `json:"name"`
	Functions   []string `json:"functions"`
	RiskLevel   string   `json:"risk_level"` // critical, high, medium, low
	ShellEscape bool     `json:"shell_escape"`
	ReverseShell bool    `json:"reverse_shell"`
	FileRead    bool     `json:"file_read"`
	FileWrite   bool     `json:"file_write"`
	Download    bool     `json:"download"`
	Upload      bool     `json:"upload"`
	SUID        bool     `json:"suid_exploitable"`
	Sudo        bool     `json:"sudo_exploitable"`
	Techniques  []Technique `json:"techniques"`
}

type Technique struct {
	Function string `json:"function"`
	Code     string `json:"code"`
	Comment  string `json:"comment,omitempty"`
}

func riskLevel(b *Binary) string {
	if b.ShellEscape || b.ReverseShell {
		return "critical"
	}
	if b.FileWrite || b.Download {
		return "high"
	}
	if b.FileRead || b.Upload {
		return "medium"
	}
	return "low"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run parse.go /path/to/_gtfobins")
		os.Exit(1)
	}

	dir := os.Args[1]
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading dir: %v\n", err)
		os.Exit(1)
	}

	var binaries []Binary
	stats := map[string]int{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", entry.Name(), err)
			continue
		}

		// Strip YAML front matter delimiters
		content := string(data)
		content = strings.TrimPrefix(content, "---\n")
		content = strings.TrimSuffix(content, "...\n")

		var raw gtfoEntry
		if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: yaml: %v\n", entry.Name(), err)
			continue
		}

		b := Binary{Name: entry.Name()}

		for funcName, techniques := range raw.Functions {
			b.Functions = append(b.Functions, funcName)
			stats[funcName]++

			switch funcName {
			case "shell":
				b.ShellEscape = true
			case "reverse-shell":
				b.ReverseShell = true
			case "file-read":
				b.FileRead = true
			case "file-write":
				b.FileWrite = true
			case "download":
				b.Download = true
			case "upload":
				b.Upload = true
			}

			for _, t := range techniques {
				// Check contexts
				if _, ok := t.Contexts["suid"]; ok {
					b.SUID = true
				}
				if _, ok := t.Contexts["sudo"]; ok {
					b.Sudo = true
				}

				if t.Code != "" {
					b.Techniques = append(b.Techniques, Technique{
						Function: funcName,
						Code:     t.Code,
						Comment:  t.Comment,
					})
				}
			}
		}

		sort.Strings(b.Functions)
		b.RiskLevel = riskLevel(&b)
		binaries = append(binaries, b)
	}

	sort.Slice(binaries, func(i, j int) bool {
		return binaries[i].Name < binaries[j].Name
	})

	// Output
	out := map[string]any{
		"source":       "https://gtfobins.org",
		"license":      "CC-BY-SA-4.0",
		"total":        len(binaries),
		"stats":        stats,
		"binaries":     binaries,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		os.Exit(1)
	}
}
