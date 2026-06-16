// Package wizard implements `wrapster config`: an interactive TUI for authoring
// a policy file and registering wrapster into the MCP client configs found on
// the machine.
package wizard

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/hed0rah/wrapster/internal/mcpconfig"
	"github.com/hed0rah/wrapster/internal/policyio"
)

// Options configures a wizard run.
type Options struct {
	// PolicyPath, if set, is loaded for editing and preselected as the save target.
	PolicyPath string
}

// Run launches the wizard and blocks until the user exits.
func Run(opts Options) error {
	pol, err := policyio.LoadForEdit(opts.PolicyPath)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	exe := "wrapster"
	if p, err := os.Executable(); err == nil && p != "" {
		exe = p
		if abs, err := filepath.Abs(p); err == nil {
			exe = abs
		}
	}

	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	env := mcpconfig.Env{GOOS: runtime.GOOS, Home: home, Getenv: os.Getenv}
	ctx := mcpconfig.PathCtx{RepoRoot: findRepoRoot(cwd), Cwd: cwd}

	m := newModel(pol, opts.PolicyPath, exe, env, ctx)
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

// findRepoRoot walks up from dir looking for a .git entry, for project-scoped
// client configs. Returns "" when not inside a repository.
func findRepoRoot(dir string) string {
	for dir != "" {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}
