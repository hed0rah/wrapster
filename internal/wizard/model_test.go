package wizard

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hed0rah/wrapster/internal/mcpconfig"
	"github.com/hed0rah/wrapster/internal/policyio"
)

func TestModelSmoke(t *testing.T) {
	pol := policyio.DefaultPolicy()
	env := mcpconfig.Env{
		GOOS: "linux",
		Home: t.TempDir(),
		Getenv: func(string) string {
			return ""
		},
	}
	ctx := mcpconfig.PathCtx{}
	exe := "wrapster"

	m := newModel(pol, "", exe, env, ctx)

	// Send window size
	tm, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = tm.(*model)
	v := m.View()
	if v == "" {
		t.Error("View() returned empty after window size")
	}

	// Navigate down to first item (already selected at index 0)
	tm, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = tm.(*model)
	v = m.View()
	if v == "" {
		t.Error("View() returned empty after KeyDown")
	}

	// Open first form with Enter
	tm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = tm.(*model)
	v = m.View()
	if v == "" {
		t.Error("View() returned empty after opening form")
	}

	// Send Escape to cancel back to menu
	tm, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = tm.(*model)
	v = m.View()
	if v == "" {
		t.Error("View() returned empty after Escape")
	}
}
