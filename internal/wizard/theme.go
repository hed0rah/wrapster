package wizard

import (
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// theme holds the lipgloss styles and the huh form theme used across the wizard.
type theme struct {
	accent lipgloss.Color
	muted  lipgloss.Color
	danger lipgloss.Color
	ok     lipgloss.Color
	warn   lipgloss.Color

	banner   lipgloss.Style
	subtitle lipgloss.Style
	box      lipgloss.Style
	boxFocus lipgloss.Style
	title    lipgloss.Style
	footer   lipgloss.Style
	key      lipgloss.Style
	item     lipgloss.Style
	itemSel  lipgloss.Style
	itemDesc lipgloss.Style
	flag     lipgloss.Style
	huh      *huh.Theme
}

func newTheme() theme {
	accent := lipgloss.Color("212") // pink/magenta
	muted := lipgloss.Color("241")
	danger := lipgloss.Color("203")
	ok := lipgloss.Color("78")
	warn := lipgloss.Color("221")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(muted).
		Padding(0, 1)

	return theme{
		accent:   accent,
		muted:    muted,
		danger:   danger,
		ok:       ok,
		warn:     warn,
		banner:   lipgloss.NewStyle().Foreground(accent).Bold(true),
		subtitle: lipgloss.NewStyle().Foreground(muted),
		box:      box,
		boxFocus: box.BorderForeground(accent),
		title:    lipgloss.NewStyle().Foreground(accent).Bold(true),
		footer:   lipgloss.NewStyle().Foreground(muted),
		key:      lipgloss.NewStyle().Foreground(accent).Bold(true),
		item:     lipgloss.NewStyle().Foreground(lipgloss.Color("252")),
		itemSel:  lipgloss.NewStyle().Foreground(accent).Bold(true),
		itemDesc: lipgloss.NewStyle().Foreground(muted),
		flag:     lipgloss.NewStyle().Foreground(warn),
		huh:      huh.ThemeCharm(),
	}
}
