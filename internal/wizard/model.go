package wizard

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/hed0rah/wrapster/internal/atomicfile"
	"github.com/hed0rah/wrapster/internal/mcpconfig"
	"github.com/hed0rah/wrapster/internal/policy"
	"github.com/hed0rah/wrapster/internal/policyio"
)

type screen int

const (
	scrMenu screen = iota
	scrForm
	scrResult
)

type action int

const (
	actLocal action = iota
	actFilters
	actOutput
	actHosts
	actSave
	actMCP
	actQuit
)

type menuItem struct {
	title string
	desc  string
	act   action
}

type model struct {
	pol     *policy.Policy
	polPath string
	exe     string
	env     mcpconfig.Env
	ctx     mcpconfig.PathCtx

	width, height int
	leftW, rightW int
	bodyH         int
	ready         bool

	scr    screen
	active action
	cursor int
	items  []menuItem

	form     *huh.Form
	vp       viewport.Model
	lastYAML string

	// scratch values for fields huh cannot bind to directly
	timeoutStr  string
	maxCharsStr string
	hostName    string
	hostAddr    string
	hostUser    string
	hostCmds    string
	savePath    string
	saveConfirm bool

	// mcp registration
	dets     []mcpconfig.Detection
	selected []string
	results  []mcpconfig.RegisterResult

	dirty  bool
	status string
	theme  theme
}

func newModel(pol *policy.Policy, polPath, exe string, env mcpconfig.Env, ctx mcpconfig.PathCtx) *model {
	return &model{
		pol:     pol,
		polPath: polPath,
		exe:     exe,
		env:     env,
		ctx:     ctx,
		scr:     scrMenu,
		theme:   newTheme(),
		items: []menuItem{
			{"Local execution", "guardrail/allowlist mode, working dir, timeout", actLocal},
			{"Security filters", "gtfobins, destructive, exfil modules", actFilters},
			{"Output processing", "ANSI strip, truncation, stats", actOutput},
			{"SSH hosts", "add an allowlisted remote host", actHosts},
			{"Save policy.yaml", "write the policy file (atomic, with backup)", actSave},
			{"Register MCP clients", "install wrapster into detected MCP clients", actMCP},
			{"Quit", "exit the wizard", actQuit},
		},
	}
}

func (m *model) Init() tea.Cmd { return nil }

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		m.recompute()
		return m, nil
	case tea.KeyMsg:
		switch m.scr {
		case scrMenu:
			return m.updateMenu(msg)
		case scrResult:
			m.scr = scrMenu
			return m, nil
		}
	}

	if m.scr == scrForm && m.form != nil {
		f, cmd := m.form.Update(msg)
		if ff, ok := f.(*huh.Form); ok {
			m.form = ff
		}
		m.recompute()
		switch m.form.State {
		case huh.StateCompleted:
			return m.onFormComplete()
		case huh.StateAborted:
			// local/filters/output bind huh fields live, so edits already
			// landed in the policy even on cancel; reflect that as unsaved.
			if m.active == actLocal || m.active == actFilters || m.active == actOutput {
				m.dirty = true
			}
			m.form = nil
			m.scr = scrMenu
			return m, nil
		}
		return m, cmd
	}
	return m, nil
}

func (m *model) updateMenu(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
		return m, nil
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
		return m, nil
	case "enter", "l", "right", " ":
		return m.openMenuItem()
	case "pgup", "pgdown", "ctrl+u", "ctrl+d":
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(k) // scroll the policy preview
		return m, cmd
	}
	return m, nil
}

func (m *model) openMenuItem() (tea.Model, tea.Cmd) {
	m.active = m.items[m.cursor].act
	m.status = ""
	switch m.active {
	case actQuit:
		return m, tea.Quit
	case actLocal:
		m.form = m.localForm()
	case actFilters:
		m.form = m.filtersForm()
	case actOutput:
		m.form = m.outputForm()
	case actHosts:
		m.form = m.hostForm()
	case actSave:
		m.form = m.saveForm()
	case actMCP:
		m.form = m.mcpForm()
	}
	m.scr = scrForm
	m.sizeForm()
	return m, m.form.Init()
}

func (m *model) onFormComplete() (tea.Model, tea.Cmd) {
	switch m.active {
	case actLocal:
		m.applyLocal()
	case actFilters:
		m.dirty = true // values are bound live
	case actOutput:
		m.applyOutput()
	case actHosts:
		m.applyHost()
	case actSave:
		return m.doSave()
	case actMCP:
		return m.doRegister()
	}
	m.form = nil
	m.scr = scrMenu
	m.recompute()
	return m, nil
}

func (m *model) applyLocal() {
	if d, err := time.ParseDuration(strings.TrimSpace(m.timeoutStr)); err == nil {
		m.pol.Local.Timeout = policy.Duration(d)
	}
	m.dirty = true
}

func (m *model) applyOutput() {
	if n, err := strconv.Atoi(strings.TrimSpace(m.maxCharsStr)); err == nil && n > 0 {
		m.pol.Output.Truncate.MaxChars = n
	}
	if m.pol.Output.Truncate.HeadLines == 0 {
		m.pol.Output.Truncate.HeadLines = 64
	}
	if m.pol.Output.Truncate.TailLines == 0 {
		m.pol.Output.Truncate.TailLines = 16
	}
	m.dirty = true
}

func (m *model) applyHost() {
	name := strings.TrimSpace(m.hostName)
	if name == "" || name == "local" {
		return
	}
	if m.pol.Hosts == nil {
		m.pol.Hosts = map[string]policy.HostPolicy{}
	}
	hp := policy.HostPolicy{Hostname: strings.TrimSpace(m.hostAddr), User: strings.TrimSpace(m.hostUser)}
	for _, c := range strings.Split(m.hostCmds, ",") {
		if c = strings.TrimSpace(c); c != "" {
			hp.AllowedCommands = append(hp.AllowedCommands, policy.CommandRule{Command: c})
		}
	}
	m.pol.Hosts[name] = hp
	m.dirty = true
}

func (m *model) doSave() (tea.Model, tea.Cmd) {
	m.form = nil
	m.scr = scrMenu
	if !m.saveConfirm || m.savePath == "" {
		m.status = "save cancelled"
		return m, nil
	}
	data, err := policyio.MarshalYAML(m.pol)
	if err != nil {
		m.status = "marshal error: " + err.Error()
		return m, nil
	}
	backup, err := atomicfile.WriteWithBackup(m.savePath, data, 0o644)
	if err != nil {
		m.status = "write error: " + err.Error()
		return m, nil
	}
	m.dirty = false
	m.polPath = m.savePath
	if backup != "" {
		m.status = "saved " + m.savePath + " (backup: " + filepath.Base(backup) + ")"
	} else {
		m.status = "saved " + m.savePath
	}
	return m, nil
}

func (m *model) doRegister() (tea.Model, tea.Cmd) {
	m.form = nil
	entry := mcpconfig.BuildEntry(m.exe, m.entryPolicyPath())
	opts := mcpconfig.RegisterOpts{
		Env:        m.env,
		Ctx:        m.ctx,
		Entry:      entry,
		ServerName: "wrapster",
		Conflict:   mcpconfig.Overwrite,
		Probe:      mcpconfig.DefaultProbe(),
	}
	var chosen []mcpconfig.Client
	for _, d := range m.dets {
		if contains(m.selected, d.Client.Name) {
			chosen = append(chosen, d.Client)
		}
	}
	m.results = mcpconfig.RegisterAll(chosen, opts)
	m.scr = scrResult
	return m, nil
}

func (m *model) entryPolicyPath() string {
	switch {
	case m.polPath != "":
		return m.polPath
	case m.savePath != "":
		return m.savePath
	}
	if tps := policyio.TargetPaths(); len(tps) > 0 {
		return tps[len(tps)-1].Path // prefer the user-config location
	}
	return "policy.yaml"
}

func (m *model) layout() {
	if m.width < 24 || m.height < 10 {
		return
	}
	const gap = 1
	leftOuter := (m.width - gap) * 55 / 100
	rightOuter := m.width - gap - leftOuter
	m.leftW = max(leftOuter-4, 12)
	m.rightW = max(rightOuter-4, 12)
	m.bodyH = max(m.height-6, 6)
	if !m.ready {
		m.vp = viewport.New(m.rightW, m.bodyH)
		m.ready = true
	} else {
		m.vp.Width = m.rightW
		m.vp.Height = m.bodyH
	}
	m.sizeForm()
}

func (m *model) sizeForm() {
	if m.form != nil && m.leftW > 0 {
		m.form = m.form.WithWidth(m.leftW).WithHeight(m.bodyH)
	}
}

func (m *model) recompute() {
	if !m.ready {
		return
	}
	data, err := policyio.MarshalYAML(m.pol)
	content := ""
	if err != nil {
		content = "# marshal error: " + err.Error()
	} else {
		content = highlightYAML(string(data), m.theme)
	}
	if content != m.lastYAML {
		m.lastYAML = content
		m.vp.SetContent(content)
	}
}

func (m *model) View() string {
	if !m.ready {
		return "starting wizard..."
	}

	var left string
	switch {
	case m.scr == scrResult:
		left = m.renderResults()
	case m.scr == scrForm && m.form != nil:
		left = m.form.View()
	default:
		left = m.renderMenu()
	}
	leftBox := m.theme.boxFocus.Width(m.leftW).Height(m.bodyH).Render(left)

	var right string
	rightDetails := m.scr == scrResult || (m.scr == scrForm && m.active == actMCP)
	if rightDetails {
		right = m.renderMCPSide()
	} else {
		right = m.vp.View()
	}
	rightBox := m.theme.box.Width(m.rightW).Height(m.bodyH).Render(right)

	body := lipgloss.JoinHorizontal(lipgloss.Top, leftBox, " ", rightBox)
	return lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), body, m.renderFooter())
}

func (m *model) renderHeader() string {
	title := m.theme.banner.Render("wrapster") + m.theme.subtitle.Render(" · config wizard")
	return title + "   " + m.theme.subtitle.Render(m.breadcrumb())
}

func (m *model) breadcrumb() string {
	switch {
	case m.scr == scrResult:
		return "Menu › Register MCP clients › results"
	case m.scr == scrForm:
		return "Menu › " + m.items[m.cursor].title
	default:
		return "Menu"
	}
}

func (m *model) renderFooter() string {
	var help string
	switch {
	case m.scr == scrMenu:
		help = m.hint("↑/↓", "move") + "   " + m.hint("enter", "open") + "   " + m.hint("q", "quit")
	case m.scr == scrResult:
		help = m.hint("any key", "back to menu")
	default:
		help = m.hint("tab / ↑↓", "fields") + "   " + m.hint("enter", "next") + "   " + m.hint("esc", "cancel")
	}
	if m.status != "" {
		help += "   " + m.theme.flag.Render(m.status)
	}
	if m.dirty {
		help += "   " + m.theme.flag.Render("● unsaved")
	}
	return m.theme.footer.Render(help)
}

func (m *model) hint(k, desc string) string {
	return m.theme.key.Render(k) + " " + m.theme.footer.Render(desc)
}

func (m *model) renderMenu() string {
	var b strings.Builder
	b.WriteString(m.theme.title.Render("Configuration") + "\n\n")
	for i, it := range m.items {
		if i == m.cursor {
			b.WriteString(m.theme.itemSel.Render("▸ "+it.title) + "\n")
		} else {
			b.WriteString("  " + m.theme.item.Render(it.title) + "\n")
		}
		b.WriteString("    " + m.theme.itemDesc.Render(it.desc) + "\n")
	}
	return b.String()
}

func (m *model) renderResults() string {
	var b strings.Builder
	b.WriteString(m.theme.title.Render("Registration results") + "\n\n")
	if len(m.results) == 0 {
		b.WriteString(m.theme.itemDesc.Render("no clients selected") + "\n")
	}
	for _, r := range m.results {
		color := m.theme.ok
		switch r.Action {
		case "error":
			color = m.theme.danger
		case "skipped":
			color = m.theme.warn
		}
		b.WriteString(lipgloss.NewStyle().Foreground(color).Render(fmt.Sprintf("%-12s", r.Action)))
		b.WriteString(" " + m.theme.item.Render(r.Client) + "\n")
		if r.Path != "" {
			b.WriteString("    " + m.theme.itemDesc.Render(r.Path) + "\n")
		}
		if r.Err != nil {
			b.WriteString("    " + lipgloss.NewStyle().Foreground(m.theme.danger).Render(r.Err.Error()) + "\n")
		}
	}
	return b.String()
}

func (m *model) renderMCPSide() string {
	var b strings.Builder
	b.WriteString(m.theme.title.Render("MCP server entry") + "\n\n")
	b.WriteString(m.theme.itemDesc.Render("command") + "\n  " + m.exe + "\n\n")
	b.WriteString(m.theme.itemDesc.Render("args") + "\n  --mcp --policy " + m.entryPolicyPath() + "\n\n")
	b.WriteString(m.theme.itemDesc.Render("Merged into each client's config without\nclobbering existing servers; a .bak of any\nexisting file is written first.") + "\n")
	return b.String()
}

func highlightYAML(s string, t theme) string {
	keyStyle := lipgloss.NewStyle().Foreground(t.accent)
	commentStyle := lipgloss.NewStyle().Foreground(t.muted)
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			b.WriteString(commentStyle.Render(line))
		} else if i := strings.Index(line, ":"); i > 0 {
			b.WriteString(keyStyle.Render(line[:i]))
			b.WriteString(valStyle.Render(line[i:]))
		} else {
			b.WriteString(valStyle.Render(line))
		}
		b.WriteByte('\n')
	}
	return b.String()
}
