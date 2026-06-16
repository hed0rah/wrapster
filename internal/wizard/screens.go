package wizard

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/hed0rah/wrapster/internal/mcpconfig"
	"github.com/hed0rah/wrapster/internal/policyio"
)

// localForm edits local execution mode, working dir, and timeout.
func (m *model) localForm() *huh.Form {
	m.timeoutStr = m.pol.Local.Timeout.Std().String()
	if m.pol.Local.Timeout == 0 {
		m.timeoutStr = "30s"
	}
	return huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Local execution mode").
			Description("guardrail: allow unless a filter catches it. allowlist: deny unless explicitly allowed.").
			Options(huh.NewOptions("guardrail", "allowlist")...).
			Value(&m.pol.Local.Mode),
		huh.NewInput().
			Title("Working directory (optional)").
			Description("restrict local commands to this directory; blank means no restriction").
			Value(&m.pol.Local.WorkDir),
		huh.NewInput().
			Title("Command timeout").
			Description("e.g. 30s, 1m, 5m").
			Validate(validateDuration).
			Value(&m.timeoutStr),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

// filtersForm toggles the security filter modules and their severities.
func (m *model) filtersForm() *huh.Form {
	gtfoClasses := []string{"shell", "reverse-shell", "bind-shell", "inherit", "file-write", "file-read", "download", "upload"}
	return huh.NewForm(huh.NewGroup(
		huh.NewConfirm().
			Title("GTFOBins filter").
			Description("block known shell-escape and exploit patterns").
			Value(&m.pol.Filters.GTFOBins.Enabled),
		huh.NewMultiSelect[string]().
			Title("GTFOBins: block these capability classes").
			Options(optsSelected(gtfoClasses, m.pol.Filters.GTFOBins.Block)...).
			Value(&m.pol.Filters.GTFOBins.Block),
		huh.NewConfirm().
			Title("Destructive filter").
			Description("block rm -rf, mkfs, DROP TABLE, git reset --hard, kubectl delete --all, etc.").
			Value(&m.pol.Filters.Destructive.Enabled),
		huh.NewConfirm().
			Title("Exfil filter").
			Description("flag outbound transfers to external hosts, listeners, and DNS tunneling").
			Value(&m.pol.Filters.Exfil.Enabled),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

// outputForm edits output post-processing.
func (m *model) outputForm() *huh.Form {
	m.maxCharsStr = strconv.Itoa(m.pol.Output.Truncate.MaxChars)
	if m.pol.Output.Truncate.MaxChars == 0 {
		m.maxCharsStr = "8192"
	}
	return huh.NewForm(huh.NewGroup(
		huh.NewConfirm().Title("Strip ANSI escape codes").Value(&m.pol.Output.ANSIStrip),
		huh.NewConfirm().Title("Truncate large output").Value(&m.pol.Output.Truncate.Enabled),
		huh.NewInput().
			Title("Truncate threshold (max chars)").
			Validate(validateInt).
			Value(&m.maxCharsStr),
		huh.NewConfirm().Title("Track output stats").Value(&m.pol.Output.Stats),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

// hostForm adds a single allowlisted SSH host.
func (m *model) hostForm() *huh.Form {
	m.hostName, m.hostAddr, m.hostUser, m.hostCmds = "", "", "", ""
	return huh.NewForm(huh.NewGroup(
		huh.NewInput().
			Title("Host alias").
			Description("used as `wrapster <alias> <command>`").
			Validate(nonEmpty).
			Value(&m.hostName),
		huh.NewInput().Title("Hostname or IP").Value(&m.hostAddr),
		huh.NewInput().Title("SSH user").Value(&m.hostUser),
		huh.NewInput().
			Title("Allowed commands (comma-separated)").
			Description("allowlist, e.g. uptime, df, nginx").
			Value(&m.hostCmds),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

// saveForm chooses a target path and confirms the write.
func (m *model) saveForm() *huh.Form {
	targets := policyio.TargetPaths()
	var opts []huh.Option[string]
	for _, tp := range targets {
		opts = append(opts, huh.NewOption(tp.Label+"  ("+tp.Path+")", tp.Path))
	}
	if m.savePath == "" {
		if m.polPath != "" {
			m.savePath = m.polPath
		} else if len(targets) > 0 {
			m.savePath = targets[0].Path
		}
	}
	m.saveConfirm = false
	return huh.NewForm(huh.NewGroup(
		huh.NewSelect[string]().Title("Save policy to").Options(opts...).Value(&m.savePath),
		huh.NewConfirm().Title("Write file now?").Affirmative("Save").Negative("Cancel").Value(&m.saveConfirm),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

// mcpForm detects clients and lets the user choose which to register into.
func (m *model) mcpForm() *huh.Form {
	m.dets = mcpconfig.DetectAll(m.env, m.ctx, mcpconfig.DefaultProbe())
	var opts []huh.Option[string]
	for _, d := range m.dets {
		label := d.Client.Display
		if d.Installed() {
			label += "  (detected)"
		}
		o := huh.NewOption(label, d.Client.Name)
		if d.Installed() {
			o = o.Selected(true)
		}
		opts = append(opts, o)
	}
	m.selected = nil
	return huh.NewForm(huh.NewGroup(
		huh.NewMultiSelect[string]().
			Title("Register wrapster into these MCP clients").
			Description("space to toggle; detected clients are preselected").
			Options(opts...).
			Value(&m.selected),
	)).WithShowHelp(true).WithTheme(m.theme.huh)
}

func optsSelected(all, selected []string) []huh.Option[string] {
	opts := make([]huh.Option[string], 0, len(all))
	for _, a := range all {
		o := huh.NewOption(a, a)
		if contains(selected, a) {
			o = o.Selected(true)
		}
		opts = append(opts, o)
	}
	return opts
}

func validateDuration(s string) error {
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	if _, err := time.ParseDuration(s); err != nil {
		return fmt.Errorf("not a duration like 30s, 1m")
	}
	return nil
}

func validateInt(s string) error {
	if s = strings.TrimSpace(s); s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err != nil || n < 0 {
		return fmt.Errorf("must be a non-negative integer")
	}
	return nil
}

func nonEmpty(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("required")
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
