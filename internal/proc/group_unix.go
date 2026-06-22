//go:build !windows

// Package proc configures an exec.Cmd so that cancelling its context (e.g. on a
// timeout) kills the whole process tree, not just the direct child -- otherwise
// a `sh -c "cmd"` that spawns grandchildren leaves them orphaned.
package proc

import (
	"os/exec"
	"syscall"
	"time"
)

// SetProcGroup puts cmd in its own process group and, when its context is
// cancelled, kills the entire group (negative pid) so grandchildren die too.
// WaitDelay bounds how long Wait blocks after the kill.
func SetProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 3 * time.Second
}
