//go:build windows

// Package proc configures an exec.Cmd so that cancelling its context (e.g. on a
// timeout) kills the whole process tree, not just the direct child -- otherwise
// a `cmd /C "cmd"` that spawns grandchildren leaves them orphaned.
package proc

import (
	"os/exec"
	"strconv"
	"time"
)

// SetProcGroup arranges for a context-cancel (e.g. on timeout) to kill the whole
// process tree via `taskkill /T`, so grandchildren are not orphaned. WaitDelay
// bounds how long Wait blocks after the kill.
func SetProcGroup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
	}
	cmd.WaitDelay = 3 * time.Second
}
