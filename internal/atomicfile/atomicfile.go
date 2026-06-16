// Package atomicfile writes files atomically, with an optional timestamped
// backup of any pre-existing file. Writes go to a temp file in the same
// directory and are renamed into place; the rename is atomic on Unix and uses
// ReplaceFile on Windows (via natefinch/atomic), so a crash never leaves a
// half-written config.
package atomicfile

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/natefinch/atomic"
)

// Write atomically writes data to path, creating parent directories as needed.
// perm is applied to the final file (best effort; the temp file is created with
// restrictive permissions first).
func Write(path string, data []byte, perm os.FileMode) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
	}
	if err := atomic.WriteFile(path, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if perm != 0 {
		_ = os.Chmod(path, perm)
	}
	return nil
}

// WriteWithBackup behaves like Write, but if path already exists it is first
// copied to "<path>.<unixtime>.bak". The backup path (empty if none was made)
// is returned so the caller can report or clean it up.
func WriteWithBackup(path string, data []byte, perm os.FileMode) (backup string, err error) {
	existing, rerr := os.ReadFile(path)
	switch {
	case rerr == nil:
		backup = fmt.Sprintf("%s.%d.bak", path, time.Now().Unix())
		if werr := os.WriteFile(backup, existing, 0o600); werr != nil {
			return "", fmt.Errorf("writing backup %s: %w", backup, werr)
		}
	case !os.IsNotExist(rerr):
		return "", fmt.Errorf("reading %s: %w", path, rerr)
	}
	if werr := Write(path, data, perm); werr != nil {
		return backup, werr
	}
	return backup, nil
}
