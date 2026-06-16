package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteCreates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("hello world")

	if err := Write(path, content, 0o644); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", data, content)
	}
}

func TestWriteCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "nested", "test.txt")
	content := []byte("nested file")

	if err := Write(path, content, 0o644); err != nil {
		t.Fatalf("Write with parents failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", data, content)
	}
}

func TestWriteWithBackupNoExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.txt")
	content := []byte("fresh file")

	backup, err := WriteWithBackup(path, content, 0o644)
	if err != nil {
		t.Fatalf("WriteWithBackup failed: %v", err)
	}

	if backup != "" {
		t.Errorf("backup should be empty for new file, got %q", backup)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("content mismatch: got %q, want %q", data, content)
	}
}

func TestWriteWithBackupMakesBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	originalContent := []byte("original")
	newContent := []byte("new")

	// Write initial file
	if err := os.WriteFile(path, originalContent, 0o644); err != nil {
		t.Fatalf("initial WriteFile failed: %v", err)
	}

	// Overwrite with backup
	backup, err := WriteWithBackup(path, newContent, 0o644)
	if err != nil {
		t.Fatalf("WriteWithBackup failed: %v", err)
	}

	if backup == "" {
		t.Fatal("backup path should not be empty for existing file")
	}

	// Verify backup exists and contains original
	backupData, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("ReadFile backup failed: %v", err)
	}

	if string(backupData) != string(originalContent) {
		t.Errorf("backup content mismatch: got %q, want %q", backupData, originalContent)
	}

	// Verify target contains new content
	targetData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile target failed: %v", err)
	}

	if string(targetData) != string(newContent) {
		t.Errorf("target content mismatch: got %q, want %q", targetData, newContent)
	}
}
