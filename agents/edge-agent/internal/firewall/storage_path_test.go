package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewDiskStoreRejectsAncestorSymlinkBeforeCreatingState(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	directRoot := filepath.Join(root, "direct")
	if _, err := newDiskStore(directRoot); err != nil {
		t.Fatalf("newDiskStore(direct root) error=%v", err)
	}

	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Fatal(err)
	}
	configuredRoot := filepath.Join(aliasParent, "firewall-state")
	if _, err := newDiskStore(configuredRoot); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("newDiskStore(ancestor symlink) error=%v, want ErrInvalidPath", err)
	}
	if _, err := os.Lstat(filepath.Join(realParent, "firewall-state")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state leaf was created through ancestor symlink: %v", err)
	}
}
