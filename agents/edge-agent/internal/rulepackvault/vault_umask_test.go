//go:build unix

package rulepackvault

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The agent unit runs with UMask=0077: the plan directory and its parents
// must still be traversable by the worker group, or the Lua engine cannot
// open a plan and every site mounting rule packs answers 503 (live-site2).
func TestPlanDirectoriesStayTraversableUnderAgentUmask(t *testing.T) {
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	private, _ := newKey(t)
	root := filepath.Join(t.TempDir(), "run-cdnca")
	planDir := filepath.Join(root, "rule-packs", "plans")
	vault, err := open(Config{PrivateKey: private, StateDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1, PlanDir: planDir, PlanGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WritePlan(strings.Repeat("a", 64), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{root: 0o711, filepath.Dir(planDir): 0o711, planDir: 0o750} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", dir, info.Mode().Perm(), want)
		}
	}
}

// An older agent left /run/cdnca and /run/cdnca/rule-packs 0700: the next
// plan write repairs both to 0711 (no reboot needed after the upgrade).
func TestExistingPlanParentsAreRepairedTo0711(t *testing.T) {
	private, _ := newKey(t)
	root := filepath.Join(t.TempDir(), "run-cdnca")
	parent := filepath.Join(root, "rule-packs")
	planDir := filepath.Join(parent, "plans")
	if err := os.MkdirAll(planDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{root, parent, planDir} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	vault, err := open(Config{PrivateKey: private, StateDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1, PlanDir: planDir, PlanGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.WritePlan(strings.Repeat("a", 64), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	for dir, want := range map[string]os.FileMode{root: 0o711, parent: 0o711, planDir: 0o750} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", dir, info.Mode().Perm(), want)
		}
	}
}

// A symlinked plan parent is refused with an error, not skipped.
func TestSymlinkedPlanParentIsRefused(t *testing.T) {
	private, _ := newKey(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "rule-packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "run-cdnca")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	vault, err := open(Config{PrivateKey: private, StateDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1,
		PlanDir: filepath.Join(link, "rule-packs", "plans"), PlanGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	err = vault.WritePlan(strings.Repeat("a", 64), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("symlinked parent: %v", err)
	}
}

// A plan parent owned by another user is refused with an error (needs root
// to chown; nodes and the Linux test container run as root).
func TestForeignOwnedPlanParentIsRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another user needs root")
	}
	private, _ := newKey(t)
	root := filepath.Join(t.TempDir(), "run-cdnca")
	if err := os.MkdirAll(filepath.Join(root, "rule-packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 65534, -1); err != nil {
		t.Fatal(err)
	}
	vault, err := open(Config{PrivateKey: private, StateDir: t.TempDir(), OwnerUID: -1, OwnerGID: -1,
		PlanDir: filepath.Join(root, "rule-packs", "plans"), PlanGID: -1,
		Objects: func(string) ([]byte, error) { return nil, os.ErrNotExist }})
	if err != nil {
		t.Fatal(err)
	}
	err = vault.WritePlan(strings.Repeat("a", 64), []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
		t.Fatalf("foreign-owned parent: %v", err)
	}
}
