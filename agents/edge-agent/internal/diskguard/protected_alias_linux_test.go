//go:build linux

package diskguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNewRejectsBindMountProtectedAliasWhenAvailable(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected")
	alias := filepath.Join(root, "protected-bind")
	for _, path := range []string{protected, alias} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cache := filepath.Join(protected, "cache")
	if err := os.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(cache, "candidate.tmp")
	writeOldFile(t, candidatePath, "candidate", time.Hour)
	if err := unix.Mount(protected, alias, "", unix.MS_BIND, ""); err != nil {
		t.Skipf("bind mounts unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(alias, 0); err != nil {
			t.Errorf("unmount bind alias: %v", err)
		}
	})
	t.Run("managed root is protected source", func(t *testing.T) {
		config := testConfig(root, cacheDirectory("cache", protected))
		config.ProtectedPaths = []string{alias}
		if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(bind alias) error = %v, want ErrInvalidConfig", err)
		}
	})
	t.Run("managed root is below protected bind alias", func(t *testing.T) {
		config := testConfig(root, cacheDirectory("cache", filepath.Join(alias, "cache")))
		config.ProtectedPaths = []string{protected}
		if _, err := New(config, Options{}); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(reverse bind alias) error = %v, want ErrInvalidConfig", err)
		}
		assertFileContent(t, candidatePath, "candidate")
	})
}
