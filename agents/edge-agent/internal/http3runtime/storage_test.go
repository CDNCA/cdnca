package http3runtime

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewDiskStorePersistsPrivateQUICHostKey(t *testing.T) {
	root := filepath.Join(t.TempDir(), "http3")
	store, err := newDiskStore(root)
	if err != nil {
		t.Fatalf("newDiskStore: %v", err)
	}
	first, err := os.ReadFile(store.quicHostKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(store.quicHostKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || len(first) != quicHostKeyBytes {
		t.Fatalf("QUIC host key mode=%v size=%d", info.Mode(), len(first))
	}
	reopened, err := newDiskStore(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	second, err := os.ReadFile(reopened.quicHostKeyPath)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("reopen rotated QUIC host key: equal=%v err=%v", bytes.Equal(first, second), err)
	}
}

func TestNewDiskStoreCreatesPrivateNginxTemporaryRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "http3")
	store, err := newDiskStore(root)
	if err != nil {
		t.Fatalf("newDiskStore: %v", err)
	}
	temporaryRoot := filepath.Join(store.runDir, "nginx-temp")
	info, err := os.Lstat(temporaryRoot)
	if err != nil {
		t.Fatalf("stat nginx temporary root: %v", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("nginx temporary root mode = %v", info.Mode())
	}
}

func TestNewDiskStoreRejectsUnsafeNginxTemporaryRoot(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{name: "symlink", setup: func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(t.TempDir(), "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group-readable", setup: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Mkdir(path, 0o750); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "http3")
			if err := os.MkdirAll(filepath.Join(root, "run"), 0o700); err != nil {
				t.Fatal(err)
			}
			fixture.setup(t, filepath.Join(root, "run", "nginx-temp"))
			if _, err := newDiskStore(root); !errors.Is(err, ErrInvalidPath) {
				t.Fatalf("newDiskStore error = %v, want ErrInvalidPath", err)
			}
		})
	}
}
