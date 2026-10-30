package certstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateRootRejectsSymlinkAndBroadPermissions(t *testing.T) {
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedRoot := filepath.Join(parent, "linked")
	if err := os.Symlink(realRoot, linkedRoot); err != nil {
		t.Fatal(err)
	}
	config := RuntimeConfig{StateRoot: linkedRoot, ListenAddress: "127.0.0.1", ListenPort: 18443}
	if _, err := NewManager(config, &fakeRuntime{}); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("symlink root error = %v", err)
	}
	if err := os.Chmod(realRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	config.StateRoot = realRoot
	if _, err := NewManager(config, &fakeRuntime{}); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("broad root error = %v", err)
	}
}

func TestRecoverRejectsHardLinksBroadModesSymlinksAndExtraFiles(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string, string)
	}{
		{name: "hard link", mutate: func(t *testing.T, root, release string) {
			certificate := filepath.Join(release, "certificates", "certificate-000.pem")
			if err := os.Link(certificate, filepath.Join(root, "leaked-certificate.pem")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "group readable", mutate: func(t *testing.T, _, release string) {
			if err := os.Chmod(filepath.Join(release, "private", "private-key-000.pem"), 0o440); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "owner writable file", mutate: func(t *testing.T, _, release string) {
			if err := os.Chmod(filepath.Join(release, "certificates", "certificate-000.pem"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "owner writable directory", mutate: func(t *testing.T, _, release string) {
			if err := os.Chmod(filepath.Join(release, "certificates"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "symlink", mutate: func(t *testing.T, root, release string) {
			privateDirectory := filepath.Join(release, "private")
			if err := os.Chmod(privateDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(privateDirectory, "private-key-000.pem")
			if err := os.Remove(key); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(root, "outside.key")
			if err := os.WriteFile(outside, []byte("not a key"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, key); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "extra file", mutate: func(t *testing.T, _, release string) {
			if err := os.Chmod(release, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(release, "extra"), []byte("unexpected"), 0o400); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := managedStateRoot(t)
			config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
			manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
				t.Fatal(err)
			}
			target, err := os.Readlink(filepath.Join(root, "current"))
			if err != nil {
				t.Fatal(err)
			}
			release := filepath.Join(root, target)
			test.mutate(t, root, release)
			restarted, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := restarted.Recover(context.Background()); !errors.Is(err, ErrUnsafeState) && !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("Recover() error = %v, want fail closed", err)
			}
		})
	}
}

func TestRecoverRejectsPointerTraversal(t *testing.T) {
	root := managedStateRoot(t)
	config := RuntimeConfig{StateRoot: root, ListenAddress: "127.0.0.1", ListenPort: 18443}
	manager, err := newManager(config, &fakeRuntime{}, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validTestBundle(t, "v1", "one.example.test")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../escape", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Recover(context.Background()); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("Recover() traversal error = %v", err)
	}
}
