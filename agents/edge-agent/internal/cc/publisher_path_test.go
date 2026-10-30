package cc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublisherRejectsSymlinkAncestorBeforeMutation(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outsideBase, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(outsideBase, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Run("missing leaf", func(t *testing.T) {
		ancestor := filepath.Join(base, "missing-state")
		if err := os.Symlink(outside, ancestor); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(ancestor, "cc")

		publisher, err := NewPublisher(root)
		if err == nil {
			_, err = publisher.PublishJSON(policyVersion(t, 1, "/v1"))
		}
		if !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("symlink ancestor error = %v, want ErrInvalidPolicy", err)
		}
		if _, err := os.Lstat(filepath.Join(outside, "cc")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("publication mutated symlink target: %v", err)
		}
	})

	t.Run("existing root", func(t *testing.T) {
		realParent := filepath.Join(outside, "existing")
		realRoot := filepath.Join(realParent, "cc")
		if err := os.MkdirAll(realRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(realRoot, "sentinel")
		wantSentinel := []byte("unchanged\n")
		if err := os.WriteFile(sentinel, wantSentinel, 0o600); err != nil {
			t.Fatal(err)
		}
		ancestor := filepath.Join(base, "existing-state")
		if err := os.Symlink(realParent, ancestor); err != nil {
			t.Fatal(err)
		}

		publisher, err := NewPublisher(filepath.Join(ancestor, "cc"))
		if err == nil {
			_, err = publisher.PublishJSON(policyVersion(t, 1, "/v1"))
		}
		if !errors.Is(err, ErrInvalidPolicy) {
			t.Fatalf("existing root under symlink ancestor error = %v, want ErrInvalidPolicy", err)
		}
		gotSentinel, readErr := os.ReadFile(sentinel)
		if readErr != nil || string(gotSentinel) != string(wantSentinel) {
			t.Fatalf("sentinel changed: content=%q error=%v", gotSentinel, readErr)
		}
		for _, name := range []string{".publish.lock", "versions", "current.json", "fallback.json"} {
			if _, err := os.Lstat(filepath.Join(realRoot, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("publication mutated existing root at %q: %v", name, err)
			}
		}
	})
}
