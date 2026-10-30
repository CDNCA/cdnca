//go:build !windows

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/google/uuid"
)

func TestOPS06HTTPLKGStorePersistsExactBoundReplay(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	installationID := uuid.NewString()
	path := filepath.Join(root, "plan.bundle")
	store, err := NewHTTPLKGStore(path, installationID, controlplaneupgrade.SystemdControlUpgradeOperation, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrHTTPLKGNotFound) {
		t.Fatalf("empty Load() error = %v", err)
	}
	plan := ops06HTTPPlan([]byte(`{"signed":"plan"}`), 4)
	if err := store.Save(plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("LKG metadata = (%v, %#v, %v)", info, stat, err)
	}
	loaded, err := store.Load()
	if err != nil || !loaded.Replayed || !sameHTTPPlan(loaded, plan) {
		t.Fatalf("Load() = (%#v, %v)", loaded, err)
	}
	restarted, err := NewHTTPLKGStore(path, installationID, controlplaneupgrade.SystemdControlUpgradeOperation, 1024)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Load()
	if err != nil || !sameHTTPPlan(replayed, plan) {
		t.Fatalf("restart Load() = (%#v, %v)", replayed, err)
	}
	lower := ops06HTTPPlan([]byte(`{"signed":"older"}`), 3)
	if err := store.Save(lower); !errors.Is(err, ErrHTTPLKGConflict) {
		t.Fatalf("lower revision error = %v", err)
	}
	conflict := ops06HTTPPlan([]byte(`{"signed":"conflict"}`), 4)
	if err := store.Save(conflict); !errors.Is(err, ErrHTTPLKGConflict) {
		t.Fatalf("same revision conflict error = %v", err)
	}
	stillLoaded, err := store.Load()
	if err != nil || !sameHTTPPlan(stillLoaded, plan) {
		t.Fatalf("conflict changed LKG: (%#v, %v)", stillLoaded, err)
	}
}

func TestOPS06HTTPLKGStoreRejectsCorruptionLinksModesAndCrossBinding(t *testing.T) {
	newFixture := func(t *testing.T) (string, string, *HTTPLKGStore, HTTPPlan) {
		t.Helper()
		root := t.TempDir()
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
		installationID := uuid.NewString()
		path := filepath.Join(root, "plan.bundle")
		store, err := NewHTTPLKGStore(path, installationID, controlplaneupgrade.SystemdControlUpgradeOperation, 1024)
		if err != nil {
			t.Fatal(err)
		}
		plan := ops06HTTPPlan([]byte(`{"signed":"plan"}`), 1)
		if err := store.Save(plan); err != nil {
			t.Fatal(err)
		}
		return root, path, store, plan
	}

	t.Run("canonical corruption", func(t *testing.T) {
		_, path, store, _ := newFixture(t)
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var envelope httpLKGEnvelope
		if err := json.Unmarshal(encoded, &envelope); err != nil {
			t.Fatal(err)
		}
		envelope.Bundle[0] ^= 0xff
		encoded, _ = json.Marshal(envelope)
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("corruption error = %v", err)
		}
	})

	t.Run("hard link", func(t *testing.T) {
		root, path, store, _ := newFixture(t)
		if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("hard-link error = %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		root, path, store, _ := newFixture(t)
		target := filepath.Join(root, "target")
		if err := os.Rename(path, target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("symlink error = %v", err)
		}
	})

	t.Run("mode", func(t *testing.T) {
		_, path, store, _ := newFixture(t)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("mode error = %v", err)
		}
	})

	t.Run("cross installation", func(t *testing.T) {
		_, path, _, _ := newFixture(t)
		other, err := NewHTTPLKGStore(path, uuid.NewString(), controlplaneupgrade.SystemdControlUpgradeOperation, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Load(); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("cross-binding error = %v", err)
		}
	})

	t.Run("parent permissions", func(t *testing.T) {
		root := t.TempDir()
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := NewHTTPLKGStore(filepath.Join(root, "plan.bundle"), uuid.NewString(),
			controlplaneupgrade.SystemdControlUpgradeOperation, 1024); !errors.Is(err, ErrHTTPLKGInvalid) {
			t.Fatalf("parent mode error = %v", err)
		}
	})
}

func ops06HTTPPlan(bundle []byte, revision uint64) HTTPPlan {
	digest := fmt.Sprintf("%x", sha256.Sum256(bundle))
	return HTTPPlan{Bundle: append([]byte(nil), bundle...), ETag: fmt.Sprintf(`"%d:%s"`, revision, digest),
		Revision: revision, Digest: digest}
}
