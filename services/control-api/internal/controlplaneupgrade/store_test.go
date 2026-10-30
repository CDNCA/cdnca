package controlplaneupgrade

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStorePersistsCanonicalStateAtomicallyAndRejectsCorruption(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	state := State{Schema: StateSchema, PlanID: "00000000-0000-4000-8000-000000000001",
		BundleSHA256: digestBytes([]byte("bundle")), Sequence: 9, Phase: PhaseActivated,
		PreviousDigest: digestBytes([]byte("old")), TargetDigest: digestBytes([]byte("new"))}
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded != state {
		t.Fatalf("Load() = (%#v, %v), want %#v", loaded, err, state)
	}
	info, err := os.Stat(filepath.Join(root, stateFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = (%v, %v)", info, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(root, ".state-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
	if err := os.WriteFile(filepath.Join(root, stateFilename), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCorruptState) {
		t.Fatalf("corrupt state error = %v", err)
	}
}
