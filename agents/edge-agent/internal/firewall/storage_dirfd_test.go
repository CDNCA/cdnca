package firewall

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskStoreRemainsBoundAfterAncestorSwap(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configuredParent := filepath.Join(base, "configured")
	if err := os.Mkdir(configuredParent, 0o700); err != nil {
		t.Fatal(err)
	}
	configuredRoot := filepath.Join(configuredParent, "state")
	store, err := newDiskStore(configuredRoot)
	if err != nil {
		t.Fatalf("newDiskStore() error = %v", err)
	}

	boundParent := filepath.Join(base, "bound")
	if err := os.Rename(configuredParent, boundParent); err != nil {
		t.Fatal(err)
	}
	attackerParent := filepath.Join(base, "attacker")
	attackerRoot := filepath.Join(attackerParent, "state")
	for _, directory := range []string{
		attackerRoot,
		filepath.Join(attackerRoot, "versions"),
		filepath.Join(attackerRoot, "tasks"),
		filepath.Join(attackerRoot, "tmp"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(attackerParent, configuredParent); err != nil {
		t.Fatal(err)
	}

	boundRoot := filepath.Join(boundParent, "state")
	boundTemporary := filepath.Join(boundRoot, "tmp", "bound.tmp")
	attackerTemporary := filepath.Join(attackerRoot, "tmp", "attacker.tmp")
	for _, path := range []string{boundTemporary, attackerTemporary} {
		if err := os.WriteFile(path, []byte("temporary"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	unlock, err := store.lock(context.Background())
	if err != nil {
		t.Fatalf("lock() error = %v", err)
	}
	unlock()
	if err := store.saveVersion(CompiledVersion{
		Version: FirewallVersion{VersionID: "version-dirfd"},
		Digest:  "version-digest",
	}); err != nil {
		t.Fatalf("saveVersion() error = %v", err)
	}
	if err := store.saveTask("task-dirfd", "task-digest", Result{TaskID: "task-dirfd"}); err != nil {
		t.Fatalf("saveTask() error = %v", err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	if err := store.saveActive(activeRecord{
		SchemaVersion: stateSchemaVersion,
		Digest:        "active-digest",
		AppliedAt:     now,
		Version:       FirewallVersion{VersionID: "version-dirfd"},
	}); err != nil {
		t.Fatalf("saveActive() error = %v", err)
	}
	if err := store.saveInflight(inflightRecord{
		SchemaVersion: stateSchemaVersion,
		Digest:        "inflight-digest",
		StartedAt:     now,
		Command:       FirewallVersion{TaskID: "task-dirfd", VersionID: "version-dirfd"},
		Candidate: activeRecord{
			Digest:  "candidate-digest",
			Version: FirewallVersion{TaskID: "task-dirfd", VersionID: "version-dirfd"},
		},
	}); err != nil {
		t.Fatalf("saveInflight() error = %v", err)
	}
	if err := store.cleanupTemporaryFiles(); err != nil {
		t.Fatalf("cleanupTemporaryFiles() error = %v", err)
	}
	batch := []byte("table inet firewall {}")
	batchPath, err := store.writeBatch("task-dirfd", batch)
	if err != nil {
		t.Fatalf("writeBatch() error = %v", err)
	}
	batchName := filepath.Base(batchPath)
	if content, err := os.ReadFile(batchPath); err != nil || string(content) != string(batch) {
		t.Fatalf("descriptor batch content = %q, %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(boundRoot, "tmp", batchName)); err != nil {
		t.Errorf("bound batch missing: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(attackerRoot, "tmp", batchName)); !os.IsNotExist(err) {
		t.Errorf("attacker batch exists, error = %v", err)
	}
	if err := os.Remove(batchPath); err != nil {
		t.Fatalf("remove descriptor batch: %v", err)
	}

	for _, relative := range []string{
		"active.json",
		"inflight.json",
		"apply.lock",
		filepath.Join("versions", "version-dirfd.json"),
		filepath.Join("tasks", "task-dirfd.json"),
	} {
		if _, err := os.Stat(filepath.Join(boundRoot, relative)); err != nil {
			t.Errorf("bound state %q missing: %v", relative, err)
		}
		if _, err := os.Lstat(filepath.Join(attackerRoot, relative)); !os.IsNotExist(err) {
			t.Errorf("attacker state %q exists, error = %v", relative, err)
		}
	}
	if _, err := os.Stat(boundTemporary); !os.IsNotExist(err) {
		t.Errorf("bound temporary was not removed: %v", err)
	}
	if _, err := os.Stat(attackerTemporary); err != nil {
		t.Errorf("attacker temporary was touched: %v", err)
	}
	attackerInflight := filepath.Join(attackerRoot, "inflight.json")
	if err := os.WriteFile(attackerInflight, []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.clearInflight(); err != nil {
		t.Fatalf("clearInflight() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(boundRoot, "inflight.json")); !os.IsNotExist(err) {
		t.Errorf("bound inflight journal was not removed: %v", err)
	}
	if content, err := os.ReadFile(attackerInflight); err != nil || string(content) != "attacker" {
		t.Errorf("attacker inflight journal was touched: content=%q error=%v", content, err)
	}
}
