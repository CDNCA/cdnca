package http3runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type journalRuntime struct {
	root            string
	identity        string
	activeTarget    string
	requireJournal  bool
	failActivations int
	failStops       int
	activateCalls   []string
	healthCalls     []string
	stopCalls       []string
	evidenceCalls   []string
}

func (r *journalRuntime) Precheck(context.Context, string) error { return nil }

func (r *journalRuntime) Activate(_ context.Context, path string) error {
	target := currentTarget(path)
	r.activateCalls = append(r.activateCalls, target)
	if r.requireJournal {
		if _, err := os.Stat(filepath.Join(r.root, "state", "activation-journal.json")); err != nil {
			return errors.New("activation journal was not durable before runtime activation")
		}
	}
	if r.failActivations > 0 {
		r.failActivations--
		return errInjectedRuntime
	}
	r.activeTarget = target
	return nil
}

func (r *journalRuntime) Healthy(_ context.Context, path string) error {
	r.healthCalls = append(r.healthCalls, currentTarget(path))
	return nil
}

func (r *journalRuntime) Stop(_ context.Context, path string) error {
	r.stopCalls = append(r.stopCalls, currentTarget(path))
	if r.failStops > 0 {
		r.failStops--
		return errInjectedRuntime
	}
	r.activeTarget = ""
	return nil
}

func (r *journalRuntime) ActiveEvidence(_ context.Context, path, versionID, digest string) (string, error) {
	target := currentTarget(path)
	r.evidenceCalls = append(r.evidenceCalls, target)
	if target == "" || target != r.activeTarget {
		return "", errors.New("runtime target does not match current")
	}
	return digestBytes([]byte(strings.Join([]string{r.identity, target, versionID, digest}, "\x00"))), nil
}

func TestActivationJournalIsDurableBeforeRuntimeAndClearedAfterCommit(t *testing.T) {
	runtime := &journalRuntime{identity: "kernel-process-1", requireJournal: true}
	manager, root := testManager(t, runtime)
	runtime.root = root
	if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertNoHTTP3ActivationJournal(t, manager)
	if len(runtime.evidenceCalls) != 1 {
		t.Fatalf("evidence calls = %v, want one post-health observation", runtime.evidenceCalls)
	}
}

func TestRestartCommitsOnlyHealthConfirmedCandidateWithMatchingRuntimeEvidence(t *testing.T) {
	runtime := &journalRuntime{identity: "kernel-process-1"}
	manager, root := testManager(t, runtime)
	if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
		t.Fatal(err)
	}
	previous := mustHTTP3Active(t, manager)
	candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v2")
	if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
		t.Fatal(err)
	}
	runtime.activeTarget = candidate.VersionDir
	evidence, err := runtime.ActiveEvidence(context.Background(), manager.store.currentPath, candidate.VersionID, candidate.Digest)
	if err != nil {
		t.Fatal(err)
	}
	writeHTTP3CrashJournal(t, manager, activationStageConfirmed, candidate, previous, evidence)
	runtime.activateCalls = nil
	runtime.healthCalls = nil
	runtime.evidenceCalls = nil

	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	active := mustHTTP3Active(t, restarted)
	if active.VersionID != candidate.VersionID || active.Digest != candidate.Digest {
		t.Fatalf("active = %+v, want confirmed candidate %+v", active, candidate)
	}
	if len(runtime.activateCalls) != 0 || len(runtime.evidenceCalls) != 1 || len(runtime.healthCalls) != 1 {
		t.Fatalf("recovery calls activate=%v evidence=%v health=%v", runtime.activateCalls, runtime.evidenceCalls, runtime.healthCalls)
	}
	assertNoHTTP3ActivationJournal(t, restarted)

	runtime.activateCalls = nil
	runtime.healthCalls = nil
	runtime.evidenceCalls = nil
	if _, err := newManager(root, runtime, fixedTime); err != nil {
		t.Fatalf("idempotent restart error = %v", err)
	}
	if len(runtime.activateCalls)+len(runtime.healthCalls)+len(runtime.evidenceCalls) != 0 {
		t.Fatalf("idempotent restart touched runtime: activate=%v health=%v evidence=%v", runtime.activateCalls, runtime.healthCalls, runtime.evidenceCalls)
	}
}

func TestRestartRestoresSealedLKGWhenCandidateIsUnconfirmedOrEvidenceChanged(t *testing.T) {
	for _, test := range []struct {
		name          string
		stage         string
		changeProcess bool
	}{
		{name: "before health confirmation", stage: activationStagePrepared},
		{name: "process identity changed", stage: activationStageConfirmed, changeProcess: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &journalRuntime{identity: "kernel-process-1"}
			manager, root := testManager(t, runtime)
			if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
				t.Fatal(err)
			}
			previous := mustHTTP3Active(t, manager)
			candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v2")
			if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
				t.Fatal(err)
			}
			runtime.activeTarget = candidate.VersionDir
			evidence, err := runtime.ActiveEvidence(context.Background(), manager.store.currentPath, candidate.VersionID, candidate.Digest)
			if err != nil {
				t.Fatal(err)
			}
			if test.stage == activationStagePrepared {
				evidence = ""
			}
			writeHTTP3CrashJournal(t, manager, test.stage, candidate, previous, evidence)
			if test.changeProcess {
				runtime.identity = "kernel-process-2"
			}
			runtime.activateCalls = nil
			runtime.healthCalls = nil

			restarted, err := newManager(root, runtime, fixedTime)
			if err != nil {
				t.Fatalf("newManager() error = %v", err)
			}
			active := mustHTTP3Active(t, restarted)
			if active.VersionID != previous.VersionID || active.Digest != previous.Digest {
				t.Fatalf("active = %+v, want LKG %+v", active, previous)
			}
			if len(runtime.activateCalls) != 1 || runtime.activateCalls[0] != previous.VersionDir {
				t.Fatalf("activate calls = %v, want sealed LKG %q", runtime.activateCalls, previous.VersionDir)
			}
			assertNoHTTP3ActivationJournal(t, restarted)
		})
	}
}

func TestRestartStopsUnconfirmedInitialCandidateBeforeClearingCurrent(t *testing.T) {
	runtime := &journalRuntime{identity: "kernel-process-1"}
	manager, root := testManager(t, runtime)
	candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v1")
	writeHTTP3CrashJournal(t, manager, activationStagePrepared, candidate, nil, "")
	if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
		t.Fatal(err)
	}
	runtime.activeTarget = candidate.VersionDir

	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	if len(runtime.stopCalls) != 1 || runtime.stopCalls[0] != candidate.VersionDir {
		t.Fatalf("stop calls = %v, want candidate %q", runtime.stopCalls, candidate.VersionDir)
	}
	if current, err := restarted.store.currentVersionDir(); err != nil || current != "" {
		t.Fatalf("current = %q, %v, want empty", current, err)
	}
	if active, err := restarted.store.loadActive(); err != nil || active != nil {
		t.Fatalf("active = %+v, %v, want nil", active, err)
	}
	assertNoHTTP3ActivationJournal(t, restarted)
}

func TestRestartRejectsJournalCandidateAndLKGMutationBeforeRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *Manager, activeRecord, *activeRecord)
	}{
		{
			name: "journal MAC",
			mutate: func(t *testing.T, manager *Manager, _ activeRecord, _ *activeRecord) {
				content, err := os.ReadFile(manager.store.activationJournalPath)
				if err != nil {
					t.Fatal(err)
				}
				content[len(content)-3] ^= 1
				if err := os.WriteFile(manager.store.activationJournalPath, content, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "journal symlink",
			mutate: func(t *testing.T, manager *Manager, _ activeRecord, _ *activeRecord) {
				target := filepath.Join(t.TempDir(), "journal.json")
				content, err := os.ReadFile(manager.store.activationJournalPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, content, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(manager.store.activationJournalPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, manager.store.activationJournalPath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "journal permissive mode",
			mutate: func(t *testing.T, manager *Manager, _ activeRecord, _ *activeRecord) {
				if err := os.Chmod(manager.store.activationJournalPath, 0o666); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "candidate",
			mutate: func(t *testing.T, manager *Manager, candidate activeRecord, _ *activeRecord) {
				corruptSealedHTTP3Policy(t, manager, candidate.VersionDir)
			},
		},
		{
			name: "last known good",
			mutate: func(t *testing.T, manager *Manager, _ activeRecord, previous *activeRecord) {
				corruptSealedHTTP3Policy(t, manager, previous.VersionDir)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &journalRuntime{identity: "kernel-process-1"}
			manager, root := testManager(t, runtime)
			if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
				t.Fatal(err)
			}
			previous := mustHTTP3Active(t, manager)
			candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v2")
			writeHTTP3CrashJournal(t, manager, activationStagePrepared, candidate, previous, "")
			if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, manager, candidate, previous)
			runtime.activateCalls = nil
			runtime.stopCalls = nil

			if _, err := newManager(root, runtime, fixedTime); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("newManager() error = %v, want ErrCorruptState", err)
			}
			if len(runtime.activateCalls) != 0 || len(runtime.stopCalls) != 0 {
				t.Fatalf("corrupt state reached runtime: activate=%v stop=%v", runtime.activateCalls, runtime.stopCalls)
			}
		})
	}
}

func TestRestartRejectsStaleGenerationAndRetainsFailedRecoveryJournal(t *testing.T) {
	t.Run("generation fence", func(t *testing.T) {
		runtime := &journalRuntime{identity: "kernel-process-1"}
		manager, root := testManager(t, runtime)
		if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
			t.Fatal(err)
		}
		previous := mustHTTP3Active(t, manager)
		candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v2")
		writeHTTP3CrashJournal(t, manager, activationStagePrepared, candidate, previous, "")
		newer := prepareHTTP3JournalCandidate(t, manager, "http3-v3")
		if err := manager.store.saveActive(newer); err != nil {
			t.Fatal(err)
		}
		if _, err := newManager(root, runtime, fixedTime); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("newManager() error = %v, want generation fence", err)
		}
	})

	t.Run("failed rollback is retryable", func(t *testing.T) {
		runtime := &journalRuntime{identity: "kernel-process-1"}
		manager, root := testManager(t, runtime)
		if _, err := manager.Apply(context.Background(), newManagerTLSFixture(t, "http3-v1").policy); err != nil {
			t.Fatal(err)
		}
		previous := mustHTTP3Active(t, manager)
		candidate := prepareHTTP3JournalCandidate(t, manager, "http3-v2")
		writeHTTP3CrashJournal(t, manager, activationStagePrepared, candidate, previous, "")
		if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
			t.Fatal(err)
		}
		runtime.activeTarget = candidate.VersionDir
		runtime.failActivations = 1
		if _, err := newManager(root, runtime, fixedTime); err == nil {
			t.Fatal("newManager() error = nil, want rollback failure")
		}
		assertHTTP3ActivationJournalExists(t, manager)
		if _, err := newManager(root, runtime, fixedTime); err != nil {
			t.Fatalf("retry newManager() error = %v", err)
		}
		assertNoHTTP3ActivationJournal(t, manager)
	})
}

func prepareHTTP3JournalCandidate(t *testing.T, manager *Manager, versionID string) activeRecord {
	t.Helper()
	compiled, err := Compile(newManagerTLSFixture(t, versionID).policy)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := manager.store.stage(compiled)
	if err != nil {
		t.Fatal(err)
	}
	versionDir, err := manager.store.commitStage(stage, compiled)
	if err != nil {
		t.Fatal(err)
	}
	return activeRecord{
		SchemaVersion: stateSchemaVersion,
		VersionID:     versionID,
		Digest:        compiled.Digest,
		VersionDir:    versionDir,
		AppliedAt:     fixedTime(),
	}
}

func writeHTTP3CrashJournal(t *testing.T, manager *Manager, stage string, candidate activeRecord, previous *activeRecord, evidence string) {
	t.Helper()
	if err := manager.store.saveActivationJournal(activationJournal{
		SchemaVersion: activationJournalSchemaVersion,
		Stage:         stage,
		Candidate:     candidate,
		Previous:      previous,
		Evidence:      evidence,
		CreatedAt:     fixedTime(),
	}); err != nil {
		t.Fatal(err)
	}
}

func mustHTTP3Active(t *testing.T, manager *Manager) *activeRecord {
	t.Helper()
	active, err := manager.store.loadActive()
	if err != nil || active == nil {
		t.Fatalf("loadActive() = %+v, %v", active, err)
	}
	return active
}

func corruptSealedHTTP3Policy(t *testing.T, manager *Manager, versionDir string) {
	t.Helper()
	path := filepath.Join(manager.store.versionsDir, versionDir, "policy.json")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
}

func assertHTTP3ActivationJournalExists(t *testing.T, manager *Manager) {
	t.Helper()
	if _, err := os.Stat(manager.store.activationJournalPath); err != nil {
		t.Fatalf("activation journal error = %v, want existing", err)
	}
}

func assertNoHTTP3ActivationJournal(t *testing.T, manager *Manager) {
	t.Helper()
	if _, err := os.Stat(manager.store.activationJournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation journal error = %v, want not exist", err)
	}
}

var _ Runtime = (*journalRuntime)(nil)
