package l4runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type recoveryRuntime struct {
	root            string
	requireJournal  bool
	failActivations int
	failStops       int
	activateCalls   []string
	stopCalls       []string
}

func (r *recoveryRuntime) Precheck(context.Context, string) error { return nil }

func (r *recoveryRuntime) Activate(_ context.Context, path string) error {
	r.activateCalls = append(r.activateCalls, currentTarget(path))
	if r.requireJournal {
		if _, err := os.Stat(filepath.Join(r.root, "state", "activation-journal.json")); err != nil {
			return errors.New("activation journal was not durable before runtime activation")
		}
	}
	if r.failActivations > 0 {
		r.failActivations--
		return errInjectedRuntime
	}
	return nil
}

func (r *recoveryRuntime) Stop(_ context.Context, path string) error {
	r.stopCalls = append(r.stopCalls, currentTarget(path))
	if r.failStops > 0 {
		r.failStops--
		return errInjectedRuntime
	}
	return nil
}

func TestApplyAndRollbackJournalActivationBeforeRuntime(t *testing.T) {
	runtime := &recoveryRuntime{requireJournal: true}
	manager, root := testManager(t, runtime)
	runtime.root = root
	first, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if _, err := manager.Apply(context.Background(), validConfig("l4-v2")); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if _, err := manager.Rollback(context.Background(), first.VersionID, first.Digest); err != nil {
		t.Fatalf("Rollback() error = %v", err)
	}
	if _, err := os.Stat(manager.store.activationJournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed operation journal error = %v, want not exist", err)
	}
}

func TestRestartRecoversExactLastKnownGoodFromInflightCandidate(t *testing.T) {
	manager, root := testManager(t, &fakeRuntime{})
	previousResult, err := manager.Apply(context.Background(), validConfig("l4-v1"))
	if err != nil {
		t.Fatal(err)
	}
	previous, err := manager.store.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	candidate := prepareJournalCandidate(t, manager, "l4-v2")
	writeCrashJournal(t, manager, activationOperationApply, candidate, previous)
	if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
		t.Fatal(err)
	}

	runtime := &recoveryRuntime{root: root}
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager(recovery) error = %v", err)
	}
	if len(runtime.activateCalls) != 1 || runtime.activateCalls[0] != previous.VersionDir {
		t.Fatalf("recovery activate calls = %v, want exact LKG %q", runtime.activateCalls, previous.VersionDir)
	}
	status, err := restarted.Status()
	if err != nil || status.VersionID != previousResult.VersionID || status.Digest != previousResult.Digest {
		t.Fatalf("recovered Status() = %+v, %v", status, err)
	}
	assertNoActivationJournal(t, restarted)
}

func TestRestartStopsUnconfirmedInitialActivation(t *testing.T) {
	manager, root := testManager(t, &fakeRuntime{})
	candidate := prepareJournalCandidate(t, manager, "l4-v1")
	writeCrashJournal(t, manager, activationOperationApply, candidate, nil)
	if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
		t.Fatal(err)
	}

	runtime := &recoveryRuntime{root: root}
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager(recovery) error = %v", err)
	}
	if len(runtime.stopCalls) != 1 || runtime.stopCalls[0] != candidate.VersionDir {
		t.Fatalf("recovery stop calls = %v, want candidate %q", runtime.stopCalls, candidate.VersionDir)
	}
	if current, err := restarted.store.currentVersionDir(); err != nil || current != "" {
		t.Fatalf("current after recovery = %q, %v", current, err)
	}
	assertNoActivationJournal(t, restarted)
}

func TestRestartTreatsPersistedCandidateAsCommitted(t *testing.T) {
	manager, root := testManager(t, &fakeRuntime{})
	if _, err := manager.Apply(context.Background(), validConfig("l4-v1")); err != nil {
		t.Fatal(err)
	}
	previous, err := manager.store.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Apply(context.Background(), validConfig("l4-v2")); err != nil {
		t.Fatal(err)
	}
	candidate, err := manager.store.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	writeCrashJournal(t, manager, activationOperationApply, *candidate, previous)

	runtime := &recoveryRuntime{root: root}
	restarted, err := newManager(root, runtime, fixedTime)
	if err != nil {
		t.Fatalf("newManager(commit recovery) error = %v", err)
	}
	if len(runtime.activateCalls) != 0 || len(runtime.stopCalls) != 0 {
		t.Fatalf("committed candidate invoked runtime: activate=%v stop=%v", runtime.activateCalls, runtime.stopCalls)
	}
	if current, err := restarted.store.currentVersionDir(); err != nil || current != candidate.VersionDir {
		t.Fatalf("current after commit recovery = %q, %v", current, err)
	}
	assertNoActivationJournal(t, restarted)
}

func TestRestartRejectsCorruptOrMismatchedJournalBeforeRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*activationJournal)
	}{
		{name: "unknown operation", mutate: func(j *activationJournal) { j.Operation = "other" }},
		{name: "candidate scope mismatch", mutate: func(j *activationJournal) { j.Candidate.VersionDir = "l4-other-" + j.Candidate.Digest }},
		{name: "previous equals candidate", mutate: func(j *activationJournal) { previous := j.Candidate; j.Previous = &previous }},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, root := testManager(t, &fakeRuntime{})
			candidate := prepareJournalCandidate(t, manager, "l4-v1")
			journal := activationJournal{
				SchemaVersion: activationJournalSchemaVersion,
				Operation:     activationOperationApply,
				Candidate:     candidate,
				CreatedAt:     fixedTime(),
			}
			test.mutate(&journal)
			writeRawJournal(t, manager, journal)
			runtime := &recoveryRuntime{root: root}
			if _, err := newManager(root, runtime, fixedTime); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("newManager() error = %v, want ErrCorruptState", err)
			}
			if len(runtime.activateCalls) != 0 || len(runtime.stopCalls) != 0 {
				t.Fatalf("invalid journal reached runtime: activate=%v stop=%v", runtime.activateCalls, runtime.stopCalls)
			}
		})
	}
}

func TestRecoveryFailurePreservesJournalForRetry(t *testing.T) {
	t.Run("activate LKG", func(t *testing.T) {
		manager, root := testManager(t, &fakeRuntime{})
		if _, err := manager.Apply(context.Background(), validConfig("l4-v1")); err != nil {
			t.Fatal(err)
		}
		previous, err := manager.store.loadActive()
		if err != nil {
			t.Fatal(err)
		}
		candidate := prepareJournalCandidate(t, manager, "l4-v2")
		writeCrashJournal(t, manager, activationOperationApply, candidate, previous)
		if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
			t.Fatal(err)
		}

		failedRuntime := &recoveryRuntime{root: root, failActivations: 1}
		if _, err := newManager(root, failedRuntime, fixedTime); err == nil {
			t.Fatal("newManager() error = nil, want recovery activation failure")
		}
		assertActivationJournalExists(t, manager)
		active, err := manager.store.loadActive()
		if err != nil || active.VersionDir != previous.VersionDir {
			t.Fatalf("active after failed recovery = %+v, %v", active, err)
		}

		retryRuntime := &recoveryRuntime{root: root}
		if _, err := newManager(root, retryRuntime, fixedTime); err != nil {
			t.Fatalf("retry newManager() error = %v", err)
		}
		assertNoActivationJournal(t, manager)
	})

	t.Run("stop initial candidate", func(t *testing.T) {
		manager, root := testManager(t, &fakeRuntime{})
		candidate := prepareJournalCandidate(t, manager, "l4-v1")
		writeCrashJournal(t, manager, activationOperationApply, candidate, nil)
		if err := manager.store.switchCurrent(candidate.VersionDir); err != nil {
			t.Fatal(err)
		}
		failedRuntime := &recoveryRuntime{root: root, failStops: 1}
		if _, err := newManager(root, failedRuntime, fixedTime); err == nil {
			t.Fatal("newManager() error = nil, want recovery stop failure")
		}
		assertActivationJournalExists(t, manager)
		if current, err := manager.store.currentVersionDir(); err != nil || current != candidate.VersionDir {
			t.Fatalf("candidate changed after failed stop = %q, %v", current, err)
		}
	})
}

func prepareJournalCandidate(t *testing.T, manager *Manager, versionID string) activeRecord {
	t.Helper()
	compiled, err := Compile(validConfig(versionID))
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

func writeCrashJournal(t *testing.T, manager *Manager, operation string, candidate activeRecord, previous *activeRecord) {
	t.Helper()
	journal := activationJournal{
		SchemaVersion: activationJournalSchemaVersion,
		Operation:     operation,
		Candidate:     candidate,
		Previous:      previous,
		CreatedAt:     fixedTime(),
	}
	if err := manager.store.saveActivationJournal(journal); err != nil {
		t.Fatal(err)
	}
}

func writeRawJournal(t *testing.T, manager *Manager, journal activationJournal) {
	t.Helper()
	if err := manager.store.saveActivationJournal(journal); err != nil {
		t.Fatal(err)
	}
}

func assertActivationJournalExists(t *testing.T, manager *Manager) {
	t.Helper()
	if _, err := os.Stat(manager.store.activationJournalPath); err != nil {
		t.Fatalf("activation journal error = %v, want existing", err)
	}
}

func assertNoActivationJournal(t *testing.T, manager *Manager) {
	t.Helper()
	if _, err := os.Stat(manager.store.activationJournalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activation journal error = %v, want not exist", err)
	}
}

var _ Runtime = (*recoveryRuntime)(nil)
