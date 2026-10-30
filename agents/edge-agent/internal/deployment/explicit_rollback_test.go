package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func testRollbackCommand(deploymentID, targetVersion, baselineVersion string) Command {
	return Command{
		DeploymentID:      deploymentID,
		Attempt:           1,
		Action:            ActionRollback,
		ConfigVersionID:   targetVersion,
		PreviousVersionID: baselineVersion,
	}
}

func deployHealthyV2(t *testing.T, manager *Manager) (Command, Command) {
	t.Helper()
	v1 := deployHealthyV1(t, manager)
	v2 := testCommand(t, "deploy-v2", 1, "cfg-v2", "cfg-v1", map[string][]byte{"nginx/site.conf": []byte("v2")})
	result, err := manager.Process(context.Background(), v2)
	if err != nil || result.State != StateHealthy {
		t.Fatalf("Process(v2) = (%+v, %v)", result, err)
	}
	return v1, v2
}

func assertCurrentRelease(t *testing.T, root, digest string) {
	t.Helper()
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || target != filepath.Join("releases", digest) {
		t.Fatalf("current target = %q, error = %v, want digest %q", target, err, digest)
	}
}

func TestExplicitRollbackSucceedsAndDuplicateRestartIsIdempotent(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	v1, v2 := deployHealthyV2(t, manager)
	command := testRollbackCommand("rollback-v2-to-v1", "cfg-v1", "cfg-v2")

	first, err := manager.Process(context.Background(), command)
	if err != nil {
		t.Fatalf("Process(rollback) error = %v", err)
	}
	wantStates := []State{StateDelivered, StateStaged, StatePrechecked, StateReverting, StateReverted}
	if !reflect.DeepEqual(states(first), wantStates) || first.Action != ActionRollback {
		t.Fatalf("rollback result = %+v; states = %v", first, states(first))
	}
	pointers, err := manager.Pointers()
	wantPointers := Pointers{
		Current: "cfg-v1", CurrentDigest: v1.Bundle.ManifestSHA256,
		Previous: "cfg-v2", PreviousDigest: v2.Bundle.ManifestSHA256,
	}
	if err != nil || pointers != wantPointers {
		t.Fatalf("Pointers() = (%+v, %v), want %+v", pointers, err, wantPointers)
	}
	assertCurrentRelease(t, root, v1.Bundle.ManifestSHA256)
	if got := runtime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1", "cfg-v2", "cfg-v1"}) {
		t.Fatalf("reloads = %v", got)
	}

	duplicate, err := manager.Process(context.Background(), command)
	if err != nil || !reflect.DeepEqual(duplicate, first) {
		t.Fatalf("duplicate Process() = (%+v, %v), want %+v", duplicate, err, first)
	}
	if got := runtime.activationList(); len(got) != 3 {
		t.Fatalf("duplicate repeated reload: %v", got)
	}

	restartedRuntime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, restartedRuntime)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	afterRestart, err := restarted.Process(context.Background(), command)
	if err != nil || !reflect.DeepEqual(afterRestart, first) {
		t.Fatalf("restart duplicate = (%+v, %v), want %+v", afterRestart, err, first)
	}
	if got := restartedRuntime.activationList(); len(got) != 0 {
		t.Fatalf("restart duplicate repeated reload: %v", got)
	}
}

func TestExplicitRollbackConflictsFailClosed(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	v1, _ := deployHealthyV2(t, manager)
	command := testRollbackCommand("rollback-conflict", "cfg-v1", "cfg-v2")
	if _, err := manager.Process(context.Background(), command); err != nil {
		t.Fatalf("Process(rollback) error = %v", err)
	}
	conflict := command
	conflict.ConfigVersionID = "cfg-other"
	if _, err := manager.Process(context.Background(), conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-attempt conflict error = %v, want ErrConflict", err)
	}

	manager2, root2 := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	_, v2b := deployHealthyV2(t, manager2)
	baselineConflict := testRollbackCommand("rollback-baseline-conflict", "cfg-v1", "cfg-other")
	result, err := manager2.Process(context.Background(), baselineConflict)
	if err != nil || result.State != StateFailed || result.ErrorCode != "ROLLBACK_BASELINE_MISMATCH" || !result.RunningConfigUnchanged {
		t.Fatalf("baseline conflict = (%+v, %v)", result, err)
	}
	assertCurrentRelease(t, root2, v2b.Bundle.ManifestSHA256)
	assertCurrentRelease(t, root, v1.Bundle.ManifestSHA256)
}

func TestExplicitRollbackRejectsCommandProvidedBundle(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	v1, v2 := deployHealthyV2(t, manager)
	command := testRollbackCommand("rollback-with-bundle", "cfg-v1", "cfg-v2")
	command.Bundle = v1.Bundle
	if _, err := manager.Process(context.Background(), command); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("Process() error = %v, want ErrInvalidCommand", err)
	}
	assertCurrentRelease(t, root, v2.Bundle.ManifestSHA256)
}

func TestExplicitRollbackRejectsMissingAndCorruptTargets(t *testing.T) {
	for _, test := range []struct {
		name     string
		id       string
		corrupt  func(t *testing.T, releasePath string)
		wantCode string
	}{
		{
			name: "missing", id: "missing", wantCode: "ROLLBACK_TARGET_UNAVAILABLE",
			corrupt: func(t *testing.T, releasePath string) {
				t.Helper()
				makeTreeWritable(releasePath)
				if err := os.RemoveAll(releasePath); err != nil {
					t.Fatalf("RemoveAll(target) error = %v", err)
				}
			},
		},
		{
			name: "digest mismatch", id: "digest-mismatch", wantCode: "ROLLBACK_TARGET_INVALID",
			corrupt: func(t *testing.T, releasePath string) {
				t.Helper()
				makeTreeWritable(releasePath)
				target := filepath.Join(releasePath, "nginx", "site.conf")
				if err := os.Chmod(target, 0o600); err != nil {
					t.Fatalf("Chmod(target) error = %v", err)
				}
				if err := os.WriteFile(target, []byte("tampered"), 0o440); err != nil {
					t.Fatalf("WriteFile(target) error = %v", err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
			v1, v2 := deployHealthyV2(t, manager)
			test.corrupt(t, filepath.Join(root, "releases", v1.Bundle.ManifestSHA256))
			result, err := manager.Process(context.Background(), testRollbackCommand("rollback-target-"+test.id, "cfg-v1", "cfg-v2"))
			if err != nil || result.State != StateFailed || result.ErrorCode != test.wantCode || !result.RunningConfigUnchanged {
				t.Fatalf("Process() = (%+v, %v)", result, err)
			}
			assertCurrentRelease(t, root, v2.Bundle.ManifestSHA256)
		})
	}
}

func TestExplicitRollbackPrecheckFailureLeavesBaselineActive(t *testing.T) {
	prechecker := &fakePrechecker{failFor: map[string]error{}}
	runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	manager, root := newTestManager(t, prechecker, runtime)
	_, v2 := deployHealthyV2(t, manager)
	prechecker.mu.Lock()
	prechecker.failFor["cfg-v1"] = errors.New("secret parser output")
	prechecker.mu.Unlock()

	result, err := manager.Process(context.Background(), testRollbackCommand("rollback-precheck", "cfg-v1", "cfg-v2"))
	if err != nil || result.State != StateFailed || result.ErrorCode != "ROLLBACK_PRECHECK_FAILED" || !result.RunningConfigUnchanged {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	if result.Summary != "rollback release precheck failed" {
		t.Fatalf("summary = %q", result.Summary)
	}
	assertCurrentRelease(t, root, v2.Bundle.ManifestSHA256)
}

func TestExplicitRollbackRuntimeFailuresRestoreBaseline(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*fakeRuntime)
		wantCode  string
	}{
		{
			name: "reload",
			configure: func(runtime *fakeRuntime) {
				runtime.activationFailures["cfg-v1"] = map[int]error{2: errors.New("target reload failed")}
			},
			wantCode: "ROLLBACK_ACTIVATION_FAILED",
		},
		{
			name: "health",
			configure: func(runtime *fakeRuntime) {
				runtime.healthFailures["cfg-v1"] = errors.New("target unhealthy")
			},
			wantCode: "ROLLBACK_HEALTH_FAILED",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
			manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
			v1, v2 := deployHealthyV2(t, manager)
			test.configure(runtime)
			result, err := manager.Process(context.Background(), testRollbackCommand("rollback-runtime-"+test.name, "cfg-v1", "cfg-v2"))
			if err != nil || result.State != StateFailed || result.ErrorCode != test.wantCode || !result.RunningConfigUnchanged {
				t.Fatalf("Process() = (%+v, %v)", result, err)
			}
			pointers, err := manager.Pointers()
			wantPointers := Pointers{
				Current: "cfg-v2", CurrentDigest: v2.Bundle.ManifestSHA256,
				Previous: "cfg-v1", PreviousDigest: v1.Bundle.ManifestSHA256,
			}
			if err != nil || pointers != wantPointers {
				t.Fatalf("Pointers() = (%+v, %v), want %+v", pointers, err, wantPointers)
			}
			assertCurrentRelease(t, root, v2.Bundle.ManifestSHA256)
		})
	}
}

func TestExplicitRollbackRestoreFailureIsTerminal(t *testing.T) {
	runtime := &fakeRuntime{
		activationFailures: map[string]map[int]error{
			"cfg-v1": {2: errors.New("target reload failed")},
			"cfg-v2": {2: errors.New("baseline reload failed")},
		},
		healthFailures: map[string]error{},
	}
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, runtime)
	_, v2 := deployHealthyV2(t, manager)
	result, err := manager.Process(context.Background(), testRollbackCommand("rollback-restore-failure", "cfg-v1", "cfg-v2"))
	if err != nil || result.State != StateRollbackFailed || result.ErrorCode != "ROLLBACK_RESTORE_FAILED" || result.RunningConfigUnchanged {
		t.Fatalf("Process() = (%+v, %v)", result, err)
	}
	assertCurrentRelease(t, root, v2.Bundle.ManifestSHA256)
}

func TestExplicitRollbackRestartResumesPersistedRevertingPhase(t *testing.T) {
	manager, root := newTestManager(t, &fakePrechecker{failFor: map[string]error{}}, &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}})
	v1, _ := deployHealthyV2(t, manager)
	command := testRollbackCommand("rollback-resume", "cfg-v1", "cfg-v2")
	_, digest, err := validateAndDigest(command)
	if err != nil {
		t.Fatalf("validateAndDigest() error = %v", err)
	}
	pointers, err := manager.Pointers()
	if err != nil {
		t.Fatalf("Pointers() error = %v", err)
	}
	value := &journal{
		Version: journalVersion, DeploymentID: command.DeploymentID,
		Attempts: []attemptRecord{{
			Attempt: command.Attempt, Action: command.Action, CommandDigest: digest,
			ConfigVersionID: command.ConfigVersionID, PreviousVersionID: command.PreviousVersionID,
			ManifestSHA256: pointers.PreviousDigest, Phase: phaseExplicitRollbackVerify,
			PriorPointersSet: true, PriorPointers: pointers,
			Transitions: []Transition{
				{Sequence: 1, State: StateDelivered, At: manager.now().UTC()},
				{Sequence: 2, State: StateStaged, At: manager.now().UTC()},
				{Sequence: 3, State: StatePrechecked, At: manager.now().UTC()},
				{Sequence: 4, State: StateReverting, At: manager.now().UTC()},
			},
		}},
	}
	if err := manager.store.saveJournal(value); err != nil {
		t.Fatalf("saveJournal() error = %v", err)
	}

	restartedRuntime := &fakeRuntime{activationFailures: map[string]map[int]error{}, healthFailures: map[string]error{}}
	restarted, err := NewManager(root, &fakePrechecker{failFor: map[string]error{}}, restartedRuntime)
	if err != nil {
		t.Fatalf("NewManager(restart) error = %v", err)
	}
	result, err := restarted.Process(context.Background(), command)
	if err != nil || result.State != StateReverted {
		t.Fatalf("Process(resume) = (%+v, %v)", result, err)
	}
	assertCurrentRelease(t, root, v1.Bundle.ManifestSHA256)
	if got := restartedRuntime.activationList(); !reflect.DeepEqual(got, []string{"cfg-v1"}) {
		t.Fatalf("resume reloads = %v", got)
	}
}
