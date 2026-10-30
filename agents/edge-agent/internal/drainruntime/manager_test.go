package drainruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeRuntime struct {
	mu sync.Mutex

	ready               bool
	remaining           int
	failActivation      bool
	failRollback        bool
	precheckCalls       int
	activateCalls       int
	healthCalls         int
	beginDrainCalls     int
	remainingCalls      int
	completeCalls       int
	rollbackCalls       int
	forceTerminateCalls int
}

func (r *fakeRuntime) Precheck(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.precheckCalls++
	return nil
}

func (r *fakeRuntime) ActivateNew(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.activateCalls++
	if r.failActivation {
		return errors.New("activation failed")
	}
	return nil
}

func (r *fakeRuntime) NewHealthy(context.Context, Plan, Artifacts) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.healthCalls++
	return r.ready, nil
}

func (r *fakeRuntime) BeginDrain(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.beginDrainCalls++
	return nil
}

func (r *fakeRuntime) RemainingOldWorkers(context.Context, Plan, Artifacts) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.remainingCalls++
	return r.remaining, nil
}

func (r *fakeRuntime) Complete(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completeCalls++
	return nil
}

func (r *fakeRuntime) Rollback(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rollbackCalls++
	if r.failRollback {
		return errors.New("rollback failed")
	}
	return nil
}

func (r *fakeRuntime) ForceTerminate(context.Context, Plan, Artifacts) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forceTerminateCalls++
	return nil
}

func TestManagerCompletesAndMakesTerminalRetryIdempotent(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: true}
	manager := testManager(t, runtime, func() time.Time { return now })
	plan := validPlan(1)
	result, err := manager.Process(context.Background(), plan)
	if err != nil || result.Phase != PhaseCompleted {
		t.Fatalf("Process() = %+v, %v", result, err)
	}
	wantPhases := []Phase{PhasePrecheck, PhaseActivateNew, PhaseHealthGate, PhaseDrainingOld, PhaseCompleted}
	if len(result.Transitions) != len(wantPhases) {
		t.Fatalf("transitions = %+v", result.Transitions)
	}
	for index, phase := range wantPhases {
		if result.Transitions[index].Phase != phase {
			t.Fatalf("transition %d = %s, want %s", index, result.Transitions[index].Phase, phase)
		}
	}
	if _, err := manager.Process(context.Background(), plan); err != nil {
		t.Fatalf("idempotent Process() error = %v", err)
	}
	if runtime.precheckCalls != 1 || runtime.activateCalls != 1 || runtime.completeCalls != 1 {
		t.Fatalf("terminal retry repeated runtime calls: %+v", runtime)
	}
	changed := plan
	changed.New.Listeners[0].UpstreamPort++
	if _, err := manager.Process(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("same revision changed content error = %v", err)
	}
	stale := validPlan(0)
	stale.Revision = 1
	manager2 := testManager(t, &fakeRuntime{ready: true}, func() time.Time { return now })
	if _, err := manager2.Process(context.Background(), validPlan(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager2.Process(context.Background(), stale); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale revision error = %v", err)
	}
}

func TestManagerDoesNotDrainBeforeHealthAndRollsBackAtGateDeadline(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: false}
	manager := testManager(t, runtime, func() time.Time { return now })
	result, err := manager.Process(context.Background(), validPlan(1))
	if !errors.Is(err, ErrHealthPending) || result.Phase != PhaseHealthGate {
		t.Fatalf("Process() = %+v, %v", result, err)
	}
	if runtime.beginDrainCalls != 0 || runtime.rollbackCalls != 0 {
		t.Fatalf("runtime changed old generation before health: %+v", runtime)
	}
	now = now.Add(3 * time.Second)
	result, err = manager.Process(context.Background(), validPlan(1))
	if err == nil || result.Phase != PhaseRolledBack || runtime.rollbackCalls != 1 || runtime.beginDrainCalls != 0 {
		t.Fatalf("health timeout result = %+v, error = %v, runtime = %+v", result, err, runtime)
	}
}

func TestManagerDrainDeadlineRequiresExplicitForce(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: true, remaining: 4}
	manager := testManager(t, runtime, func() time.Time { return now })
	plan := validPlan(1)
	result, err := manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrDrainInProgress) || result.Phase != PhaseDrainingOld || result.RemainingOldWorkers != 4 {
		t.Fatalf("initial drain result = %+v, %v", result, err)
	}
	now = now.Add(4 * time.Second)
	result, err = manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrDrainDeadlineExceeded) || result.Phase != PhaseDrainingOld || runtime.forceTerminateCalls != 0 {
		t.Fatalf("non-force deadline result = %+v, %v, runtime = %+v", result, err, runtime)
	}
	runtime.remaining = 0
	result, err = manager.Process(context.Background(), plan)
	if err != nil || result.Phase != PhaseCompleted || result.ForcedTermination {
		t.Fatalf("completed natural drain = %+v, %v", result, err)
	}
}

func TestManagerExplicitForceTerminatesOnlyAfterDeadline(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: true, remaining: 2}
	manager := testManager(t, runtime, func() time.Time { return now })
	plan := validPlan(1)
	plan.Drain.Force = ForceAfterDeadline
	plan.Drain.ForceReason = "operator-approved emergency migration"
	if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("initial Process() error = %v", err)
	}
	if runtime.forceTerminateCalls != 0 {
		t.Fatal("force termination ran before deadline")
	}
	now = now.Add(4 * time.Second)
	result, err := manager.Process(context.Background(), plan)
	if err != nil || result.Phase != PhaseCompleted || !result.ForcedTermination || runtime.forceTerminateCalls != 1 {
		t.Fatalf("forced result = %+v, error = %v, runtime = %+v", result, err, runtime)
	}
}

func TestManagerRecoversDrainingStateAfterManagerRestart(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: true, remaining: 1}
	root := drainTestRoot(t)
	manager, err := newManager(root, runtime, func() time.Time { return now }, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Process(context.Background(), validPlan(1)); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("first Process() error = %v", err)
	}
	runtime.remaining = 0
	restarted, err := newManager(root, runtime, func() time.Time { return now }, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.Process(context.Background(), validPlan(1))
	if err != nil || result.Phase != PhaseCompleted || runtime.precheckCalls != 1 || runtime.activateCalls != 1 {
		t.Fatalf("recovered Process() = %+v, %v, runtime = %+v", result, err, runtime)
	}
}

func TestManagerUsesOneMonotonicPhaseTimeAcrossClockRollback(t *testing.T) {
	base := time.Date(2026, time.August, 7, 13, 0, 0, 0, time.UTC)
	values := []time.Time{base, base.Add(time.Second), base.Add(-time.Second), base.Add(-2 * time.Second)}
	clockIndex := 0
	clock := func() time.Time {
		if clockIndex < len(values) {
			value := values[clockIndex]
			clockIndex++
			return value
		}
		return values[len(values)-1]
	}
	runtime := &fakeRuntime{ready: false}
	root := drainTestRoot(t)
	manager, err := newManager(root, runtime, clock, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	plan := validPlan(1)
	result, err := manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrHealthPending) || result.Phase != PhaseHealthGate {
		t.Fatalf("Process() = %+v, %v", result, err)
	}
	healthAt := transitionAt(t, mustLoadState(t, manager), PhaseHealthGate)
	if want := healthAt.Add(time.Duration(plan.HealthTimeoutSeconds) * time.Second); !result.HealthDeadline.Equal(want) {
		t.Fatalf("health deadline = %s, want phase time + timeout %s", result.HealthDeadline, want)
	}
	if runtime.activateCalls != 1 {
		t.Fatalf("activation calls = %d, want 1", runtime.activateCalls)
	}

	restarted, err := newManager(root, runtime, clock, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := restarted.Process(context.Background(), plan); !errors.Is(err, ErrHealthPending) || result.Phase != PhaseHealthGate {
		t.Fatalf("restarted Process() = %+v, %v", result, err)
	}
	if runtime.activateCalls != 1 {
		t.Fatalf("restart repeated activation: calls = %d", runtime.activateCalls)
	}
}

func TestManagerClampsTerminationJournalAndCompletionAcrossClockRollback(t *testing.T) {
	base := time.Date(2026, time.August, 7, 14, 0, 0, 0, time.UTC)
	now := base
	runtime := &fakeRuntime{ready: true, remaining: 2}
	manager := testManager(t, runtime, func() time.Time { return now })
	plan := forcedPlan()
	if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("initial Process() error = %v", err)
	}
	state := mustLoadState(t, manager)
	deadline := state.DrainDeadline

	clockCalls := 0
	manager.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return deadline.Add(time.Second)
		}
		return base.Add(-time.Hour)
	}
	result, err := manager.Process(context.Background(), plan)
	if err != nil || result.Phase != PhaseCompleted || !result.ForcedTermination {
		t.Fatalf("forced Process() = %+v, %v", result, err)
	}
	completedAt := result.Transitions[len(result.Transitions)-1].At
	if completedAt.Before(deadline) {
		t.Fatalf("completed transition %s precedes force deadline %s", completedAt, deadline)
	}
}

func mustLoadState(t *testing.T, manager *Manager) *stateRecord {
	t.Helper()
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestManagerSerializesConcurrentIdempotentRetries(t *testing.T) {
	runtime := &fakeRuntime{ready: true}
	manager := testManager(t, runtime, time.Now)
	plan := validPlan(1)
	const workers = 16
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := manager.Process(context.Background(), plan)
			if err != nil {
				errorsFound <- err
				return
			}
			if result.Phase != PhaseCompleted {
				errorsFound <- errors.New("concurrent result was not completed")
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Errorf("concurrent Process() error = %v", err)
	}
	if runtime.precheckCalls != 1 || runtime.activateCalls != 1 || runtime.beginDrainCalls != 1 || runtime.completeCalls != 1 {
		t.Fatalf("runtime calls were not idempotent: %+v", runtime)
	}
}

func TestManagerActivationFailureRollsBackWithoutDraining(t *testing.T) {
	runtime := &fakeRuntime{ready: true, failActivation: true}
	manager := testManager(t, runtime, time.Now)
	result, err := manager.Process(context.Background(), validPlan(1))
	if err == nil || result.Phase != PhaseRolledBack || runtime.rollbackCalls != 1 || runtime.beginDrainCalls != 0 {
		t.Fatalf("activation failure = %+v, %v, runtime = %+v", result, err, runtime)
	}
}

func TestManagerPersistsRollbackIntentAndDoesNotResumeForwardPath(t *testing.T) {
	now := time.Date(2026, time.July, 22, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: false, failRollback: true}
	root := drainTestRoot(t)
	manager, err := newManager(root, runtime, func() time.Time { return now }, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	plan := validPlan(1)
	result, err := manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrHealthPending) || result.Phase != PhaseHealthGate {
		t.Fatalf("initial health result = %+v, %v", result, err)
	}
	now = now.Add(3 * time.Second)
	result, err = manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrRollbackFailed) || !result.RollbackPending || result.Phase != PhaseHealthGate {
		t.Fatalf("failed rollback result = %+v, %v", result, err)
	}
	healthCalls := runtime.healthCalls
	runtime.ready = true
	runtime.failRollback = false
	restarted, err := newManager(root, runtime, func() time.Time { return now }, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err = restarted.Process(context.Background(), plan)
	if err == nil || result.Phase != PhaseRolledBack || result.RollbackPending || runtime.healthCalls != healthCalls {
		t.Fatalf("recovered rollback result = %+v, %v, runtime = %+v", result, err, runtime)
	}
}

func TestManagerRejectsCorruptTransitionAndSymlinkState(t *testing.T) {
	t.Run("transition", func(t *testing.T) {
		runtime := &fakeRuntime{ready: false}
		manager := testManager(t, runtime, time.Now)
		if _, err := manager.Process(context.Background(), validPlan(1)); !errors.Is(err, ErrHealthPending) {
			t.Fatalf("Process() error = %v", err)
		}
		state, err := manager.store.load()
		if err != nil {
			t.Fatal(err)
		}
		state.Transitions[1].Phase = PhaseDrainingOld
		content, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manager.store.statePath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := manager.Lookup(); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("Lookup() error = %v, want ErrCorruptState", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		manager := testManager(t, &fakeRuntime{ready: true}, time.Now)
		if _, err := manager.Process(context.Background(), validPlan(1)); err != nil {
			t.Fatal(err)
		}
		backing := manager.store.statePath + ".backing"
		if err := os.Rename(manager.store.statePath, backing); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(backing, manager.store.statePath); err != nil {
			t.Fatal(err)
		}
		if _, _, err := manager.Lookup(); !errors.Is(err, ErrCorruptState) {
			t.Fatalf("Lookup() error = %v, want ErrCorruptState", err)
		}
	})
}

func testManager(t *testing.T, runtime Runtime, now func() time.Time) *Manager {
	t.Helper()
	manager, err := newManager(drainTestRoot(t), runtime, now, DefaultConfig())
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	return manager
}

func drainTestRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "drain")
	t.Cleanup(func() {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err == nil {
				if info.IsDir() {
					_ = os.Chmod(path, 0o700)
				} else {
					_ = os.Chmod(path, 0o600)
				}
			}
			return nil
		})
	})
	return root
}
