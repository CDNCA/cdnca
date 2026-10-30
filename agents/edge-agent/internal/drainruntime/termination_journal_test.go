package drainruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

type terminationRuntime struct {
	statePath    string
	ready        bool
	remaining    int
	failComplete int
	failForce    int
	calls        []string
	generation   string
}

func (r *terminationRuntime) Precheck(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "precheck")
	return nil
}

func (r *terminationRuntime) ActivateNew(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "activate")
	return nil
}

func (r *terminationRuntime) NewHealthy(context.Context, Plan, Artifacts) (bool, error) {
	r.calls = append(r.calls, "health")
	return r.ready, nil
}

func (r *terminationRuntime) BeginDrain(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "begin")
	if r.generation == "" {
		r.generation = "old-generation"
	}
	return nil
}

func (r *terminationRuntime) RemainingOldWorkers(context.Context, Plan, Artifacts) (int, error) {
	r.calls = append(r.calls, "remaining")
	return r.remaining, nil
}

func (r *terminationRuntime) Complete(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "complete")
	journal, err := r.persistedJournal()
	if err != nil {
		return err
	}
	if journal.Stage != terminationStageComplete ||
		(journal.Operation != terminationOperationComplete && journal.Operation != terminationOperationForce) {
		return fmt.Errorf("complete called without durable intent: %+v", journal)
	}
	if r.failComplete > 0 {
		r.failComplete--
		return errors.New("injected complete failure")
	}
	return nil
}

func (r *terminationRuntime) Rollback(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "rollback")
	return nil
}

func (r *terminationRuntime) ForceTerminate(context.Context, Plan, Artifacts) error {
	r.calls = append(r.calls, "force")
	journal, err := r.persistedJournal()
	if err != nil {
		return err
	}
	if journal.Operation != terminationOperationForce || journal.Stage != terminationStageForce {
		return fmt.Errorf("force called without durable intent: %+v", journal)
	}
	if r.failForce > 0 {
		r.failForce--
		return errors.New("injected force failure")
	}
	return nil
}

func (r *terminationRuntime) persistedJournal() (*terminationJournal, error) {
	content, err := os.ReadFile(r.statePath)
	if err != nil {
		return nil, err
	}
	var state stateRecord
	if err := json.Unmarshal(content, &state); err != nil {
		return nil, err
	}
	if state.TerminationJournal == nil {
		return nil, errors.New("termination journal is not durable")
	}
	return state.TerminationJournal, nil
}

func TestTerminationJournalPrecedesNormalAndForcedSideEffects(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
		runtime := &terminationRuntime{ready: true}
		manager := newTerminationManager(t, runtime, &now)
		result, err := manager.Process(context.Background(), validPlan(1))
		if err != nil || result.Phase != PhaseCompleted || result.ForcedTermination {
			t.Fatalf("Process() = %+v, %v", result, err)
		}
		assertNoTerminationJournal(t, manager)
		if countCall(runtime.calls, "complete") != 1 || countCall(runtime.calls, "force") != 0 {
			t.Fatalf("runtime calls = %v", runtime.calls)
		}
	})

	t.Run("forced", func(t *testing.T) {
		now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
		runtime := &terminationRuntime{ready: true, remaining: 2}
		manager := newTerminationManager(t, runtime, &now)
		plan := forcedPlan()
		if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
			t.Fatalf("initial Process() error = %v", err)
		}
		now = now.Add(4 * time.Second)
		result, err := manager.Process(context.Background(), plan)
		if err != nil || result.Phase != PhaseCompleted || !result.ForcedTermination {
			t.Fatalf("forced Process() = %+v, %v", result, err)
		}
		assertNoTerminationJournal(t, manager)
		if countCall(runtime.calls, "force") != 1 || countCall(runtime.calls, "complete") != 1 || countForcedTransitions(result) != 1 {
			t.Fatalf("forced runtime/result = %v, %+v", runtime.calls, result)
		}
	})
}

func TestRestartFinishesOnlyPendingTerminationStage(t *testing.T) {
	for _, test := range []struct {
		name          string
		operation     string
		stage         string
		forced        bool
		wantComplete  int
		wantForce     int
		wantForcedLog int
	}{
		{name: "normal commit", operation: terminationOperationComplete, stage: terminationStageCommit},
		{name: "force remaining workers", operation: terminationOperationForce, stage: terminationStageForce, wantComplete: 1, wantForce: 1, wantForcedLog: 1},
		{name: "force complete", operation: terminationOperationForce, stage: terminationStageComplete, forced: true, wantComplete: 1, wantForcedLog: 1},
		{name: "force commit", operation: terminationOperationForce, stage: terminationStageCommit, forced: true, wantForcedLog: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, runtime, plan, now := pendingTerminationState(t, test.operation, test.stage, test.forced)
			root := manager.store.stateDir[:len(manager.store.stateDir)-len("/state")]
			runtime.calls = nil
			runtime.statePath = manager.store.statePath
			restarted, err := newManager(root, runtime, func() time.Time { return now }, DefaultConfig())
			if err != nil {
				t.Fatal(err)
			}
			result, err := restarted.Process(context.Background(), plan)
			if err != nil || result.Phase != PhaseCompleted || result.ForcedTermination != (test.operation == terminationOperationForce) {
				t.Fatalf("recovered Process() = %+v, %v", result, err)
			}
			if countCall(runtime.calls, "begin") != 0 || countCall(runtime.calls, "remaining") != 0 ||
				countCall(runtime.calls, "complete") != test.wantComplete || countCall(runtime.calls, "force") != test.wantForce {
				t.Fatalf("recovery recaptured generation: calls = %v", runtime.calls)
			}
			if runtime.generation != "old-generation" || countForcedTransitions(result) != test.wantForcedLog {
				t.Fatalf("recovery lost worker/audit identity: generation=%q result=%+v", runtime.generation, result)
			}
			assertNoTerminationJournal(t, restarted)
		})
	}
}

func TestTerminationFailuresPreserveJournalForRetry(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
		runtime := &terminationRuntime{ready: true, failComplete: 1}
		manager := newTerminationManager(t, runtime, &now)
		plan := validPlan(1)
		result, err := manager.Process(context.Background(), plan)
		if err == nil || result.Phase != PhaseDrainingOld {
			t.Fatalf("failed completion = %+v, %v", result, err)
		}
		assertTerminationJournal(t, manager, terminationOperationComplete, terminationStageComplete)
		runtime.calls = nil
		result, err = manager.Process(context.Background(), plan)
		if err != nil || result.Phase != PhaseCompleted || countCall(runtime.calls, "complete") != 1 || countCall(runtime.calls, "begin") != 0 {
			t.Fatalf("completion retry = %+v, %v, calls=%v", result, err, runtime.calls)
		}
	})

	t.Run("force and post-force complete", func(t *testing.T) {
		now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
		runtime := &terminationRuntime{ready: true, remaining: 2, failForce: 1}
		manager := newTerminationManager(t, runtime, &now)
		plan := forcedPlan()
		if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
			t.Fatal(err)
		}
		now = now.Add(4 * time.Second)
		if result, err := manager.Process(context.Background(), plan); err == nil || result.Phase != PhaseDrainingOld || result.ForcedTermination {
			t.Fatalf("failed force = %+v, %v", result, err)
		}
		assertTerminationJournal(t, manager, terminationOperationForce, terminationStageForce)

		runtime.failComplete = 1
		runtime.calls = nil
		if result, err := manager.Process(context.Background(), plan); err == nil || result.Phase != PhaseDrainingOld || !result.ForcedTermination {
			t.Fatalf("failed post-force completion = %+v, %v", result, err)
		}
		assertTerminationJournal(t, manager, terminationOperationForce, terminationStageComplete)
		if countCall(runtime.calls, "force") != 1 || countCall(runtime.calls, "complete") != 1 {
			t.Fatalf("post-force calls = %v", runtime.calls)
		}

		runtime.calls = nil
		result, err := manager.Process(context.Background(), plan)
		if err != nil || result.Phase != PhaseCompleted || !result.ForcedTermination || countForcedTransitions(result) != 1 {
			t.Fatalf("forced retry = %+v, %v", result, err)
		}
		if countCall(runtime.calls, "force") != 0 || countCall(runtime.calls, "complete") != 1 || countCall(runtime.calls, "begin") != 0 {
			t.Fatalf("forced retry repeated wrong stage: %v", runtime.calls)
		}
	})
}

func TestInvalidTerminationJournalFailsClosedBeforeRuntime(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*stateRecord)
	}{
		{name: "corrupt schema", mutate: func(state *stateRecord) { state.TerminationJournal.SchemaVersion++ }},
		{name: "scope mismatch", mutate: func(state *stateRecord) { state.TerminationJournal.Revision++ }},
		{name: "unknown stage", mutate: func(state *stateRecord) { state.TerminationJournal.Stage = "other" }},
		{name: "rollback conflict", mutate: func(state *stateRecord) {
			state.RollbackPending = true
			state.RollbackErrorCode = "FAILED"
			state.RollbackSummary = "failed"
		}},
		{name: "non-draining pending", mutate: func(state *stateRecord) {
			state.Phase = PhaseCompleted
			state.Transitions = append(state.Transitions, Transition{Sequence: uint64(len(state.Transitions) + 1), Phase: PhaseCompleted, At: state.TerminationJournal.CreatedAt})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, runtime, plan, _ := pendingTerminationState(t, terminationOperationComplete, terminationStageComplete, false)
			state, err := manager.store.load()
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(state)
			content, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(manager.store.statePath, content, 0o600); err != nil {
				t.Fatal(err)
			}
			runtime.calls = nil
			if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Process() error = %v, want ErrCorruptState", err)
			}
			if len(runtime.calls) != 0 {
				t.Fatalf("invalid journal reached runtime: %v", runtime.calls)
			}
		})
	}
}

func TestExpiredNonForceDoesNotCreateTerminationIntent(t *testing.T) {
	now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
	runtime := &terminationRuntime{ready: true, remaining: 2}
	manager := newTerminationManager(t, runtime, &now)
	plan := validPlan(1)
	if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
		t.Fatal(err)
	}
	now = now.Add(4 * time.Second)
	runtime.calls = nil
	result, err := manager.Process(context.Background(), plan)
	if !errors.Is(err, ErrDrainDeadlineExceeded) || result.Phase != PhaseDrainingOld {
		t.Fatalf("expired non-force = %+v, %v", result, err)
	}
	if countCall(runtime.calls, "force") != 0 || countCall(runtime.calls, "complete") != 0 {
		t.Fatalf("expired non-force terminated workers: %v", runtime.calls)
	}
	assertNoTerminationJournal(t, manager)
}

func newTerminationManager(t *testing.T, runtime *terminationRuntime, now *time.Time) *Manager {
	t.Helper()
	manager, err := newManager(drainTestRoot(t), runtime, func() time.Time { return *now }, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runtime.statePath = manager.store.statePath
	return manager
}

func forcedPlan() Plan {
	plan := validPlan(1)
	plan.Drain.Force = ForceAfterDeadline
	plan.Drain.ForceReason = "operator-approved recovery"
	return plan
}

func pendingTerminationState(t *testing.T, operation, stage string, forced bool) (*Manager, *terminationRuntime, Plan, time.Time) {
	t.Helper()
	now := time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)
	runtime := &terminationRuntime{ready: true, remaining: 1}
	manager := newTerminationManager(t, runtime, &now)
	plan := validPlan(1)
	if operation == terminationOperationForce {
		plan = forcedPlan()
	}
	if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("prepare draining state error = %v", err)
	}
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if operation == terminationOperationForce && now.Before(state.DrainDeadline) {
		now = state.DrainDeadline
	}
	if operation == terminationOperationComplete {
		state.RemainingOldWorkers = 0
	}
	state.ForcedTermination = forced
	state.TerminationJournal = newTerminationJournal(state, operation, stage, now)
	if err := manager.store.save(state); err != nil {
		t.Fatalf("save pending termination: %v", err)
	}
	return manager, runtime, plan, now
}

func assertTerminationJournal(t *testing.T, manager *Manager, operation, stage string) {
	t.Helper()
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if state.TerminationJournal == nil || state.TerminationJournal.Operation != operation || state.TerminationJournal.Stage != stage {
		t.Fatalf("termination journal = %+v, want %s/%s", state.TerminationJournal, operation, stage)
	}
}

func assertNoTerminationJournal(t *testing.T, manager *Manager) {
	t.Helper()
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	if state.TerminationJournal != nil {
		t.Fatalf("termination journal was not cleared: %+v", state.TerminationJournal)
	}
}

func countCall(calls []string, want string) int {
	count := 0
	for _, call := range calls {
		if call == want {
			count++
		}
	}
	return count
}

func countForcedTransitions(result Result) int {
	count := 0
	for _, transition := range result.Transitions {
		if transition.ErrorCode == "DRAIN_FORCED" {
			count++
		}
	}
	return count
}
