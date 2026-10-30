package drainruntime

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestStateLoadRejectsNonCanonicalAndUnknownJSON(t *testing.T) {
	manager, state := completedState(t)
	canonical, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		content []byte
	}{
		{name: "leading whitespace", content: append([]byte("\n"), canonical...)},
		{name: "unknown field", content: append(append([]byte(nil), canonical[:len(canonical)-1]...), []byte(`,"unexpected":true}`)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(manager.store.statePath, test.content, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := manager.Lookup(); !errors.Is(err, ErrCorruptState) {
				t.Fatalf("Lookup() error = %v, want ErrCorruptState", err)
			}
		})
	}
}

func TestStateValidationRejectsImpossibleAuditTimeline(t *testing.T) {
	_, baseline := completedState(t)
	for _, test := range []struct {
		name   string
		mutate func(*stateRecord)
	}{
		{name: "transition time regresses", mutate: func(state *stateRecord) {
			state.Transitions[2].At = state.Transitions[1].At.Add(-time.Second)
		}},
		{name: "intermediate transition carries terminal error", mutate: func(state *stateRecord) {
			state.Transitions[1].ErrorCode = "INJECTED"
			state.Transitions[1].Summary = "not a terminal transition"
		}},
		{name: "terminal error metadata is partial", mutate: func(state *stateRecord) {
			state.Transitions[len(state.Transitions)-1].ErrorCode = "INJECTED"
		}},
		{name: "terminal error code is unbounded", mutate: func(state *stateRecord) {
			state.Transitions[len(state.Transitions)-1].ErrorCode = strings.Repeat("A", maxIdentifierBytes+1)
			state.Transitions[len(state.Transitions)-1].Summary = "injected"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := cloneState(t, baseline)
			test.mutate(state)
			if validState(*state) {
				t.Fatal("invalid audit timeline was accepted")
			}
		})
	}
}

func TestStateValidationBindsDeadlinesToPhaseAndConfiguredBounds(t *testing.T) {
	_, baseline := completedState(t)
	healthAt := transitionAt(t, baseline, PhaseHealthGate)
	drainAt := transitionAt(t, baseline, PhaseDrainingOld)

	for _, test := range []struct {
		name   string
		mutate func(*stateRecord)
	}{
		{name: "health deadline precedes phase", mutate: func(state *stateRecord) {
			state.HealthDeadline = healthAt
		}},
		{name: "health deadline exceeds schema bound", mutate: func(state *stateRecord) {
			state.HealthDeadline = healthAt.Add((maxHealthTimeoutSeconds + 1) * time.Second)
		}},
		{name: "drain deadline precedes phase", mutate: func(state *stateRecord) {
			state.DrainDeadline = drainAt.Add(-time.Second)
		}},
		{name: "drain deadline exceeds schema bound", mutate: func(state *stateRecord) {
			state.DrainDeadline = drainAt.Add((maxDrainTimeoutSeconds + 1) * time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := cloneState(t, baseline)
			test.mutate(state)
			if validState(*state) {
				t.Fatal("invalid persisted deadline was accepted")
			}
		})
	}

	runtime := &fakeRuntime{ready: true, failActivation: true}
	manager := testManager(t, runtime, func() time.Time { return healthAt })
	if _, err := manager.Process(context.Background(), validPlan(1)); err == nil {
		t.Fatal("activation failure unexpectedly succeeded")
	}
	activationRollback, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	activationRollback.HealthDeadline = healthAt.Add(time.Second)
	if validState(*activationRollback) {
		t.Fatal("health deadline before health-gate phase was accepted")
	}
}

func TestStateValidationRejectsFalseNaturalCompletion(t *testing.T) {
	_, baseline := completedState(t)
	baseline.RemainingOldWorkers = 1
	if validState(*baseline) {
		t.Fatal("natural completion with remaining old workers was accepted")
	}
}

func TestStateValidationRejectsEarlyTerminationJournal(t *testing.T) {
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	runtime := &fakeRuntime{ready: true, remaining: 2}
	manager := testManager(t, runtime, func() time.Time { return now })
	plan := forcedPlan()
	if _, err := manager.Process(context.Background(), plan); !errors.Is(err, ErrDrainInProgress) {
		t.Fatalf("Process() error = %v", err)
	}
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	state.TerminationJournal = newTerminationJournal(state, terminationOperationForce, terminationStageForce, state.DrainDeadline.Add(-time.Second))
	if validState(*state) {
		t.Fatal("force termination journal before drain deadline was accepted")
	}

	state.TerminationJournal = newTerminationJournal(state, terminationOperationComplete, terminationStageComplete, transitionAt(t, state, PhaseDrainingOld).Add(-time.Second))
	state.RemainingOldWorkers = 0
	if validState(*state) {
		t.Fatal("completion journal before draining phase was accepted")
	}
}

func completedState(t *testing.T) (*Manager, *stateRecord) {
	t.Helper()
	now := time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)
	manager := testManager(t, &fakeRuntime{ready: true}, func() time.Time { return now })
	if result, err := manager.Process(context.Background(), validPlan(1)); err != nil || result.Phase != PhaseCompleted {
		t.Fatalf("Process() = %+v, %v", result, err)
	}
	state, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	return manager, state
}

func cloneState(t *testing.T, state *stateRecord) *stateRecord {
	t.Helper()
	content, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	var clone stateRecord
	if err := json.Unmarshal(content, &clone); err != nil {
		t.Fatal(err)
	}
	return &clone
}

func transitionAt(t *testing.T, state *stateRecord, phase Phase) time.Time {
	t.Helper()
	for _, transition := range state.Transitions {
		if transition.Phase == phase {
			return transition.At
		}
	}
	t.Fatalf("state has no %s transition", phase)
	return time.Time{}
}
