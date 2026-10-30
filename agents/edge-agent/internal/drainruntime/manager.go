package drainruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Runtime interface {
	Precheck(context.Context, Plan, Artifacts) error
	ActivateNew(context.Context, Plan, Artifacts) error
	NewHealthy(context.Context, Plan, Artifacts) (bool, error)
	BeginDrain(context.Context, Plan, Artifacts) error
	RemainingOldWorkers(context.Context, Plan, Artifacts) (int, error)
	Complete(context.Context, Plan, Artifacts) error
	Rollback(context.Context, Plan, Artifacts) error
	ForceTerminate(context.Context, Plan, Artifacts) error
}

type Config struct {
	OperationTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{OperationTimeout: 15 * time.Second}
}

type Manager struct {
	mu      sync.Mutex
	store   *diskStore
	runtime Runtime
	now     func() time.Time
	config  Config
}

func NewManager(stateRoot string, runtime Runtime) (*Manager, error) {
	return newManager(stateRoot, runtime, time.Now, DefaultConfig())
}

func newManager(stateRoot string, runtime Runtime, now func() time.Time, config Config) (*Manager, error) {
	if runtime == nil || now == nil || config.OperationTimeout <= 0 || config.OperationTimeout > time.Minute {
		return nil, ErrInvalidPlan
	}
	store, err := newDiskStore(stateRoot)
	if err != nil {
		return nil, err
	}
	return &Manager{store: store, runtime: runtime, now: now, config: config}, nil
}

func (m *Manager) Process(ctx context.Context, plan Plan) (Result, error) {
	compiled, err := Compile(plan)
	if err != nil {
		return Result{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	state, err := m.store.load()
	if err != nil {
		return Result{}, err
	}
	terminalRetry := false
	if state != nil {
		switch {
		case compiled.Plan.Revision < state.Revision:
			return Result{}, ErrStaleRevision
		case compiled.Plan.Revision == state.Revision && (compiled.Plan.PlanID != state.PlanID || compiled.Digest != state.Digest):
			return Result{}, ErrConflict
		case compiled.Plan.Revision > state.Revision && state.Phase != PhaseCompleted && state.Phase != PhaseRolledBack:
			return Result{}, fmt.Errorf("%w: revision %d is still %s", ErrConflict, state.Revision, state.Phase)
		case compiled.Plan.Revision == state.Revision && (state.Phase == PhaseCompleted || state.Phase == PhaseRolledBack):
			terminalRetry = true
		}
	}
	artifacts, err := m.store.stage(compiled)
	if err != nil {
		return Result{}, err
	}
	if terminalRetry {
		return resultFrom(state), nil
	}
	if state == nil || compiled.Plan.Revision > state.Revision {
		state = &stateRecord{
			SchemaVersion: stateSchemaVersion, PlanID: compiled.Plan.PlanID, Revision: compiled.Plan.Revision,
			Digest: compiled.Digest, Phase: PhasePrecheck,
			Transitions: []Transition{{Sequence: 1, Phase: PhasePrecheck, At: m.now().UTC()}},
		}
		if err := m.store.save(state); err != nil {
			return Result{}, err
		}
	}
	return m.run(ctx, compiled.Plan, artifacts, state)
}

func (m *Manager) Lookup() (Result, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, err := m.store.load()
	if err != nil {
		return Result{}, false, err
	}
	if state == nil {
		return Result{}, false, nil
	}
	return resultFrom(state), true, nil
}

func (m *Manager) run(ctx context.Context, plan Plan, artifacts Artifacts, state *stateRecord) (Result, error) {
	for {
		if state.TerminationJournal != nil {
			return m.finishPendingTermination(ctx, state, plan, artifacts)
		}
		if state.RollbackPending {
			return m.finishPendingRollback(state, plan, artifacts, nil)
		}
		switch state.Phase {
		case PhasePrecheck:
			if err := m.operation(ctx, func(operationCtx context.Context) error {
				return m.runtime.Precheck(operationCtx, plan, artifacts)
			}); err != nil {
				return m.rolledBack(state, "PRECHECK_FAILED", "candidate fixture precheck failed", err)
			}
			if err := m.advance(state, PhaseActivateNew, "", ""); err != nil {
				return Result{}, err
			}
		case PhaseActivateNew:
			if err := m.operation(ctx, func(operationCtx context.Context) error {
				return m.runtime.ActivateNew(operationCtx, plan, artifacts)
			}); err != nil {
				return m.rollbackAfterMutation(state, plan, artifacts, "ACTIVATION_FAILED", "new version activation failed", err)
			}
			phaseAt := m.nextStateTime(state)
			state.HealthDeadline = phaseAt.Add(time.Duration(plan.HealthTimeoutSeconds) * time.Second)
			if err := m.advanceAt(state, PhaseHealthGate, phaseAt, "", ""); err != nil {
				return Result{}, err
			}
		case PhaseHealthGate:
			if !m.now().UTC().Before(state.HealthDeadline) {
				return m.rollbackAfterMutation(state, plan, artifacts, "HEALTH_GATE_TIMEOUT", "new version did not become healthy before its deadline", ErrHealthPending)
			}
			ready, healthErr := m.health(ctx, plan, artifacts)
			if healthErr != nil {
				return m.rollbackAfterMutation(state, plan, artifacts, "HEALTH_GATE_FAILED", "new version health check failed", healthErr)
			}
			if !ready || !m.now().UTC().Before(state.HealthDeadline) {
				if m.now().UTC().Before(state.HealthDeadline) {
					return resultFrom(state), ErrHealthPending
				}
				return m.rollbackAfterMutation(state, plan, artifacts, "HEALTH_GATE_TIMEOUT", "new version did not become healthy before its deadline", ErrHealthPending)
			}
			phaseAt := m.nextStateTime(state)
			state.DrainDeadline = phaseAt.Add(time.Duration(plan.Drain.MaxDrainSeconds) * time.Second)
			if err := m.advanceAt(state, PhaseDrainingOld, phaseAt, "", ""); err != nil {
				return Result{}, err
			}
		case PhaseDrainingOld:
			if err := m.operation(ctx, func(operationCtx context.Context) error {
				return m.runtime.BeginDrain(operationCtx, plan, artifacts)
			}); err != nil {
				return m.rollbackAfterMutation(state, plan, artifacts, "DRAIN_ACTIVATION_FAILED", "old listener drain activation failed", err)
			}
			remaining, err := m.remaining(ctx, plan, artifacts)
			if err != nil {
				return resultFrom(state), err
			}
			state.RemainingOldWorkers = remaining
			if err := m.store.save(state); err != nil {
				return Result{}, err
			}
			if remaining == 0 {
				state.TerminationJournal = newTerminationJournal(state, terminationOperationComplete, terminationStageComplete, m.nextStateTime(state))
				if err := m.store.save(state); err != nil {
					return Result{}, err
				}
				return m.finishPendingTermination(ctx, state, plan, artifacts)
			}
			if m.now().UTC().Before(state.DrainDeadline) {
				return resultFrom(state), ErrDrainInProgress
			}
			if plan.Drain.Force != ForceAfterDeadline {
				return resultFrom(state), ErrDrainDeadlineExceeded
			}
			state.TerminationJournal = newTerminationJournal(state, terminationOperationForce, terminationStageForce, m.nextStateTime(state, state.DrainDeadline))
			if err := m.store.save(state); err != nil {
				return Result{}, err
			}
			return m.finishPendingTermination(ctx, state, plan, artifacts)
		case PhaseCompleted, PhaseRolledBack:
			return resultFrom(state), nil
		default:
			return Result{}, ErrCorruptState
		}
	}
}

func (m *Manager) finishPendingTermination(ctx context.Context, state *stateRecord, plan Plan, artifacts Artifacts) (Result, error) {
	journal := state.TerminationJournal
	if journal == nil {
		return Result{}, ErrCorruptState
	}
	if journal.Operation == terminationOperationForce && journal.Stage == terminationStageForce {
		if err := m.operation(ctx, func(operationCtx context.Context) error {
			return m.runtime.ForceTerminate(operationCtx, plan, artifacts)
		}); err != nil {
			return resultFrom(state), err
		}
		state.ForcedTermination = true
		journal.Stage = terminationStageComplete
		if err := m.store.save(state); err != nil {
			return Result{}, err
		}
	}
	if journal.Stage == terminationStageComplete {
		if err := m.operation(ctx, func(operationCtx context.Context) error {
			return m.runtime.Complete(operationCtx, plan, artifacts)
		}); err != nil {
			return resultFrom(state), err
		}
		journal.Stage = terminationStageCommit
		if err := m.store.save(state); err != nil {
			return Result{}, err
		}
	}
	if journal.Stage != terminationStageCommit {
		return Result{}, ErrCorruptState
	}
	code, summary := "", ""
	if journal.Operation == terminationOperationForce {
		code = "DRAIN_FORCED"
		summary = "old connections were explicitly terminated after the drain deadline"
	}
	completedAt := m.nextStateTime(state, journal.CreatedAt)
	state.TerminationJournal = nil
	if err := m.advanceAt(state, PhaseCompleted, completedAt, code, summary); err != nil {
		return Result{}, err
	}
	return resultFrom(state), nil
}

func (m *Manager) health(ctx context.Context, plan Plan, artifacts Artifacts) (bool, error) {
	var ready bool
	err := m.operation(ctx, func(operationCtx context.Context) error {
		var err error
		ready, err = m.runtime.NewHealthy(operationCtx, plan, artifacts)
		return err
	})
	return ready, err
}

func (m *Manager) remaining(ctx context.Context, plan Plan, artifacts Artifacts) (int, error) {
	remaining := 0
	err := m.operation(ctx, func(operationCtx context.Context) error {
		var err error
		remaining, err = m.runtime.RemainingOldWorkers(operationCtx, plan, artifacts)
		return err
	})
	if err == nil && remaining < 0 {
		return 0, ErrCorruptState
	}
	return remaining, err
}

func (m *Manager) operation(parent context.Context, operation func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(parent, m.config.OperationTimeout)
	defer cancel()
	return operation(ctx)
}

func (m *Manager) rollbackAfterMutation(state *stateRecord, plan Plan, artifacts Artifacts, code, summary string, cause error) (Result, error) {
	state.RollbackPending = true
	state.RollbackErrorCode = code
	state.RollbackSummary = summary
	if err := m.store.save(state); err != nil {
		return Result{}, err
	}
	return m.finishPendingRollback(state, plan, artifacts, cause)
}

func (m *Manager) finishPendingRollback(state *stateRecord, plan Plan, artifacts Artifacts, cause error) (Result, error) {
	code := state.RollbackErrorCode
	summary := state.RollbackSummary
	ctx, cancel := context.WithTimeout(context.Background(), m.config.OperationTimeout)
	defer cancel()
	if err := m.runtime.Rollback(ctx, plan, artifacts); err != nil {
		return resultFrom(state), fmt.Errorf("%w: %s: %v; rollback: %v", ErrRollbackFailed, code, cause, err)
	}
	state.RollbackPending = false
	state.RollbackErrorCode = ""
	state.RollbackSummary = ""
	if cause == nil {
		cause = errors.New("pending rollback recovered")
	}
	return m.rolledBack(state, code, summary, cause)
}

func (m *Manager) rolledBack(state *stateRecord, code, summary string, cause error) (Result, error) {
	if err := m.advance(state, PhaseRolledBack, code, summary); err != nil {
		return Result{}, err
	}
	return resultFrom(state), fmt.Errorf("%s: %w", code, cause)
}

func (m *Manager) advance(state *stateRecord, phase Phase, code, summary string) error {
	return m.advanceAt(state, phase, m.nextStateTime(state), code, summary)
}

func (m *Manager) advanceAt(state *stateRecord, phase Phase, at time.Time, code, summary string) error {
	state.Phase = phase
	state.Transitions = append(state.Transitions, Transition{
		Sequence: uint64(len(state.Transitions) + 1), Phase: phase, At: at, ErrorCode: code, Summary: summary,
	})
	return m.store.save(state)
}

func (m *Manager) nextStateTime(state *stateRecord, minimum ...time.Time) time.Time {
	at := m.now().UTC()
	if len(state.Transitions) > 0 && at.Before(state.Transitions[len(state.Transitions)-1].At) {
		at = state.Transitions[len(state.Transitions)-1].At
	}
	for _, candidate := range minimum {
		candidate = candidate.UTC()
		if at.Before(candidate) {
			at = candidate
		}
	}
	return at
}

func resultFrom(state *stateRecord) Result {
	transitions := append([]Transition(nil), state.Transitions...)
	return Result{
		PlanID: state.PlanID, Revision: state.Revision, Digest: state.Digest, Phase: state.Phase,
		HealthDeadline: state.HealthDeadline, DrainDeadline: state.DrainDeadline,
		RemainingOldWorkers: state.RemainingOldWorkers, ForcedTermination: state.ForcedTermination,
		RollbackPending: state.RollbackPending, Transitions: transitions,
	}
}
