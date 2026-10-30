package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/drainruntime"
)

// drainProcessor runs a drain plan against the node's deployments
// (deployment.Manager, or a dynamic routing node's dynamicRoutingManager).
type drainProcessor interface {
	ProcessDrain(context.Context, deployment.DrainRequest) (deployment.DrainResult, error)
}

type formalDrainHandler struct {
	manager drainProcessor
	now     func() time.Time

	mu       sync.RWMutex
	snapshot drainRuntimeSnapshot
	closed   chan struct{}
	close    sync.Once
}

func newFormalDrainHandler(manager drainProcessor, _ time.Duration) *formalDrainHandler {
	return &formalDrainHandler{
		manager: manager, now: time.Now,
		snapshot: drainRuntimeSnapshot{Enabled: true, Ready: true}, closed: make(chan struct{}),
	}
}

func (handler *formalDrainHandler) Recover(context.Context) error {
	if handler == nil || handler.manager == nil {
		return drainruntime.ErrCorruptState
	}
	return nil
}

func (handler *formalDrainHandler) Run(ctx context.Context) error {
	if handler == nil {
		return drainruntime.ErrCorruptState
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-handler.closed:
		return errDrainRuntimeClosed
	}
}

func (handler *formalDrainHandler) HandleDrainPlan(ctx context.Context, plan drainruntime.Plan) (drainruntime.Result, error) {
	return handler.HandleDrainPlanCommand(ctx, plan, handler.now().UTC().Add(time.Duration(plan.Drain.MaxDrainSeconds)*time.Second))
}

func (handler *formalDrainHandler) HandleDrainPlanCommand(ctx context.Context, plan drainruntime.Plan, commandDeadline time.Time) (drainruntime.Result, error) {
	compiled, err := drainruntime.Compile(plan)
	if err != nil {
		return drainruntime.Result{}, err
	}
	select {
	case <-handler.closed:
		return drainruntime.Result{}, errDrainRuntimeClosed
	default:
	}
	result, processErr := handler.manager.ProcessDrain(ctx, deployment.DrainRequest{
		DeploymentID: plan.PlanID, Revision: plan.Revision, Digest: compiled.Digest,
		OldVersionID: plan.Old.VersionID, NewVersionID: plan.New.VersionID,
		MaxDrain: time.Duration(plan.Drain.MaxDrainSeconds) * time.Second, CommandDeadline: commandDeadline,
	})
	mapped, mappedErr := mapFormalDrainResult(compiled, result, processErr, handler.now().UTC())
	handler.updateSnapshot(mapped, mappedErr)
	return mapped, mappedErr
}

func mapFormalDrainResult(compiled drainruntime.CompiledPlan, result deployment.DrainResult, processErr error, now time.Time) (drainruntime.Result, error) {
	mapped := drainruntime.Result{
		PlanID: compiled.Plan.PlanID, Revision: compiled.Plan.Revision, Digest: compiled.Digest,
		HealthDeadline: result.StartedAt, DrainDeadline: result.Deadline,
		RemainingOldWorkers: result.RemainingOldWorkers,
	}
	for _, transition := range result.Transitions {
		mapped.Transitions = append(mapped.Transitions, drainruntime.Transition{
			Sequence: transition.Sequence, Phase: mapFormalDrainPhase(transition.Phase), At: transition.At,
			ErrorCode: transition.ErrorCode,
		})
	}
	mapped.Phase = mapFormalDrainPhase(result.Phase)
	if len(mapped.Transitions) == 0 {
		phase := mapped.Phase
		if phase == "" {
			phase = drainruntime.PhaseHealthGate
			mapped.Phase = phase
		}
		mapped.Transitions = []drainruntime.Transition{{Sequence: 1, Phase: phase, At: now}}
	}
	switch {
	case processErr == nil:
		return mapped, nil
	case errors.Is(processErr, deployment.ErrDrainNotReady):
		return mapped, drainruntime.ErrHealthPending
	case errors.Is(processErr, deployment.ErrDrainInProgress):
		return mapped, drainruntime.ErrDrainInProgress
	case errors.Is(processErr, deployment.ErrDrainDeadline):
		return mapped, drainruntime.ErrDrainDeadlineExceeded
	case errors.Is(processErr, deployment.ErrConflict):
		return mapped, drainruntime.ErrConflict
	case errors.Is(processErr, deployment.ErrCorruptState):
		return mapped, drainruntime.ErrCorruptState
	case mapped.Phase == drainruntime.PhaseDrainingOld:
		return mapped, drainruntime.ErrDrainObservationFailed
	default:
		return mapped, processErr
	}
}

func mapFormalDrainPhase(phase deployment.DrainPhase) drainruntime.Phase {
	switch phase {
	case deployment.DrainPhaseHealthGate:
		return drainruntime.PhaseHealthGate
	case deployment.DrainPhaseDrainingOld:
		return drainruntime.PhaseDrainingOld
	case deployment.DrainPhaseCompleted:
		return drainruntime.PhaseCompleted
	default:
		return ""
	}
}

func (handler *formalDrainHandler) updateSnapshot(result drainruntime.Result, err error) {
	snapshot := drainRuntimeSnapshot{Enabled: true, Ready: true, Phase: result.Phase}
	snapshot.Pending = result.Phase != drainruntime.PhaseCompleted && result.Phase != drainruntime.PhaseRolledBack
	if errors.Is(err, drainruntime.ErrDrainObservationFailed) {
		snapshot.Degraded = true
		snapshot.LastErrorCode = "DRAIN_OBSERVATION_FAILED"
	} else if err != nil && !errors.Is(err, drainruntime.ErrHealthPending) && !errors.Is(err, drainruntime.ErrDrainInProgress) {
		snapshot.Pending = false
		snapshot.Degraded = true
		snapshot.LastErrorCode = "DRAIN_RUNTIME_FAILED"
	}
	handler.mu.Lock()
	handler.snapshot = snapshot
	handler.mu.Unlock()
}

func (handler *formalDrainHandler) Snapshot() drainRuntimeSnapshot {
	if handler == nil {
		return drainRuntimeSnapshot{}
	}
	handler.mu.RLock()
	defer handler.mu.RUnlock()
	return handler.snapshot
}

func (handler *formalDrainHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.close.Do(func() { close(handler.closed) })
	return nil
}
