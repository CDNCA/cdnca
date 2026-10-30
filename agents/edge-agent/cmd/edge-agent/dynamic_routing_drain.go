package main

import (
	"context"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/deployment"
)

// ProcessDrain is the drain plan of a dynamic routing node (the formal
// drain handler's processor, same contract as deployment.Manager): the plan
// names the deployment that made New current after Old. An activation
// without a reload kept the workers (only the index generation changed), so
// there is nothing old to drain; after a reload the replaced workers are
// the old generation, finishing their connections, and the plan completes
// once none is left or fails at its deadline. The record lives on the
// scope's current release, so a restart or a redelivery continues it.
func (m *dynamicRoutingManager) ProcessDrain(ctx context.Context, request deployment.DrainRequest) (deployment.DrainResult, error) {
	if request.DeploymentID == "" || request.OldVersionID == "" || request.NewVersionID == "" ||
		request.OldVersionID == request.NewVersionID || request.Revision == 0 || len(request.Digest) != 64 ||
		request.MaxDrain < time.Second || request.MaxDrain > 24*time.Hour || request.CommandDeadline.IsZero() {
		return deployment.DrainResult{}, deployment.ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return deployment.DrainResult{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	pending := deployment.DrainResult{DeploymentID: request.DeploymentID, Revision: request.Revision, Digest: request.Digest,
		Phase: deployment.DrainPhaseHealthGate}
	scopeID, scope, found, err := m.deploymentScope(request.DeploymentID)
	if err != nil {
		return deployment.DrainResult{}, err
	}
	if !found {
		return pending, deployment.ErrDrainNotReady
	}
	result, _ := scope.lastResult(request.DeploymentID)
	current := scope.Current
	if result.Action != deployment.ActionApply || result.State != deployment.StateHealthy || current == nil ||
		current.ConfigVersionID != request.NewVersionID || scope.Previous == nil || scope.Previous.ConfigVersionID != request.OldVersionID {
		return pending, deployment.ErrDrainNotReady
	}
	drain := current.Drain
	if drain == nil {
		startedAt := m.now().UTC()
		commandDeadline := request.CommandDeadline.UTC()
		if !commandDeadline.After(startedAt) {
			return deployment.DrainResult{}, deployment.ErrDrainDeadline
		}
		deadline := startedAt.Add(request.MaxDrain)
		if commandDeadline.Before(deadline) {
			deadline = commandDeadline
		}
		drain = &dynamicRoutingDrain{Revision: request.Revision, Digest: request.Digest, OldVersionID: request.OldVersionID,
			Phase: deployment.DrainPhaseDrainingOld, StartedAt: startedAt, Deadline: deadline, CommandDeadline: commandDeadline,
			Remaining: len(current.OldWorkers), Transitions: []deployment.DrainTransition{
				{Sequence: 1, Phase: deployment.DrainPhaseHealthGate, At: startedAt},
				{Sequence: 2, Phase: deployment.DrainPhaseDrainingOld, At: startedAt}}}
		current.Drain = drain
	} else if drain.Revision != request.Revision || drain.Digest != request.Digest || drain.OldVersionID != request.OldVersionID ||
		!drain.CommandDeadline.Equal(request.CommandDeadline.UTC()) {
		return deployment.DrainResult{}, fmt.Errorf("%w: drain command differs from the dynamic routing journal", deployment.ErrConflict)
	}
	var phaseErr error
	switch drain.Phase {
	case deployment.DrainPhaseCompleted:
		return drain.result(request.DeploymentID), nil
	case deployment.DrainPhaseFailed:
		return drain.result(request.DeploymentID), deployment.ErrDrainDeadline
	}
	drain.Remaining = m.remaining(current.OldWorkers)
	now := m.now().UTC()
	switch {
	case drain.Remaining == 0:
		drain.advance(deployment.DrainPhaseCompleted, now, "")
	case !now.Before(drain.Deadline):
		drain.advance(deployment.DrainPhaseFailed, now, "DRAIN_DEADLINE_EXCEEDED")
		phaseErr = deployment.ErrDrainDeadline
	default:
		phaseErr = deployment.ErrDrainInProgress
	}
	if err := m.save(scopeID, scope); err != nil {
		return deployment.DrainResult{}, err
	}
	return drain.result(request.DeploymentID), phaseErr
}

func (drain *dynamicRoutingDrain) advance(phase deployment.DrainPhase, at time.Time, code string) {
	drain.Phase = phase
	drain.Transitions = append(drain.Transitions, deployment.DrainTransition{Sequence: uint64(len(drain.Transitions) + 1),
		Phase: phase, At: at, ErrorCode: code})
}

func (drain *dynamicRoutingDrain) result(deploymentID string) deployment.DrainResult {
	return deployment.DrainResult{DeploymentID: deploymentID, Revision: drain.Revision, Digest: drain.Digest, Phase: drain.Phase,
		StartedAt: drain.StartedAt, Deadline: drain.Deadline, RemainingOldWorkers: drain.Remaining,
		Transitions: append([]deployment.DrainTransition(nil), drain.Transitions...)}
}

// deploymentScope is the scope whose journal holds deploymentID.
func (m *dynamicRoutingManager) deploymentScope(deploymentID string) (string, dynamicRoutingScope, bool, error) {
	ids, err := m.scopeIDs()
	if err != nil {
		return "", dynamicRoutingScope{}, false, err
	}
	for _, scopeID := range ids {
		scope, err := m.load(scopeID)
		if err != nil {
			return "", dynamicRoutingScope{}, false, err
		}
		if _, ok := scope.lastResult(deploymentID); ok {
			return scopeID, scope, true, nil
		}
	}
	return "", dynamicRoutingScope{}, false, nil
}

func (scope dynamicRoutingScope) lastResult(deploymentID string) (deployment.Result, bool) {
	for index := len(scope.Results) - 1; index >= 0; index-- {
		if scope.Results[index].DeploymentID == deploymentID {
			return scope.Results[index].Result, true
		}
	}
	return deployment.Result{}, false
}
