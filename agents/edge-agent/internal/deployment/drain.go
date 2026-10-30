package deployment

import (
	"context"
	"fmt"
	"time"
)

func (m *Manager) ProcessDrain(ctx context.Context, request DrainRequest) (DrainResult, error) {
	if m == nil || m.generationRuntime == nil || validateID(request.DeploymentID, "drain deployment id") != nil ||
		validateID(request.OldVersionID, "drain old version id") != nil || validateID(request.NewVersionID, "drain new version id") != nil ||
		request.OldVersionID == request.NewVersionID || request.Revision == 0 || !validSHA256(request.Digest) ||
		request.MaxDrain < time.Second || request.MaxDrain > 24*time.Hour || request.CommandDeadline.IsZero() {
		return DrainResult{}, ErrInvalidCommand
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	unlock, err := m.store.lock(ctx)
	if err != nil {
		return DrainResult{}, err
	}
	defer unlock()

	value, err := m.store.loadJournal(request.DeploymentID)
	if err != nil {
		return DrainResult{}, err
	}
	if value == nil || len(value.Attempts) == 0 {
		return DrainResult{DeploymentID: request.DeploymentID, Revision: request.Revision, Digest: request.Digest, Phase: DrainPhaseHealthGate}, ErrDrainNotReady
	}
	record := &value.Attempts[len(value.Attempts)-1]
	latest := record.Transitions[len(record.Transitions)-1]
	if record.Action != ActionApply || record.ConfigVersionID != request.NewVersionID || record.PreviousVersionID != request.OldVersionID ||
		record.Phase != "" || latest.State != StateHealthy || !record.GenerationCaptured || emptyRuntimeGeneration(record.OldGeneration) {
		return DrainResult{DeploymentID: request.DeploymentID, Revision: request.Revision, Digest: request.Digest, Phase: DrainPhaseHealthGate}, ErrDrainNotReady
	}

	if record.Drain == nil {
		startedAt := m.now().UTC()
		commandDeadline := request.CommandDeadline.UTC()
		if !commandDeadline.After(startedAt) {
			return DrainResult{}, ErrDrainDeadline
		}
		deadline := startedAt.Add(request.MaxDrain)
		if commandDeadline.Before(deadline) {
			deadline = commandDeadline
		}
		record.Drain = &drainRecord{
			Revision: request.Revision, Digest: request.Digest, OldVersionID: request.OldVersionID,
			NewVersionID: request.NewVersionID, Phase: DrainPhaseDrainingOld, StartedAt: startedAt,
			Deadline: deadline, CommandDeadline: commandDeadline, RemainingOldWorkers: len(record.OldGeneration.Workers),
			Transitions: []DrainTransition{
				{Sequence: 1, Phase: DrainPhaseHealthGate, At: startedAt},
				{Sequence: 2, Phase: DrainPhaseDrainingOld, At: startedAt},
			},
		}
		if err := m.store.saveJournal(value); err != nil {
			return DrainResult{}, err
		}
	} else if record.Drain.Revision != request.Revision || record.Drain.Digest != request.Digest ||
		record.Drain.OldVersionID != request.OldVersionID || record.Drain.NewVersionID != request.NewVersionID ||
		!record.Drain.CommandDeadline.Equal(request.CommandDeadline.UTC()) {
		return DrainResult{}, fmt.Errorf("%w: drain command differs from the deployment journal", ErrConflict)
	}

	drain := record.Drain
	if drain.Phase == DrainPhaseCompleted {
		return drainResultFrom(request.DeploymentID, drain), nil
	}
	if drain.Phase == DrainPhaseFailed {
		return drainResultFrom(request.DeploymentID, drain), ErrDrainDeadline
	}
	remaining, err := m.remainingGeneration(ctx, record.OldGeneration)
	if err != nil {
		return drainResultFrom(request.DeploymentID, drain), err
	}
	drain.RemainingOldWorkers = remaining
	now := m.now().UTC()
	switch {
	case remaining == 0:
		if err := m.advanceDrain(value, drain, DrainPhaseCompleted, now, ""); err != nil {
			return DrainResult{}, err
		}
		return drainResultFrom(request.DeploymentID, drain), nil
	case !now.Before(drain.Deadline):
		if err := m.advanceDrain(value, drain, DrainPhaseFailed, now, "DRAIN_DEADLINE_EXCEEDED"); err != nil {
			return DrainResult{}, err
		}
		return drainResultFrom(request.DeploymentID, drain), ErrDrainDeadline
	default:
		if err := m.store.saveJournal(value); err != nil {
			return DrainResult{}, err
		}
		return drainResultFrom(request.DeploymentID, drain), ErrDrainInProgress
	}
}

func (m *Manager) remainingGeneration(ctx context.Context, generation RuntimeGeneration) (int, error) {
	remaining := 0
	err := runBounded(ctx, m.config.ReloadTimeout, func(operationCtx context.Context) error {
		var err error
		remaining, err = m.generationRuntime.RemainingGeneration(operationCtx, generation)
		return err
	})
	if err != nil {
		return 0, err
	}
	if remaining < 0 || remaining > len(generation.Workers) {
		return 0, ErrCorruptState
	}
	return remaining, nil
}

func (m *Manager) advanceDrain(value *journal, drain *drainRecord, phase DrainPhase, at time.Time, errorCode string) error {
	drain.Phase = phase
	drain.Transitions = append(drain.Transitions, DrainTransition{
		Sequence: uint64(len(drain.Transitions) + 1), Phase: phase, At: at.UTC(), ErrorCode: errorCode,
	})
	return m.store.saveJournal(value)
}

func drainResultFrom(deploymentID string, drain *drainRecord) DrainResult {
	return DrainResult{
		DeploymentID: deploymentID, Revision: drain.Revision, Digest: drain.Digest, Phase: drain.Phase,
		StartedAt: drain.StartedAt, Deadline: drain.Deadline, RemainingOldWorkers: drain.RemainingOldWorkers,
		Transitions: append([]DrainTransition(nil), drain.Transitions...),
	}
}
