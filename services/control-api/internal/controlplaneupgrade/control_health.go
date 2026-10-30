package controlplaneupgrade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

const controlStateSchema = "cdnca.control-plane-upgrade-control-state/v1"

var ErrQuorumUnavailable = errors.New("control upgrade replica quorum unavailable")

type ControlPhase string

const (
	ControlActive   ControlPhase = "active"
	ControlDraining ControlPhase = "draining"
)

type ReplicaFacts struct {
	ReplicaID string `json:"replica_id"`
	Version   string `json:"version"`
	Digest    string `json:"digest"`
}

type ReplicaObservation struct {
	ReplicaFacts
	ObservedAt int64 `json:"observed_at"`
}

type ControlReceipt struct {
	ReceiptID   string `json:"receipt_id"`
	PlanID      string `json:"plan_id"`
	Generation  uint64 `json:"generation"`
	Result      Result `json:"result"`
	Version     string `json:"version"`
	Digest      string `json:"digest"`
	Quorum      int    `json:"quorum"`
	CompletedAt int64  `json:"completed_at"`
	Replayed    bool   `json:"-"`
}

type ControlState struct {
	Schema              string                        `json:"schema"`
	Generation          uint64                        `json:"generation"`
	Phase               ControlPhase                  `json:"phase"`
	PlanID              string                        `json:"plan_id,omitempty"`
	PublicationRevision uint64                        `json:"publication_revision,omitempty"`
	ExpectedReplicas    int                           `json:"expected_replicas"`
	Quorum              int                           `json:"quorum"`
	Observations        map[string]ReplicaObservation `json:"observations"`
	Receipt             *ControlReceipt               `json:"receipt,omitempty"`
}

type ControlSnapshot struct {
	Generation          uint64               `json:"generation"`
	Phase               ControlPhase         `json:"phase"`
	PlanID              string               `json:"plan_id,omitempty"`
	PublicationRevision uint64               `json:"publication_revision,omitempty"`
	ExpectedReplicas    int                  `json:"expected_replicas"`
	Quorum              int                  `json:"quorum"`
	HealthyReplicas     int                  `json:"healthy_replicas"`
	Replicas            []ReplicaObservation `json:"replicas"`
	Receipt             *ControlReceipt      `json:"receipt,omitempty"`
}

type ControlCoordinatorConfig struct {
	ReplicaID        string
	Version          string
	Digest           string
	ExpectedReplicas int
	Quorum           int
	ObservationTTL   time.Duration
	Now              func() time.Time
}

type ControlCoordinator struct {
	config     ControlCoordinatorConfig
	repository SecretRepository
}

func NewControlCoordinator(config ControlCoordinatorConfig, repository SecretRepository) (*ControlCoordinator, error) {
	if !validMeta(config.ReplicaID, 128) || config.Version == "" || !digestPattern.MatchString(config.Digest) ||
		config.ExpectedReplicas < 1 || config.Quorum < 1 || config.Quorum > config.ExpectedReplicas ||
		config.ObservationTTL <= 0 || config.ObservationTTL > 10*time.Minute || config.Now == nil || repository == nil {
		return nil, ErrInvalidConfig
	}
	return &ControlCoordinator{config: config, repository: repository}, nil
}

func (coordinator *ControlCoordinator) Facts() ReplicaFacts {
	return ReplicaFacts{ReplicaID: coordinator.config.ReplicaID, Version: coordinator.config.Version,
		Digest: coordinator.config.Digest}
}

func (coordinator *ControlCoordinator) BeginDrain(ctx context.Context, planID string) (ControlSnapshot, error) {
	if planID == "" {
		return ControlSnapshot{}, ErrInvalidPlan
	}
	snapshot, err := coordinator.mutate(ctx, func(document *SecretDocument, state *ControlState) error {
		publication := document.Publication
		if publication == nil || publication.PlanID != planID {
			return ErrPlanConflict
		}
		if state.Phase == ControlActive && state.Receipt != nil {
			if state.Receipt.PlanID == planID {
				return nil
			}
			state.Receipt = nil
		}
		if state.Phase == ControlActive {
			state.Generation++
			state.Phase, state.PlanID, state.PublicationRevision = ControlDraining, planID, publication.PublicationRevision
			state.Observations = map[string]ReplicaObservation{}
		} else if state.PlanID != planID || state.PublicationRevision != publication.PublicationRevision {
			return ErrPlanConflict
		}
		coordinator.observe(state)
		return nil
	})
	if err == nil && snapshot.HealthyReplicas < snapshot.Quorum {
		return snapshot, ErrQuorumUnavailable
	}
	return snapshot, err
}

func (coordinator *ControlCoordinator) Observe(ctx context.Context) (ControlSnapshot, error) {
	return coordinator.mutate(ctx, func(_ *SecretDocument, state *ControlState) error {
		coordinator.observe(state)
		return nil
	})
}

func (coordinator *ControlCoordinator) Resume(ctx context.Context, planID string) (ControlReceipt, error) {
	var result ControlReceipt
	snapshot, err := coordinator.mutate(ctx, func(document *SecretDocument, state *ControlState) error {
		if state.Phase == ControlActive && state.Receipt != nil && state.Receipt.PlanID == planID {
			result = *state.Receipt
			result.Replayed = true
			return nil
		}
		if document.Publication == nil || document.Publication.PlanID != planID || state.Phase != ControlDraining ||
			state.PlanID != planID || state.PublicationRevision != document.Publication.PublicationRevision {
			return ErrPlanConflict
		}
		coordinator.observe(state)
		publication := document.Publication
		now := coordinator.config.Now().UTC()
		targetCount := coordinator.count(*state, publication.TargetVersion, publication.TargetDigest, now)
		rollbackCount := coordinator.count(*state, publication.RollbackVersion, publication.RollbackDigest, now)
		outcome, version, digest, count := Result(""), "", "", 0
		switch {
		case targetCount >= state.Quorum:
			outcome, version, digest, count = ResultApplied, publication.TargetVersion, publication.TargetDigest, targetCount
		case rollbackCount >= state.Quorum:
			outcome, version, digest, count = ResultRolledBack, publication.RollbackVersion, publication.RollbackDigest, rollbackCount
		default:
			return ErrQuorumUnavailable
		}
		result = ControlReceipt{ReceiptID: fmt.Sprintf("%s:%d:%s", planID, state.Generation, outcome),
			PlanID: planID, Generation: state.Generation, Result: outcome, Version: version, Digest: digest,
			Quorum: count, CompletedAt: now.Unix()}
		state.Phase, state.Receipt = ControlActive, &result
		return nil
	})
	if err != nil {
		return ControlReceipt{}, err
	}
	if result.ReceiptID == "" && snapshot.Receipt != nil {
		result = *snapshot.Receipt
		result.Replayed = true
	}
	return result, nil
}

func (coordinator *ControlCoordinator) Snapshot(ctx context.Context) (ControlSnapshot, error) {
	document, err := coordinator.repository.Read(ctx)
	if err != nil {
		return ControlSnapshot{}, err
	}
	state, err := coordinator.state(document.Control)
	if err != nil {
		return ControlSnapshot{}, err
	}
	return coordinator.snapshot(state, document.Publication), nil
}

func (coordinator *ControlCoordinator) mutate(ctx context.Context,
	mutation func(*SecretDocument, *ControlState) error) (ControlSnapshot, error) {
	for attempt := 0; attempt < 5; attempt++ {
		document, err := coordinator.repository.Read(ctx)
		if err != nil {
			return ControlSnapshot{}, err
		}
		state, err := coordinator.state(document.Control)
		if err != nil {
			return ControlSnapshot{}, err
		}
		if err := mutation(&document, &state); err != nil {
			return coordinator.snapshot(state, document.Publication), err
		}
		document.Control = &state
		updated, err := coordinator.repository.CompareAndSwap(ctx, document.ResourceVersion, document)
		if errors.Is(err, ErrSecretConflict) {
			continue
		}
		if err != nil {
			return ControlSnapshot{}, err
		}
		return coordinator.snapshot(*updated.Control, updated.Publication), nil
	}
	return ControlSnapshot{}, ErrSecretConflict
}

func (coordinator *ControlCoordinator) state(current *ControlState) (ControlState, error) {
	if current == nil {
		return ControlState{Schema: controlStateSchema, Phase: ControlActive,
			ExpectedReplicas: coordinator.config.ExpectedReplicas, Quorum: coordinator.config.Quorum,
			Observations: map[string]ReplicaObservation{}}, nil
	}
	state := cloneControlState(*current)
	if !validControlState(state) || state.ExpectedReplicas != coordinator.config.ExpectedReplicas ||
		state.Quorum != coordinator.config.Quorum {
		return ControlState{}, ErrSecretUnavailable
	}
	return state, nil
}

func (coordinator *ControlCoordinator) observe(state *ControlState) {
	if state.Observations == nil {
		state.Observations = map[string]ReplicaObservation{}
	}
	state.Observations[coordinator.config.ReplicaID] = ReplicaObservation{ReplicaFacts: coordinator.Facts(),
		ObservedAt: coordinator.config.Now().UTC().Unix()}
}

func (coordinator *ControlCoordinator) count(state ControlState, version, digest string, now time.Time) int {
	count := 0
	cutoff := now.Add(-coordinator.config.ObservationTTL).Unix()
	for _, observation := range state.Observations {
		if observation.ObservedAt >= cutoff && observation.ObservedAt <= now.Unix() &&
			observation.Version == version && observation.Digest == digest {
			count++
		}
	}
	return count
}

func (coordinator *ControlCoordinator) snapshot(state ControlState, publication *PublicationReceipt) ControlSnapshot {
	snapshot := ControlSnapshot{Generation: state.Generation, Phase: state.Phase, PlanID: state.PlanID,
		PublicationRevision: state.PublicationRevision, ExpectedReplicas: state.ExpectedReplicas,
		Quorum: state.Quorum, Receipt: state.Receipt}
	now := coordinator.config.Now().UTC()
	if publication != nil {
		target := coordinator.count(state, publication.TargetVersion, publication.TargetDigest, now)
		rollback := coordinator.count(state, publication.RollbackVersion, publication.RollbackDigest, now)
		if target > rollback {
			snapshot.HealthyReplicas = target
		} else {
			snapshot.HealthyReplicas = rollback
		}
	}
	for _, observation := range state.Observations {
		snapshot.Replicas = append(snapshot.Replicas, observation)
	}
	sort.Slice(snapshot.Replicas, func(left, right int) bool {
		return snapshot.Replicas[left].ReplicaID < snapshot.Replicas[right].ReplicaID
	})
	if snapshot.Replicas == nil {
		snapshot.Replicas = []ReplicaObservation{}
	}
	if state.Receipt != nil {
		receipt := *state.Receipt
		snapshot.Receipt = &receipt
	}
	return snapshot
}

func validControlState(state ControlState) bool {
	if state.Schema != controlStateSchema || state.ExpectedReplicas < 1 || state.Quorum < 1 ||
		state.Quorum > state.ExpectedReplicas || state.Observations == nil ||
		state.Phase != ControlActive && state.Phase != ControlDraining {
		return false
	}
	if state.Phase == ControlDraining && (state.Generation == 0 || state.PlanID == "" || state.PublicationRevision == 0) {
		return false
	}
	for key, observation := range state.Observations {
		if key != observation.ReplicaID || !validMeta(key, 128) || observation.Version == "" ||
			!digestPattern.MatchString(observation.Digest) || observation.ObservedAt <= 0 {
			return false
		}
	}
	if state.Receipt != nil && (state.Phase != ControlActive || state.Receipt.PlanID != state.PlanID ||
		state.Receipt.Generation != state.Generation || state.Receipt.ReceiptID == "" ||
		state.Receipt.Result != ResultApplied && state.Receipt.Result != ResultRolledBack ||
		state.Receipt.Version == "" || !digestPattern.MatchString(state.Receipt.Digest) || state.Receipt.Quorum < state.Quorum ||
		state.Receipt.CompletedAt <= 0) {
		return false
	}
	return true
}

func cloneControlState(state ControlState) ControlState {
	cloned := state
	cloned.Observations = make(map[string]ReplicaObservation, len(state.Observations))
	for key, observation := range state.Observations {
		cloned.Observations[key] = observation
	}
	if state.Receipt != nil {
		receipt := *state.Receipt
		cloned.Receipt = &receipt
	}
	return cloned
}
