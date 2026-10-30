package nodeisolation

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
)

const maxPublicationNodes = 4096

var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

type Service struct {
	repository Repository
	policy     Policy
	clock      func() time.Time
}

func NewIsolationService(repository Repository, policy Policy, clock func() time.Time) (*Service, error) {
	if repository == nil || clock == nil || !validPolicy(policy) {
		return nil, ErrInvalidInput
	}
	return &Service{repository: repository, policy: policy, clock: clock}, nil
}

func (service *Service) RecordSyncResult(ctx context.Context, value SyncResult) (Result, error) {
	if ctx == nil || !validSyncResult(value) {
		return failClosedResult(value, ReasonOutcomeUncertain), ErrInvalidInput
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return failClosedResult(value, ReasonOutcomeUncertain), ErrInvalidInput
	}
	normalized := normalizeSyncResult(value)
	digest, err := syncResultDigest(normalized)
	if err != nil {
		return failClosedResult(value, ReasonOutcomeUncertain), ErrInvalidInput
	}
	result, err := service.repository.Apply(ctx, ApplyCommand{Result: normalized, Policy: service.policy, Now: now, Digest: digest})
	if err != nil {
		failClosed := failClosedResult(value, ReasonOutcomeUncertain)
		switch {
		case errors.Is(err, ErrConflict):
			return failClosed, ErrConflict
		case errors.Is(err, ErrNotFound):
			return failClosed, ErrNotFound
		}
		return failClosed, fmt.Errorf("%w: persist sync result", ErrOutcomeUncertain)
	}
	if result.State.ScopeID != value.ScopeID || result.State.NodeID != value.NodeID ||
		result.State.Status != StatusActive && result.State.Status != StatusIsolated {
		return failClosedResult(value, ReasonOutcomeUncertain), fmt.Errorf("%w: invalid persisted state", ErrOutcomeUncertain)
	}
	result.PublicationAllowed = result.State.Status == StatusActive
	result.ReasonCode = result.State.ReasonCode
	return result, nil
}

func (service *Service) PlanPublication(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) (PublicationPlan, error) {
	if ctx == nil || scopeID == uuid.Nil || len(nodeIDs) == 0 || len(nodeIDs) > maxPublicationNodes || !validNodeIDs(nodeIDs) {
		return PublicationPlan{}, ErrInvalidInput
	}
	states, err := service.repository.List(ctx, scopeID, slices.Clone(nodeIDs))
	if err != nil {
		return blockedPlan(nodeIDs, ReasonOutcomeUncertain), fmt.Errorf("%w: read isolation state", ErrOutcomeUncertain)
	}
	plan := PublicationPlan{Decisions: make([]PublicationDecision, 0, len(nodeIDs))}
	for _, nodeID := range nodeIDs {
		state, exists := states[nodeID]
		if !exists {
			plan.EligibleNodeIDs = append(plan.EligibleNodeIDs, nodeID)
			plan.Decisions = append(plan.Decisions, PublicationDecision{NodeID: nodeID, Allowed: true, Status: StatusActive, ReasonCode: ReasonHealthy})
			continue
		}
		if state.ScopeID != scopeID || state.NodeID != nodeID || state.Status != StatusActive && state.Status != StatusIsolated {
			return blockedPlan(nodeIDs, ReasonOutcomeUncertain), fmt.Errorf("%w: invalid isolation state", ErrOutcomeUncertain)
		}
		allowed := state.Status == StatusActive
		plan.Decisions = append(plan.Decisions, PublicationDecision{NodeID: nodeID, Allowed: allowed, Status: state.Status, ReasonCode: state.ReasonCode})
		if allowed {
			plan.EligibleNodeIDs = append(plan.EligibleNodeIDs, nodeID)
		} else {
			plan.IsolatedNodeIDs = append(plan.IsolatedNodeIDs, nodeID)
		}
	}
	return plan, nil
}

func (service *Service) ListIsolationStates(ctx context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) ([]State, error) {
	if ctx == nil || scopeID == uuid.Nil || len(nodeIDs) > maxPublicationNodes || !validNodeIDs(nodeIDs) {
		return nil, ErrInvalidInput
	}
	states, err := service.repository.List(ctx, scopeID, slices.Clone(nodeIDs))
	if err != nil {
		return nil, fmt.Errorf("%w: read isolation state", ErrOutcomeUncertain)
	}
	result := make([]State, 0, len(states))
	if len(nodeIDs) == 0 {
		for _, state := range states {
			if state.ScopeID != scopeID || state.NodeID == uuid.Nil || state.Status != StatusActive && state.Status != StatusIsolated {
				return nil, fmt.Errorf("%w: invalid isolation state", ErrOutcomeUncertain)
			}
			result = append(result, state)
		}
		slices.SortFunc(result, func(left, right State) int {
			return cmp.Compare(left.NodeID.String(), right.NodeID.String())
		})
		return result, nil
	}
	for _, nodeID := range nodeIDs {
		state, ok := states[nodeID]
		if !ok {
			continue
		}
		if state.ScopeID != scopeID || state.NodeID != nodeID || state.Status != StatusActive && state.Status != StatusIsolated {
			return nil, fmt.Errorf("%w: invalid isolation state", ErrOutcomeUncertain)
		}
		result = append(result, state)
	}
	return result, nil
}

func evolveIsolationState(previous State, command ApplyCommand) ApplyResult {
	value, now := command.Result, command.Now
	state := previous
	wasIsolated := state.Status == StatusIsolated
	if state.ScopeID == uuid.Nil {
		state.ScopeID = value.ScopeID
		state.NodeID = value.NodeID
		state.Status = StatusActive
		state.ReasonCode = ReasonHealthy
	}
	desiredChanged := state.Desired != value.Desired
	if desiredChanged {
		state.Desired = value.Desired
		state.ConsecutiveFailures = 0
		state.ConsecutiveHealthy = 0
	}
	state.Revision++
	state.LastReportID = value.ReportID
	state.LastOutcome = value.Outcome
	state.LastErrorCode = value.ErrorCode
	state.UpdatedAt = now
	effects := []Effect{{Kind: EffectAudit, Code: AuditSyncResultRecorded, DedupeKey: reportDedupeKey(value.ReportID)}}

	switch value.Outcome {
	case OutcomeFailed:
		state.ConsecutiveHealthy = 0
		if state.ConsecutiveFailures < command.Policy.FailureThreshold {
			state.ConsecutiveFailures++
		}
		if state.Status == StatusIsolated || state.ConsecutiveFailures >= command.Policy.FailureThreshold {
			state.Status = StatusIsolated
			state.ReasonCode = ReasonFailureThreshold
		} else {
			state.ReasonCode = ReasonFailurePending
		}
	case OutcomeUnknown:
		state.Status = StatusIsolated
		state.ConsecutiveFailures = 0
		state.ConsecutiveHealthy = 0
		state.ReasonCode = ReasonOutcomeUnknown
	case OutcomeSucceeded:
		state.ConsecutiveFailures = 0
		state = applyHealthEvidence(state, value.Health, command.Policy, now)
	}

	isIsolated := state.Status == StatusIsolated
	if !wasIsolated && isIsolated {
		isolatedAt := now
		state.IsolatedAt = &isolatedAt
		state.RecoveredAt = nil
		effects = append(effects,
			Effect{Kind: EffectAlertOpened, Code: AuditNodeIsolated, DedupeKey: transitionDedupeKey(state, AuditNodeIsolated)},
			Effect{Kind: EffectAudit, Code: AuditNodeIsolated, DedupeKey: transitionDedupeKey(state, AuditNodeIsolated)},
		)
	}
	if wasIsolated && !isIsolated {
		recoveredAt := now
		state.RecoveredAt = &recoveredAt
		effects = append(effects,
			Effect{Kind: EffectAlertResolved, Code: AuditNodeRecovered, DedupeKey: transitionDedupeKey(state, AuditNodeRecovered)},
			Effect{Kind: EffectAudit, Code: AuditNodeRecovered, DedupeKey: transitionDedupeKey(state, AuditNodeRecovered)},
		)
	}
	return ApplyResult{State: state, PublicationAllowed: !isIsolated, ReasonCode: state.ReasonCode, Effects: effects}
}

func applyHealthEvidence(state State, evidence *HealthEvidence, policy Policy, now time.Time) State {
	if evidence == nil || evidence.ObservedAt.After(now) || now.Sub(evidence.ObservedAt) > policy.MaxEvidenceAge ||
		evidence.SessionEpoch < state.LastSessionEpoch || evidence.SessionEpoch == state.LastSessionEpoch && evidence.Sequence <= state.LastHealthSequence {
		state.ConsecutiveHealthy = 0
		state.ReasonCode = ReasonEvidenceStale
		return state
	}
	state.LastSessionEpoch = evidence.SessionEpoch
	state.LastHealthSequence = evidence.Sequence
	if evidence.Active != state.Desired {
		state.ConsecutiveHealthy = 0
		state.ReasonCode = ReasonIdentityMismatch
		return state
	}
	if state.Status == StatusActive {
		state.ConsecutiveHealthy = 0
		state.ReasonCode = ReasonHealthy
		return state
	}
	state.ConsecutiveHealthy++
	if state.ConsecutiveHealthy < policy.RecoveryThreshold {
		state.ReasonCode = ReasonRecoveryPending
		return state
	}
	state.Status = StatusActive
	state.ReasonCode = ReasonRecovered
	return state
}

func validPolicy(policy Policy) bool {
	return policy.FailureThreshold > 0 && policy.FailureThreshold <= 100 &&
		policy.RecoveryThreshold > 0 && policy.RecoveryThreshold <= 100 && policy.MaxEvidenceAge > 0
}

func validSyncResult(value SyncResult) bool {
	if value.ScopeID == uuid.Nil || value.NodeID == uuid.Nil || value.ReportID == uuid.Nil || !validIdentity(value.Desired) {
		return false
	}
	switch value.Outcome {
	case OutcomeSucceeded:
		return value.ErrorCode == "" && value.Health != nil && validHealth(*value.Health)
	case OutcomeFailed, OutcomeUnknown:
		return errorCodePattern.MatchString(value.ErrorCode) && value.Health == nil
	default:
		return false
	}
}

func validIdentity(value ConfigIdentity) bool {
	return value.Schema == 1 && value.ConfigVersionID != uuid.Nil && value.ArtifactSHA256 != ([32]byte{})
}

func validHealth(value HealthEvidence) bool {
	return value.SessionEpoch > 0 && value.SessionEpoch <= uint64(^uint64(0)>>1) &&
		value.Sequence > 0 && value.Sequence <= uint64(^uint64(0)>>1) && !value.ObservedAt.IsZero() && validIdentity(value.Active)
}

func validNodeIDs(nodeIDs []uuid.UUID) bool {
	seen := make(map[uuid.UUID]struct{}, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if nodeID == uuid.Nil {
			return false
		}
		if _, exists := seen[nodeID]; exists {
			return false
		}
		seen[nodeID] = struct{}{}
	}
	return true
}

func normalizeSyncResult(value SyncResult) SyncResult {
	if value.Health != nil {
		health := *value.Health
		health.ObservedAt = health.ObservedAt.UTC().Truncate(time.Microsecond)
		value.Health = &health
	}
	return value
}

func syncResultDigest(value SyncResult) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func blockedPlan(nodeIDs []uuid.UUID, reason string) PublicationPlan {
	plan := PublicationPlan{IsolatedNodeIDs: slices.Clone(nodeIDs), Decisions: make([]PublicationDecision, 0, len(nodeIDs))}
	for _, nodeID := range nodeIDs {
		plan.Decisions = append(plan.Decisions, PublicationDecision{NodeID: nodeID, Allowed: false, Status: StatusIsolated, ReasonCode: reason})
	}
	return plan
}

func failClosedResult(value SyncResult, reason string) Result {
	return Result{State: State{ScopeID: value.ScopeID, NodeID: value.NodeID, Status: StatusIsolated, Desired: value.Desired, ReasonCode: reason}, ReasonCode: reason}
}

func reportDedupeKey(reportID uuid.UUID) string {
	return "node-config-sync-report:" + reportID.String()
}

func transitionDedupeKey(state State, code string) string {
	return fmt.Sprintf("node-isolation:%s:%d:%s", state.NodeID, state.Revision, code)
}
