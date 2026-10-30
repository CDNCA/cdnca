package dnspropagation

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

type CircuitPhase string

const (
	CircuitClosed   CircuitPhase = "closed"
	CircuitOpen     CircuitPhase = "open"
	CircuitHalfOpen CircuitPhase = "half_open"

	ReasonProviderAttemptAllowed        ReasonCode = "provider_attempt_allowed"
	ReasonProviderRetryAfter            ReasonCode = "provider_retry_after"
	ReasonProviderRetryBudgetExhausted  ReasonCode = "provider_retry_budget_exhausted"
	ReasonProviderCircuitOpen           ReasonCode = "provider_circuit_open"
	ReasonProviderHalfOpenProbe         ReasonCode = "provider_half_open_probe"
	ReasonProviderHalfOpenProbeInFlight ReasonCode = "provider_half_open_probe_in_flight"
	ReasonProviderSucceeded             ReasonCode = "provider_operation_succeeded"
	ReasonProviderCredentialsRejected   ReasonCode = "provider_credentials_rejected"
	ReasonProviderPermanentFailure      ReasonCode = "provider_permanent_failure"
	ReasonProviderUnknownFailure        ReasonCode = "provider_unknown_failure"
)

type ProviderCorrelation struct {
	TenantID          uuid.UUID
	ScopeID           uuid.UUID
	ProviderID        uuid.UUID
	ZoneID            uuid.UUID
	OperationID       string
	ClientRequestID   string
	ProviderRequestID string
	Attempt           uint32
}

type ProviderRetryPolicy struct {
	BaseDelay               time.Duration
	MaxDelay                time.Duration
	BudgetWindow            time.Duration
	CircuitOpen             time.Duration
	AttemptsPerZone         uint32
	TransientFailuresToOpen uint32
}

type ProviderRetryState struct {
	Revision              uint64
	WindowStartedAt       time.Time
	AttemptsInWindow      uint32
	ConsecutiveTransient  uint32
	Phase                 CircuitPhase
	OpenUntil             time.Time
	ProbeOperationID      string
	LastOperationID       string
	LastProviderRequestID string
}

type ProviderOutcome struct {
	Success           bool
	Unknown           bool
	Code              dnsproviderremote.ErrorCode
	RetryAfter        time.Duration
	ProviderRequestID string
}

type ProviderRetryDecision struct {
	Allowed          bool
	Deferred         bool
	Rejected         bool
	NotBefore        time.Time
	Reason           ReasonCode
	ExpectedRevision uint64
	NextState        ProviderRetryState
	Correlation      ProviderCorrelation
}

type ProviderAttempt struct {
	Correlation ProviderCorrelation
	ReadyAt     time.Time
}

func ReserveProviderAttempt(now time.Time, policy ProviderRetryPolicy, correlation ProviderCorrelation,
	state ProviderRetryState) (ProviderRetryDecision, error) {
	if !validRetryInput(now, policy, correlation, state) {
		return ProviderRetryDecision{}, ErrInvalidInput
	}
	decision := retryDecision(correlation, state)
	next := state
	resetBudgetWindow(now, policy, &next)

	switch next.Phase {
	case CircuitOpen:
		if now.Before(next.OpenUntil) {
			decision.Deferred = true
			decision.NotBefore = next.OpenUntil
			decision.Reason = ReasonProviderCircuitOpen
			return decision, nil
		}
		next.Phase = CircuitHalfOpen
		next.OpenUntil = time.Time{}
		next.ProbeOperationID = correlation.OperationID
		decision.Reason = ReasonProviderHalfOpenProbe
	case CircuitHalfOpen:
		decision.Deferred = true
		decision.NotBefore = now.Add(policy.BaseDelay)
		decision.Reason = ReasonProviderHalfOpenProbeInFlight
		return decision, nil
	default:
		decision.Reason = ReasonProviderAttemptAllowed
	}

	if next.AttemptsInWindow >= policy.AttemptsPerZone {
		decision.Deferred = true
		decision.NotBefore = next.WindowStartedAt.Add(policy.BudgetWindow)
		decision.Reason = ReasonProviderRetryBudgetExhausted
		return decision, nil
	}
	next.AttemptsInWindow++
	next.LastOperationID = correlation.OperationID
	next.LastProviderRequestID = correlation.ProviderRequestID
	next.Revision++
	decision.Allowed = true
	decision.NextState = next
	return decision, nil
}

func SettleProviderAttempt(now time.Time, policy ProviderRetryPolicy, correlation ProviderCorrelation,
	state ProviderRetryState, outcome ProviderOutcome) (ProviderRetryDecision, error) {
	if !validRetryInput(now, policy, correlation, state) || !validProviderOutcome(outcome) ||
		state.Phase == CircuitHalfOpen && state.ProbeOperationID != correlation.OperationID ||
		state.LastOperationID != "" && state.LastOperationID != correlation.OperationID ||
		state.LastProviderRequestID != "" && state.LastProviderRequestID != correlation.ProviderRequestID ||
		outcome.ProviderRequestID != "" && outcome.ProviderRequestID != correlation.ProviderRequestID {
		return ProviderRetryDecision{}, ErrInvalidInput
	}
	decision := retryDecision(correlation, state)
	next := state
	next.Revision++
	next.LastOperationID = correlation.OperationID
	if outcome.ProviderRequestID != "" {
		next.LastProviderRequestID = outcome.ProviderRequestID
	} else {
		next.LastProviderRequestID = correlation.ProviderRequestID
	}
	decision.NextState = next

	if outcome.Success {
		next.Phase = CircuitClosed
		next.OpenUntil = time.Time{}
		next.ProbeOperationID = ""
		next.ConsecutiveTransient = 0
		decision.Allowed = true
		decision.Reason = ReasonProviderSucceeded
		decision.NextState = next
		return decision, nil
	}
	if outcome.Unknown {
		decision.Rejected = true
		decision.Reason = ReasonProviderUnknownFailure
		return decision, nil
	}
	if outcome.Code == dnsproviderremote.CodeCredentialsRejected {
		next.Phase = CircuitClosed
		next.OpenUntil = time.Time{}
		next.ProbeOperationID = ""
		next.ConsecutiveTransient = 0
		decision.Rejected = true
		decision.Reason = ReasonProviderCredentialsRejected
		decision.NextState = next
		return decision, nil
	}
	if !transientProviderCode(outcome.Code) {
		next.Phase = CircuitClosed
		next.OpenUntil = time.Time{}
		next.ProbeOperationID = ""
		next.ConsecutiveTransient = 0
		decision.Rejected = true
		decision.Reason = ReasonProviderPermanentFailure
		decision.NextState = next
		return decision, nil
	}

	next.ConsecutiveTransient++
	delay := boundedRetryDelay(policy, outcome.RetryAfter)
	decision.Deferred = true
	decision.NotBefore = now.Add(delay)
	decision.Reason = ReasonProviderRetryAfter
	if next.ConsecutiveTransient >= policy.TransientFailuresToOpen {
		next.Phase = CircuitOpen
		next.ProbeOperationID = ""
		openUntil := now.Add(policy.CircuitOpen)
		if decision.NotBefore.After(openUntil) {
			openUntil = decision.NotBefore
		}
		next.OpenUntil = openUntil
		decision.NotBefore = openUntil
		decision.Reason = ReasonProviderCircuitOpen
	}
	decision.NextState = next
	return decision, nil
}

func ProviderOutcomeFromError(err error) ProviderOutcome {
	if err == nil {
		return ProviderOutcome{Success: true}
	}
	var remote *dnsproviderremote.Error
	if errors.As(err, &remote) && remote != nil {
		return ProviderOutcome{Code: remote.Code, RetryAfter: remote.RetryAfter}
	}
	return ProviderOutcome{Unknown: true}
}

func SelectFairProviderAttempts(now time.Time, afterZone uuid.UUID, candidates []ProviderAttempt,
	limit int) ([]ProviderAttempt, error) {
	if now.IsZero() || limit < 1 {
		return nil, ErrInvalidInput
	}
	perZone := make(map[uuid.UUID]ProviderAttempt, len(candidates))
	for _, candidate := range candidates {
		if !validCorrelation(candidate.Correlation) || candidate.ReadyAt.IsZero() {
			return nil, ErrInvalidInput
		}
		if candidate.ReadyAt.After(now) {
			continue
		}
		current, exists := perZone[candidate.Correlation.ZoneID]
		if !exists || providerAttemptLess(candidate, current) {
			perZone[candidate.Correlation.ZoneID] = candidate
		}
	}
	ready := make([]ProviderAttempt, 0, len(perZone))
	for _, candidate := range perZone {
		ready = append(ready, candidate)
	}
	sort.Slice(ready, func(left, right int) bool {
		return ready[left].Correlation.ZoneID.String() < ready[right].Correlation.ZoneID.String()
	})
	if len(ready) == 0 {
		return []ProviderAttempt{}, nil
	}
	start := 0
	if afterZone != uuid.Nil {
		after := afterZone.String()
		start = sort.Search(len(ready), func(index int) bool {
			return ready[index].Correlation.ZoneID.String() > after
		})
		if start == len(ready) {
			start = 0
		}
	}
	if limit > len(ready) {
		limit = len(ready)
	}
	selected := make([]ProviderAttempt, 0, limit)
	for offset := 0; offset < limit; offset++ {
		selected = append(selected, ready[(start+offset)%len(ready)])
	}
	return selected, nil
}

func retryDecision(correlation ProviderCorrelation, state ProviderRetryState) ProviderRetryDecision {
	return ProviderRetryDecision{
		ExpectedRevision: state.Revision,
		NextState:        state,
		Correlation:      correlation,
	}
}

func resetBudgetWindow(now time.Time, policy ProviderRetryPolicy, state *ProviderRetryState) {
	if state.WindowStartedAt.IsZero() || !now.Before(state.WindowStartedAt.Add(policy.BudgetWindow)) {
		state.WindowStartedAt = now
		state.AttemptsInWindow = 0
	}
}

func boundedRetryDelay(policy ProviderRetryPolicy, hint time.Duration) time.Duration {
	if hint < policy.BaseDelay {
		return policy.BaseDelay
	}
	if hint > policy.MaxDelay {
		return policy.MaxDelay
	}
	return hint
}

func transientProviderCode(code dnsproviderremote.ErrorCode) bool {
	switch code {
	case dnsproviderremote.CodeRateLimited, dnsproviderremote.CodeUnavailable,
		dnsproviderremote.CodeSourceUnavailable, dnsproviderremote.CodeTimeout:
		return true
	default:
		return false
	}
}

func validRetryInput(now time.Time, policy ProviderRetryPolicy, correlation ProviderCorrelation,
	state ProviderRetryState) bool {
	if now.IsZero() || !validRetryPolicy(policy) || !validCorrelation(correlation) ||
		state.AttemptsInWindow > policy.AttemptsPerZone ||
		!state.WindowStartedAt.IsZero() && state.WindowStartedAt.After(now) {
		return false
	}
	switch state.Phase {
	case CircuitClosed:
		return state.ProbeOperationID == ""
	case CircuitOpen:
		return !state.OpenUntil.IsZero() && state.ProbeOperationID == ""
	case CircuitHalfOpen:
		return validRetryReference(state.ProbeOperationID)
	default:
		return false
	}
}

func validRetryPolicy(policy ProviderRetryPolicy) bool {
	return policy.BaseDelay > 0 && policy.MaxDelay >= policy.BaseDelay && policy.BudgetWindow > 0 &&
		policy.MaxDelay <= time.Hour && policy.CircuitOpen > 0 &&
		policy.AttemptsPerZone > 0 && policy.TransientFailuresToOpen > 0
}

func validCorrelation(correlation ProviderCorrelation) bool {
	return correlation.TenantID != uuid.Nil && correlation.ScopeID != uuid.Nil &&
		correlation.ProviderID != uuid.Nil && correlation.ZoneID != uuid.Nil && correlation.Attempt > 0 &&
		validRetryReference(correlation.OperationID) && validRetryReference(correlation.ClientRequestID) &&
		validRetryReference(correlation.ProviderRequestID)
}

func validProviderOutcome(outcome ProviderOutcome) bool {
	if outcome.Success || outcome.Unknown {
		return outcome.Success != outcome.Unknown && outcome.Code == "" && outcome.RetryAfter == 0 &&
			validOptionalRetryReference(outcome.ProviderRequestID)
	}
	return outcome.Code != "" && outcome.RetryAfter >= 0 && validOptionalRetryReference(outcome.ProviderRequestID)
}

func validRetryReference(value string) bool {
	if len(value) < 1 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validOptionalRetryReference(value string) bool {
	return value == "" || validRetryReference(value)
}

func providerAttemptLess(left, right ProviderAttempt) bool {
	if !left.ReadyAt.Equal(right.ReadyAt) {
		return left.ReadyAt.Before(right.ReadyAt)
	}
	if left.Correlation.OperationID != right.Correlation.OperationID {
		return left.Correlation.OperationID < right.Correlation.OperationID
	}
	return left.Correlation.ProviderRequestID < right.Correlation.ProviderRequestID
}
