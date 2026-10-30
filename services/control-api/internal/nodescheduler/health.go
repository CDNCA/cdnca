package nodescheduler

import (
	"crypto/sha256"
	"encoding/json"
	"time"
)

// NextHealthState applies one probe verdict observed at observedAt to current
// under policy (consecutive results + debounce) and reports whether the
// status changed. Other probe targets than line endpoints (the aggregated
// edge's third-party supplies, ADR 0008 §6.3) share this rule.
func NextHealthState(current HealthState, policy HealthPolicy, healthy bool, observedAt time.Time) (HealthState, bool) {
	return nextHealthState(current, policy, ProbeRequest{Healthy: healthy, ObservedAt: observedAt}, observedAt)
}

func nextHealthState(current HealthState, policy HealthPolicy, request ProbeRequest, receivedAt time.Time) (HealthState, bool) {
	next := current
	observedAt := request.ObservedAt.UTC().Truncate(time.Microsecond)
	receivedAt = receivedAt.UTC().Truncate(time.Microsecond)
	startsNewStreak := (request.Healthy && current.ConsecutiveSuccesses == 0) ||
		(!request.Healthy && current.ConsecutiveFailures == 0)
	if startsNewStreak {
		started := observedAt
		next.StreakStartedAt = &started
	}
	if request.Healthy {
		next.ConsecutiveFailures = 0
		next.ConsecutiveSuccesses = min(current.ConsecutiveSuccesses+1, policy.RecoveryThreshold)
	} else {
		next.ConsecutiveSuccesses = 0
		next.ConsecutiveFailures = min(current.ConsecutiveFailures+1, policy.FailureThreshold)
	}
	targetStatus := HealthUnhealthy
	thresholdMet := next.ConsecutiveFailures >= policy.FailureThreshold
	debounce := policy.FailureDebounce
	if request.Healthy {
		targetStatus = HealthHealthy
		thresholdMet = next.ConsecutiveSuccesses >= policy.RecoveryThreshold
		debounce = policy.RecoveryDebounce
	}
	transitioned := false
	if next.Status != targetStatus && thresholdMet && next.StreakStartedAt != nil &&
		observedAt.Sub(*next.StreakStartedAt) >= debounce {
		next.Status = targetStatus
		next.LastChangedAt = observedAt
		transitioned = true
	}
	next.LastSequence = request.Sequence
	next.LastObservedAt = &observedAt
	next.LastReceivedAt = &receivedAt
	healthy := request.Healthy
	next.LastProbeHealthy = &healthy
	next.RowRevision++
	next.UpdatedAt = receivedAt
	return next, transitioned
}

func probeDigest(request ProbeRequest) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		TenantScopeID string `json:"tenant_scope_id"`
		GroupID       string `json:"group_id"`
		Revision      int64  `json:"revision"`
		EndpointID    string `json:"endpoint_id"`
		Sequence      int64  `json:"sequence"`
		ObservedAt    string `json:"observed_at"`
		Healthy       bool   `json:"healthy"`
	}{
		request.TenantScopeID.String(), request.GroupID.String(), request.Revision,
		request.EndpointID.String(), request.Sequence,
		request.ObservedAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano), request.Healthy,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
