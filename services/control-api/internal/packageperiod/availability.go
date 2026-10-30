package packageperiod

import "time"

type SuspensionReason string

const (
	SuspensionNone           SuspensionReason = ""
	SuspensionPending        SuspensionReason = "not_started"
	SuspensionExpired        SuspensionReason = "expired"
	SuspensionQuota          SuspensionReason = "quota_exceeded"
	SuspensionAdministrative SuspensionReason = "administrative"
)

type DecisionCause string

const (
	DecisionNone          DecisionCause = ""
	DecisionNotStarted    DecisionCause = "not_started"
	DecisionExpired       DecisionCause = "expired"
	DecisionQuotaExceeded DecisionCause = "quota_exceeded"
	DecisionNewCycle      DecisionCause = "new_cycle"
	DecisionActivated     DecisionCause = "activated"
)

type ServiceState struct {
	Enabled  bool
	Reason   SuspensionReason
	ResetKey string
}

type AvailabilityDecision struct {
	State   ServiceState
	Changed bool
	Cause   DecisionCause
}

func DecideAvailability(at time.Time, validity Validity, cycle Cycle, quotaExceeded bool,
	current ServiceState,
) (AvailabilityDecision, error) {
	if !validity.valid() || !validTime(at) || !current.valid() {
		return AvailabilityDecision{}, ErrInvalidState
	}
	if current.Reason == SuspensionAdministrative {
		return unchanged(current), nil
	}
	at = canonicalTime(at)
	if at.Before(validity.startsAt) {
		return changed(current, ServiceState{Reason: SuspensionPending}, DecisionNotStarted), nil
	}
	if !at.Before(validity.endsAt) {
		return changed(current, ServiceState{Reason: SuspensionExpired}, DecisionExpired), nil
	}
	if !cycle.valid() || !cycle.contains(at) {
		return AvailabilityDecision{}, ErrInvalidCycle
	}
	if quotaExceeded {
		desired := ServiceState{Reason: SuspensionQuota, ResetKey: cycle.resetKey}
		return changed(current, desired, DecisionQuotaExceeded), nil
	}
	if current.Reason == SuspensionQuota {
		if current.ResetKey == cycle.resetKey {
			return unchanged(current), nil
		}
		return changed(current, ServiceState{Enabled: true}, DecisionNewCycle), nil
	}
	if !current.Enabled {
		return changed(current, ServiceState{Enabled: true}, DecisionActivated), nil
	}
	return unchanged(current), nil
}

func (s ServiceState) valid() bool {
	if s.Enabled {
		return s.Reason == SuspensionNone && s.ResetKey == ""
	}
	switch s.Reason {
	case SuspensionPending, SuspensionExpired, SuspensionAdministrative:
		return s.ResetKey == ""
	case SuspensionQuota:
		return s.ResetKey != ""
	default:
		return false
	}
}

func changed(current, desired ServiceState, cause DecisionCause) AvailabilityDecision {
	if current == desired {
		return unchanged(current)
	}
	return AvailabilityDecision{State: desired, Changed: true, Cause: cause}
}

func unchanged(state ServiceState) AvailabilityDecision {
	return AvailabilityDecision{State: state}
}
