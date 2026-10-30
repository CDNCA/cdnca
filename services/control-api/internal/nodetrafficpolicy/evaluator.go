package nodetrafficpolicy

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

func PeriodFor(now time.Time, timezone string) (Period, error) {
	if now.IsZero() || timezone == "" || strings.TrimSpace(timezone) != timezone {
		return Period{}, ErrInvalidInput
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return Period{}, ErrInvalidInput
	}
	local := now.In(location)
	start := time.Date(local.Year(), local.Month(), 1, 0, 0, 0, 0, location)
	end := time.Date(local.Year(), local.Month()+1, 1, 0, 0, 0, 0, location)
	return Period{
		Key:   fmt.Sprintf("%04d-%02d", local.Year(), int(local.Month())),
		Start: start.UTC(), End: end.UTC(),
	}, nil
}

func Evaluate(input EvaluationInput) (EvaluationDecision, error) {
	if err := ValidatePolicy(input.Policy); err != nil || input.Now.IsZero() ||
		input.Usage.Bytes > maxPostgresBigint ||
		input.Usage.SnapshotAt.IsZero() || input.Usage.FinalizedThrough.IsZero() ||
		!validDigest(input.Usage.SourceDigest) {
		return EvaluationDecision{}, ErrInvalidInput
	}
	period, err := PeriodFor(input.Now, input.Policy.Timezone)
	if err != nil {
		return EvaluationDecision{}, err
	}
	decision := EvaluationDecision{
		PeriodKey: period.Key, PeriodStart: period.Start, PeriodEnd: period.End,
		UsageBytes: input.Usage.Bytes, MonthlyLimitBytes: input.Policy.MonthlyLimitBytes,
		ReasonCode: ReasonWithinPolicy, EvaluatedAt: input.Now.UTC(),
		SourceSnapshotAt:       input.Usage.SnapshotAt.UTC(),
		SourceFinalizedThrough: input.Usage.FinalizedThrough.UTC(),
		SourceDigest:           input.Usage.SourceDigest,
	}

	if input.AdminState == NodeStateDisabled || input.AdminState == NodeStateRetired {
		decision.Suppressed = true
		decision.ReasonCode = ReasonAdminStateProtected
		return decision, nil
	}

	activeOverride := input.Policy.Override.ExpiresAt != nil && input.Policy.Override.ExpiresAt.After(input.Now)
	if activeOverride {
		decision.OverrideRevision = input.Policy.Override.Revision
		switch input.Policy.Override.Mode {
		case OverrideForceDisabled:
			decision.Suppressed = true
			decision.ReasonCode = ReasonManualForceDisabled
		case OverrideForceEnabled:
			decision.ReasonCode = ReasonManualForceEnabled
		}
	} else if input.Policy.MonthlyLimitBytes > 0 && input.Usage.Bytes >= input.Policy.MonthlyLimitBytes {
		decision.Suppressed = true
		decision.ReasonCode = ReasonMonthlyLimitReached
	} else if scheduled(input.Policy, input.Now) {
		decision.Suppressed = true
		decision.ReasonCode = ReasonScheduledWindow
	}

	if input.Previous == nil {
		decision.SyncRequired = decision.Suppressed
		return decision, nil
	}
	if input.Previous.Suppressed == decision.Suppressed {
		return decision, nil
	}
	decision.SyncRequired = true
	if !decision.Suppressed {
		if input.Previous.PeriodKey != decision.PeriodKey {
			decision.ReasonCode = ReasonPeriodReset
		} else if decision.ReasonCode == ReasonWithinPolicy {
			decision.ReasonCode = ReasonPolicyRecovered
		}
	}
	return decision, nil
}

func scheduled(policy Policy, now time.Time) bool {
	location, err := time.LoadLocation(policy.Timezone)
	if err != nil {
		return false
	}
	local := now.In(location)
	minute := local.Hour()*60 + local.Minute()
	for _, window := range policy.Windows {
		if window.StartMinute < window.EndMinute {
			if local.Weekday() == window.Weekday && minute >= window.StartMinute && minute < window.EndMinute {
				return true
			}
			continue
		}
		if local.Weekday() == window.Weekday && minute >= window.StartMinute {
			return true
		}
		previousDay := time.Weekday((int(window.Weekday) + 1) % 7)
		if local.Weekday() == previousDay && minute < window.EndMinute {
			return true
		}
	}
	return false
}

func ValidatePolicy(policy Policy) error {
	if policy.ScopeID == uuid.Nil || policy.NodeID == uuid.Nil || policy.Revision < 0 ||
		policy.MonthlyLimitBytes > maxPostgresBigint ||
		policy.Timezone == "" || strings.TrimSpace(policy.Timezone) != policy.Timezone || len(policy.Windows) > 32 {
		return ErrInvalidInput
	}
	if _, err := time.LoadLocation(policy.Timezone); err != nil {
		return ErrInvalidInput
	}
	for _, window := range policy.Windows {
		if window.Weekday < time.Sunday || window.Weekday > time.Saturday ||
			window.StartMinute < 0 || window.StartMinute >= 1440 ||
			window.EndMinute < 0 || window.EndMinute >= 1440 || window.StartMinute == window.EndMinute {
			return ErrInvalidInput
		}
	}
	if policy.Override.Mode == "" {
		policy.Override.Mode = OverrideNone
	}
	switch policy.Override.Mode {
	case OverrideNone:
		if policy.Override.ExpiresAt != nil {
			return ErrInvalidInput
		}
	case OverrideForceEnabled, OverrideForceDisabled:
		if policy.Override.Revision <= 0 || policy.Override.ExpiresAt == nil || policy.Override.ExpiresAt.IsZero() {
			return ErrInvalidInput
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
