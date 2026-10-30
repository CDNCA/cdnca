package packageperiod

import (
	"testing"
	"time"
)

func TestAvailabilityExpiresAtExactEndBoundary(t *testing.T) {
	location := mustLocation(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	end := time.Date(2026, time.August, 1, 0, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, end, location)
	active := ServiceState{Enabled: true}

	decision, err := DecideAvailability(end, validity, Cycle{}, false, active)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Changed || decision.Cause != DecisionExpired || decision.State.Enabled ||
		decision.State.Reason != SuspensionExpired {
		t.Fatalf("expiry decision = %#v", decision)
	}

	decision, err = DecideAvailability(end.Add(24*time.Hour), validity, Cycle{}, false, decision.State)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Changed || decision.Cause != DecisionNone || decision.State.Reason != SuspensionExpired {
		t.Fatalf("repeated expiry decision = %#v", decision)
	}
}

func TestAvailabilityActivatesAfterValidityIsExtended(t *testing.T) {
	location := mustLocation(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	originalEnd := time.Date(2026, time.August, 1, 0, 0, 0, 0, location)
	original := mustCustomValidity(t, start, originalEnd, location)
	expired, err := DecideAvailability(originalEnd, original, Cycle{}, false, ServiceState{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	extendedEnd := time.Date(2026, time.September, 1, 0, 0, 0, 0, location)
	extended := mustCustomValidity(t, start, extendedEnd, location)
	cycle, err := CurrentCycle("subscription-renewed", extended, CyclePolicy{Kind: CycleMonthly}, originalEnd)
	if err != nil {
		t.Fatal(err)
	}
	activated, err := DecideAvailability(originalEnd, extended, cycle, false, expired.State)
	if err != nil {
		t.Fatal(err)
	}
	if !activated.Changed || activated.Cause != DecisionActivated || !activated.State.Enabled {
		t.Fatalf("extended validity decision = %#v", activated)
	}
}

func TestAvailabilityRecoversOnlyInANewCycle(t *testing.T) {
	location := mustLocation(t, "Asia/Shanghai")
	start := time.Date(2026, time.July, 1, 8, 0, 0, 0, location)
	end := time.Date(2026, time.September, 1, 8, 0, 0, 0, location)
	validity := mustCustomValidity(t, start, end, location)
	policy := CyclePolicy{Kind: CycleMonthly}
	firstAt := time.Date(2026, time.July, 20, 12, 0, 0, 0, location)
	firstCycle, err := CurrentCycle("subscription-recovery", validity, policy, firstAt)
	if err != nil {
		t.Fatal(err)
	}

	disabled, err := DecideAvailability(firstAt, validity, firstCycle, true, ServiceState{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if !disabled.Changed || disabled.Cause != DecisionQuotaExceeded || disabled.State.Enabled ||
		disabled.State.Reason != SuspensionQuota || disabled.State.ResetKey != firstCycle.ResetKey() {
		t.Fatalf("quota decision = %#v", disabled)
	}

	stillDisabled, err := DecideAvailability(firstAt.Add(time.Hour), validity, firstCycle, false, disabled.State)
	if err != nil {
		t.Fatal(err)
	}
	if stillDisabled.Changed || stillDisabled.State.Enabled || stillDisabled.State.ResetKey != firstCycle.ResetKey() {
		t.Fatalf("same-cycle decision = %#v", stillDisabled)
	}

	secondAt := time.Date(2026, time.August, 1, 8, 0, 0, 0, location)
	secondCycle, err := CurrentCycle("subscription-recovery", validity, policy, secondAt)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := DecideAvailability(secondAt, validity, secondCycle, false, disabled.State)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Changed || recovered.Cause != DecisionNewCycle || !recovered.State.Enabled ||
		recovered.State.Reason != SuspensionNone || recovered.State.ResetKey != "" {
		t.Fatalf("new-cycle decision = %#v", recovered)
	}
}

func TestAvailabilityDoesNotOverrideAdministrativeSuspension(t *testing.T) {
	location := mustLocation(t, "UTC")
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, location)
	end := start.AddDate(0, 2, 0)
	validity := mustCustomValidity(t, start, end, location)
	cycle, err := CurrentCycle("subscription-manual", validity, CyclePolicy{Kind: CycleMonthly}, start)
	if err != nil {
		t.Fatal(err)
	}
	manual := ServiceState{Reason: SuspensionAdministrative}

	decision, err := DecideAvailability(start, validity, cycle, false, manual)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Changed || decision.State != manual {
		t.Fatalf("administrative decision = %#v", decision)
	}
}
