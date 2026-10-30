package packagesubscription

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

func TestDecideCycleEnforcementMonthlyLeapAndIANABoundaries(t *testing.T) {
	location := mustEnforcementLocation(t, "America/Los_Angeles")
	startsAt := time.Date(2024, time.January, 31, 1, 30, 0, 0, location)
	endsAt := time.Date(2024, time.May, 31, 1, 30, 0, 0, location)
	subscription := enforcementSubscription(startsAt, endsAt, location, packageperiod.CycleMonthly)

	before, err := DecideCycleEnforcement(EnforcementInput{
		At:           time.Date(2024, time.February, 29, 1, 29, 59, 0, location),
		Subscription: subscription, Limits: enforcementLimits(),
		Usage: EnforcementUsage{TrafficBytes: 101}, EvidenceID: "leap-before",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := DecideCycleEnforcement(EnforcementInput{
		At:           time.Date(2024, time.February, 29, 1, 30, 0, 0, location),
		Subscription: subscription, Limits: enforcementLimits(), EvidenceID: "leap-after",
	}, &before.State)
	if err != nil {
		t.Fatal(err)
	}
	if before.State.PeriodKey == after.State.PeriodKey {
		t.Fatal("exact monthly boundary must advance the target period")
	}
	if got := after.State.CycleStartsAt.In(location); got.Day() != 29 || got.Hour() != 1 || got.Minute() != 30 {
		t.Fatalf("monthly cycle must clamp to leap day in the subscription IANA zone: %s", got)
	}
	if after.State.Status != EnforcementActive || after.Transition != EnforcementRecovered {
		t.Fatalf("new cycle must recover an old-cycle suspension: %+v", after)
	}
}

func TestDecideCycleEnforcementDailyDSTUsesCivilBoundaries(t *testing.T) {
	location := mustEnforcementLocation(t, "America/Los_Angeles")
	startsAt := time.Date(2024, time.March, 9, 1, 30, 0, 0, location)
	endsAt := time.Date(2024, time.March, 13, 1, 30, 0, 0, location)
	decision, err := DecideCycleEnforcement(EnforcementInput{
		At:           time.Date(2024, time.March, 10, 1, 30, 0, 0, location),
		Subscription: enforcementSubscription(startsAt, endsAt, location, packageperiod.CycleDaily),
		Limits:       enforcementLimits(), EvidenceID: "dst-day",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := decision.State.CycleEndsAt.Sub(decision.State.CycleStartsAt); got != 23*time.Hour {
		t.Fatalf("spring-forward civil day must be 23 hours, got %s", got)
	}
}

func TestDecideCycleEnforcementReasonsSoftSuspensionAndRecovery(t *testing.T) {
	subscription := enforcementSubscriptionUTC()
	tests := []struct {
		name   string
		usage  EnforcementUsage
		reason EnforcementReason
	}{
		{name: "traffic", usage: EnforcementUsage{TrafficBytes: 101}, reason: EnforcementTrafficExceeded},
		{name: "bandwidth", usage: EnforcementUsage{BandwidthBPS: 201}, reason: EnforcementBandwidthExceeded},
		{name: "connections", usage: EnforcementUsage{Connections: 301}, reason: EnforcementConnectionsExceeded},
		{name: "sites", usage: EnforcementUsage{Sites: 5}, reason: EnforcementSitesExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := DecideCycleEnforcement(EnforcementInput{
				At: subscription.Period.StartsAt.Add(time.Hour), Subscription: subscription,
				Limits: enforcementLimits(), Usage: test.usage, EvidenceID: "quota-" + test.name,
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if decision.State.Status != EnforcementSuspended || decision.State.Reason != test.reason ||
				decision.Transition != EnforcementSuspendedNow {
				t.Fatalf("unexpected suspension decision: %+v", decision)
			}
			if len(decision.BlockedOperations) != 2 || decision.BlockedOperations[0] != SuccessorCreate ||
				decision.BlockedOperations[1] != SuccessorExpand || decision.EdgeAction != "" {
				t.Fatalf("suspension must block only successor growth and never stop edge traffic: %+v", decision)
			}
		})
	}

	suspended, err := DecideCycleEnforcement(EnforcementInput{
		At: subscription.Period.StartsAt.Add(time.Hour), Subscription: subscription,
		Limits: enforcementLimits(), Usage: EnforcementUsage{TrafficBytes: 101}, EvidenceID: "old-cycle",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := DecideCycleEnforcement(EnforcementInput{
		At: subscription.Period.StartsAt.AddDate(0, 1, 0), Subscription: subscription,
		Limits: enforcementLimits(), EvidenceID: "new-cycle",
	}, &suspended.State)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State.Status != EnforcementActive || recovered.Transition != EnforcementRecovered ||
		recovered.State.PeriodKey == suspended.State.PeriodKey {
		t.Fatalf("next cycle must recover without mutating the old cycle: %+v", recovered)
	}
}

func TestDecideCycleEnforcementTargetedCreditsOverridesAndReplay(t *testing.T) {
	subscription := enforcementSubscriptionUTC()
	at := subscription.Period.StartsAt.Add(time.Hour)
	base := EnforcementInput{
		At: at, Subscription: subscription, Limits: enforcementLimits(),
		Usage: EnforcementUsage{TrafficBytes: 110}, EvidenceID: "adjusted",
	}
	probe, err := DecideCycleEnforcement(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.Adjustments = []UsageAdjustment{{
		ID: "z-credit", PeriodKey: probe.State.PeriodKey, Metric: EnforcementMetricTraffic,
		Kind: AdjustmentCredit, Amount: 20,
	}}
	credited, err := DecideCycleEnforcement(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if credited.State.Status != EnforcementActive || credited.EffectiveUsage.TrafficBytes != 90 {
		t.Fatalf("target-period credit must reduce effective usage: %+v", credited)
	}
	base.Adjustments = append(base.Adjustments, UsageAdjustment{
		ID: "a-reversal", ReversesID: "z-credit", PeriodKey: probe.State.PeriodKey,
		Metric: EnforcementMetricTraffic, Kind: AdjustmentReversal, Amount: 20,
	})
	base.EvidenceID = "reversed"
	reversed, err := DecideCycleEnforcement(base, &credited.State)
	if err != nil {
		t.Fatal(err)
	}
	if reversed.State.Status != EnforcementSuspended || reversed.State.Reason != EnforcementTrafficExceeded {
		t.Fatalf("credit reversal must restore the original usage: %+v", reversed)
	}
	base.Adjustments = []UsageAdjustment{{
		ID: "wrong-period", PeriodKey: "another-period", Metric: EnforcementMetricTraffic,
		Kind: AdjustmentCredit, Amount: 110,
	}}
	base.EvidenceID = "wrong-period"
	wrongPeriod, err := DecideCycleEnforcement(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wrongPeriod.State.Status != EnforcementSuspended {
		t.Fatal("an adjustment for another period must not reset the target period")
	}
	base.Adjustments = nil
	base.Override = &EnforcementOverride{PeriodKey: probe.State.PeriodKey, Mode: OverrideKeepActive, Revision: 1}
	base.EvidenceID = "override"
	overridden, err := DecideCycleEnforcement(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	if overridden.State.Status != EnforcementActive || overridden.State.Reason != EnforcementManualOverride {
		t.Fatalf("manual keep-active override must be explainable: %+v", overridden)
	}
	replay, err := DecideCycleEnforcement(base, &overridden.State)
	if err != nil {
		t.Fatal(err)
	}
	if replay.Transition != EnforcementNoChange || replay.State.DecisionDigest != overridden.State.DecisionDigest {
		t.Fatalf("same evidence replay must preserve the exact LKG decision: %+v", replay)
	}
}

func TestDecideCycleEnforcementRejectsTamperAndOverflow(t *testing.T) {
	subscription := enforcementSubscriptionUTC()
	input := EnforcementInput{
		At: subscription.Period.StartsAt.Add(time.Hour), Subscription: subscription,
		Limits: enforcementLimits(), EvidenceID: "same-evidence",
	}
	first, err := DecideCycleEnforcement(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.Usage.TrafficBytes = 1
	if _, err := DecideCycleEnforcement(input, &first.State); !errors.Is(err, ErrEnforcementEvidenceConflict) {
		t.Fatalf("same evidence id with different facts must fail closed, got %v", err)
	}
	input.EvidenceID = "overflow"
	input.Usage.TrafficBytes = ^uint64(0)
	input.Adjustments = []UsageAdjustment{{
		ID: "overflow-reversal", ReversesID: "missing", PeriodKey: first.State.PeriodKey,
		Metric: EnforcementMetricTraffic, Kind: AdjustmentReversal, Amount: 1,
	}}
	if _, err := DecideCycleEnforcement(input, nil); !errors.Is(err, ErrEnforcementInvalidInput) {
		t.Fatalf("orphan reversal must be rejected, got %v", err)
	}
}

func enforcementSubscriptionUTC() Subscription {
	location := time.UTC
	startsAt := time.Date(2024, time.January, 1, 0, 0, 0, 0, location)
	endsAt := time.Date(2024, time.April, 1, 0, 0, 0, 0, location)
	return enforcementSubscription(startsAt, endsAt, location, packageperiod.CycleMonthly)
}

func enforcementSubscription(startsAt, endsAt time.Time, location *time.Location, kind packageperiod.CycleKind) Subscription {
	return Subscription{
		ID:              uuid.MustParse("10000000-0000-4000-8000-000000000001"),
		TenantScopeID:   uuid.MustParse("20000000-0000-4000-8000-000000000001"),
		LifecycleStatus: LifecycleActive,
		Period: PeriodSnapshot{
			StartsAt: startsAt.UTC(), EndsAt: endsAt.UTC(), TimeZone: location.String(),
			CyclePolicy:   packageperiod.CyclePolicy{Kind: kind},
			TrafficFactor: RationalSnapshot{Numerator: 1, Denominator: 1},
		},
	}
}

func enforcementLimits() EnforcementLimits {
	return EnforcementLimits{TrafficBytes: 100, BandwidthBPS: 200, Connections: 300, Sites: 4}
}

func mustEnforcementLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return location
}
