package nodetrafficpolicy

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPeriodForUsesPolicyTimezoneAndHalfOpenNaturalMonth(t *testing.T) {
	period, err := PeriodFor(time.Date(2028, 3, 1, 3, 59, 59, 0, time.UTC), "America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := period.Start, time.Date(2028, 2, 1, 5, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("start = %s, want %s", got, want)
	}
	if got, want := period.End, time.Date(2028, 3, 1, 5, 0, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("end = %s, want %s", got, want)
	}
	if period.Key != "2028-02" {
		t.Fatalf("key = %q, want 2028-02", period.Key)
	}
}

func TestEvaluateThresholdAndScheduleBoundaries(t *testing.T) {
	now := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	policy := validPolicy()
	policy.MonthlyLimitBytes = 1_000
	policy.Windows = []ScheduleWindow{{Weekday: time.Monday, StartMinute: 570, EndMinute: 600}}

	below, err := Evaluate(EvaluationInput{Policy: policy, Now: now, Usage: usageEvidence(999), AdminState: NodeStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if below.Suppressed || below.ReasonCode != ReasonWithinPolicy {
		t.Fatalf("below limit = %#v", below)
	}

	atLimit, err := Evaluate(EvaluationInput{Policy: policy, Now: now, Usage: usageEvidence(1_000), AdminState: NodeStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if !atLimit.Suppressed || atLimit.ReasonCode != ReasonMonthlyLimitReached {
		t.Fatalf("at limit = %#v", atLimit)
	}

	windowStart := now.Add(90 * time.Minute)
	inside, err := Evaluate(EvaluationInput{Policy: policy, Now: windowStart, Usage: usageEvidence(999), AdminState: NodeStateActive})
	if err != nil || !inside.Suppressed || inside.ReasonCode != ReasonScheduledWindow {
		t.Fatalf("window start = (%#v, %v)", inside, err)
	}

	windowEnd := windowStart.Add(30 * time.Minute)
	after, err := Evaluate(EvaluationInput{Policy: policy, Now: windowEnd, Usage: usageEvidence(999), AdminState: NodeStateActive})
	if err != nil || after.Suppressed {
		t.Fatalf("window end = (%#v, %v), want enabled", after, err)
	}
}

func TestEvaluateManualOverrideExpiryAndAdminStateProtection(t *testing.T) {
	now := time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC)
	policy := validPolicy()
	policy.MonthlyLimitBytes = 100
	expiresAt := now.Add(time.Second)
	policy.Override = ManualOverride{Mode: OverrideForceEnabled, Revision: 8, ExpiresAt: &expiresAt}

	forced, err := Evaluate(EvaluationInput{Policy: policy, Now: now, Usage: usageEvidence(100), AdminState: NodeStateActive})
	if err != nil || forced.Suppressed || forced.ReasonCode != ReasonManualForceEnabled || forced.OverrideRevision != 8 {
		t.Fatalf("forced = (%#v, %v)", forced, err)
	}

	expired, err := Evaluate(EvaluationInput{Policy: policy, Now: now.Add(time.Second), Usage: usageEvidence(100), AdminState: NodeStateActive})
	if err != nil || !expired.Suppressed || expired.ReasonCode != ReasonMonthlyLimitReached {
		t.Fatalf("expired = (%#v, %v)", expired, err)
	}

	for _, state := range []string{NodeStateDisabled, NodeStateRetired} {
		protected, protectErr := Evaluate(EvaluationInput{
			Policy: policy, Now: now, Usage: usageEvidence(0), AdminState: state,
		})
		if protectErr != nil || !protected.Suppressed || protected.ReasonCode != ReasonAdminStateProtected || protected.SyncRequired {
			t.Fatalf("protected %s = (%#v, %v)", state, protected, protectErr)
		}
	}
}

func TestEvaluateNewMonthRequiresRealConfigSyncOnlyWhenAutomaticSuppressionClears(t *testing.T) {
	policy := validPolicy()
	policy.MonthlyLimitBytes = 100
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	decision, err := Evaluate(EvaluationInput{
		Policy: policy, Now: now, Usage: usageEvidence(0), AdminState: NodeStateActive,
		Previous: &EvaluationSnapshot{PeriodKey: "2026-08", Suppressed: true, ReasonCode: ReasonMonthlyLimitReached},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Suppressed || !decision.SyncRequired || decision.ReasonCode != ReasonPeriodReset {
		t.Fatalf("decision = %#v", decision)
	}
}

func validPolicy() Policy {
	return Policy{
		ID:       uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ScopeID:  uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		NodeID:   uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Timezone: "Asia/Shanghai", Revision: 4,
	}
}

func usageEvidence(bytes uint64) UsageEvidence {
	return UsageEvidence{
		Bytes:            bytes,
		SnapshotAt:       time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC),
		FinalizedThrough: time.Date(2026, 8, 10, 1, 59, 0, 0, time.UTC),
		SourceDigest:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}
