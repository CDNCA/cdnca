package dnspropagation

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/google/uuid"
)

func TestProviderRetryReservePreservesCASAndCorrelation(t *testing.T) {
	now := retryTestNow()
	policy := retryTestPolicy()
	correlation := retryTestCorrelation("operation-a", "provider-request-a")
	state := ProviderRetryState{Revision: 7, WindowStartedAt: now, Phase: CircuitPhase("closed")}

	decision, err := ReserveProviderAttempt(now, policy, correlation, state)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.Deferred || decision.Rejected {
		t.Fatalf("decision = %#v, want one allowed attempt", decision)
	}
	if decision.ExpectedRevision != state.Revision || decision.NextState.Revision != state.Revision+1 {
		t.Fatalf("revisions = (%d,%d), want (%d,%d)", decision.ExpectedRevision,
			decision.NextState.Revision, state.Revision, state.Revision+1)
	}
	if decision.Correlation != correlation || decision.NextState.LastOperationID != correlation.OperationID ||
		decision.NextState.LastProviderRequestID != correlation.ProviderRequestID {
		t.Fatalf("correlation was not preserved: decision=%#v", decision)
	}
	if decision.NextState.AttemptsInWindow != 1 || state.AttemptsInWindow != 0 || state.Revision != 7 {
		t.Fatalf("reserve state = %#v, input = %#v", decision.NextState, state)
	}
}

func TestProviderRetryBudgetDefersUntilWindowReset(t *testing.T) {
	now := retryTestNow()
	policy := retryTestPolicy()
	state := ProviderRetryState{
		Revision: 3, WindowStartedAt: now.Add(-policy.BudgetWindow / 2),
		AttemptsInWindow: policy.AttemptsPerZone, Phase: CircuitPhase("closed"),
	}

	decision, err := ReserveProviderAttempt(now, policy, retryTestCorrelation("budgeted", "provider-budgeted"), state)
	if err != nil {
		t.Fatal(err)
	}
	wantNotBefore := state.WindowStartedAt.Add(policy.BudgetWindow)
	if decision.Allowed || !decision.Deferred || decision.Rejected || !decision.NotBefore.Equal(wantNotBefore) ||
		string(decision.Reason) != "provider_retry_budget_exhausted" {
		t.Fatalf("budget decision = %#v, want defer until %s", decision, wantNotBefore)
	}

	expired := state
	expired.WindowStartedAt = now.Add(-policy.BudgetWindow)
	resumed, err := ReserveProviderAttempt(now, policy, retryTestCorrelation("window-reset", "provider-reset"), expired)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Allowed || resumed.NextState.AttemptsInWindow != 1 || !resumed.NextState.WindowStartedAt.Equal(now) {
		t.Fatalf("expired budget decision = %#v, want a fresh one-attempt window", resumed)
	}
}

func TestProviderRetryAfterUsesHintBoundsAndFallback(t *testing.T) {
	now := retryTestNow()
	policy := retryTestPolicy()
	correlation := retryTestCorrelation("retry-after", "provider-retry-after")
	state := ProviderRetryState{Revision: 11, WindowStartedAt: now, AttemptsInWindow: 1, Phase: CircuitPhase("closed")}

	for _, test := range []struct {
		name  string
		hint  time.Duration
		delay time.Duration
	}{
		{name: "provider 37 seconds", hint: 37 * time.Second, delay: 37 * time.Second},
		{name: "provider two hours is capped", hint: 2 * time.Hour, delay: policy.MaxDelay},
		{name: "missing provider hint uses base", hint: 0, delay: policy.BaseDelay},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := SettleProviderAttempt(now, policy, correlation, state, ProviderOutcome{
				Code: dnsproviderremote.CodeRateLimited, RetryAfter: test.hint,
				ProviderRequestID: correlation.ProviderRequestID,
			})
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allowed || !decision.Deferred || decision.Rejected ||
				!decision.NotBefore.Equal(now.Add(test.delay)) || string(decision.Reason) != "provider_retry_after" {
				t.Fatalf("decision = %#v, want retry at %s", decision, now.Add(test.delay))
			}
			if decision.ExpectedRevision != state.Revision || decision.NextState.Revision != state.Revision+1 ||
				decision.NextState.LastOperationID != correlation.OperationID ||
				decision.NextState.LastProviderRequestID != correlation.ProviderRequestID {
				t.Fatalf("settlement lost CAS/correlation: %#v", decision)
			}
		})
	}
}

func TestProviderRetryCircuitOpensAndAllowsOneHalfOpenProbe(t *testing.T) {
	now := retryTestNow()
	policy := retryTestPolicy()
	correlation := retryTestCorrelation("opens-circuit", "provider-opens-circuit")
	state := ProviderRetryState{
		Revision: 21, WindowStartedAt: now, AttemptsInWindow: 1,
		ConsecutiveTransient: policy.TransientFailuresToOpen - 1, Phase: CircuitPhase("closed"),
	}

	opened, err := SettleProviderAttempt(now, policy, correlation, state, ProviderOutcome{
		Code: dnsproviderremote.CodeUnavailable, ProviderRequestID: correlation.ProviderRequestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opened.Deferred || opened.Allowed || opened.Rejected ||
		opened.NextState.Phase != CircuitPhase("open") || !opened.NextState.OpenUntil.Equal(now.Add(policy.CircuitOpen)) {
		t.Fatalf("opened decision = %#v", opened)
	}

	blocked, err := ReserveProviderAttempt(now.Add(time.Second), policy,
		retryTestCorrelation("blocked-by-open", "provider-blocked"), opened.NextState)
	if err != nil {
		t.Fatal(err)
	}
	if !blocked.Deferred || blocked.Allowed || !blocked.NotBefore.Equal(opened.NextState.OpenUntil) ||
		string(blocked.Reason) != "provider_circuit_open" {
		t.Fatalf("open circuit decision = %#v", blocked)
	}

	probeCorrelation := retryTestCorrelation("half-open-probe", "provider-probe")
	probe, err := ReserveProviderAttempt(opened.NextState.OpenUntil, policy, probeCorrelation, opened.NextState)
	if err != nil {
		t.Fatal(err)
	}
	if !probe.Allowed || probe.NextState.Phase != CircuitPhase("half_open") ||
		probe.NextState.ProbeOperationID != probeCorrelation.OperationID {
		t.Fatalf("half-open probe decision = %#v", probe)
	}

	second, err := ReserveProviderAttempt(opened.NextState.OpenUntil, policy,
		retryTestCorrelation("second-half-open", "provider-second"), probe.NextState)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Deferred || second.Allowed || second.Rejected || string(second.Reason) != "provider_half_open_probe_in_flight" {
		t.Fatalf("second half-open decision = %#v, want one probe only", second)
	}

	recovered, err := SettleProviderAttempt(opened.NextState.OpenUntil, policy, probeCorrelation,
		probe.NextState, ProviderOutcome{Success: true, ProviderRequestID: probeCorrelation.ProviderRequestID})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.NextState.Phase != CircuitPhase("closed") || recovered.NextState.ConsecutiveTransient != 0 ||
		recovered.NextState.ProbeOperationID != "" {
		t.Fatalf("recovered circuit = %#v", recovered.NextState)
	}
}

func TestProviderRetryCredentialFailureIsPermanentAndUnknownFailsClosed(t *testing.T) {
	now := retryTestNow()
	policy := retryTestPolicy()
	correlation := retryTestCorrelation("failure-classification", "provider-failure")
	state := ProviderRetryState{Revision: 31, WindowStartedAt: now, Phase: CircuitPhase("closed")}

	credential := ProviderOutcomeFromError(&dnsproviderremote.Error{
		Code: dnsproviderremote.CodeCredentialsRejected, RetryAfter: time.Minute,
	})
	rejected, err := SettleProviderAttempt(now, policy, correlation, state, credential)
	if err != nil {
		t.Fatal(err)
	}
	if !rejected.Rejected || rejected.Allowed || rejected.Deferred || !rejected.NotBefore.IsZero() ||
		string(rejected.Reason) != "provider_credentials_rejected" ||
		rejected.NextState.Phase != CircuitPhase("closed") || rejected.NextState.ConsecutiveTransient != 0 {
		t.Fatalf("credential decision = %#v, want permanent zero-retry rejection", rejected)
	}

	unknownOutcome := ProviderOutcomeFromError(errors.New("unclassified provider failure"))
	if unknownOutcome.Success || !unknownOutcome.Unknown {
		t.Fatalf("unknown outcome = %#v, want fail-closed classification", unknownOutcome)
	}
	unknown, err := SettleProviderAttempt(now, policy, correlation, state, unknownOutcome)
	if err != nil {
		t.Fatal(err)
	}
	if unknown.Allowed || !unknown.Rejected || unknown.Deferred || string(unknown.Reason) != "provider_unknown_failure" {
		t.Fatalf("unknown decision = %#v, want fail-closed rejection", unknown)
	}
}

func TestSelectFairProviderAttemptsIsStableAndDoesNotStarveZones(t *testing.T) {
	now := retryTestNow()
	zoneA := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	zoneB := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	zoneC := uuid.MustParse("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
	candidates := []ProviderAttempt{
		{Correlation: retryTestCorrelationForZone("a-2", zoneA), ReadyAt: now.Add(-time.Second)},
		{Correlation: retryTestCorrelationForZone("c-1", zoneC), ReadyAt: now.Add(time.Minute)},
		{Correlation: retryTestCorrelationForZone("b-1", zoneB), ReadyAt: now.Add(-time.Second)},
		{Correlation: retryTestCorrelationForZone("a-1", zoneA), ReadyAt: now.Add(-2 * time.Second)},
	}

	first, err := SelectFairProviderAttempts(now, uuid.Nil, candidates, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SelectFairProviderAttempts(now, uuid.Nil, []ProviderAttempt{
		candidates[3], candidates[1], candidates[0], candidates[2],
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("selected lengths = (%d,%d), want two ready zones", len(first), len(second))
	}
	if first[0].Correlation != second[0].Correlation || first[1].Correlation != second[1].Correlation {
		t.Fatalf("selection is input-order dependent: first=%#v second=%#v", first, second)
	}
	if first[0].Correlation.ZoneID == first[1].Correlation.ZoneID || first[0].Correlation.ZoneID == zoneC ||
		first[1].Correlation.ZoneID == zoneC {
		t.Fatalf("selection = %#v, want one ready operation from each of two zones", first)
	}

	rotated, err := SelectFairProviderAttempts(now, zoneA, candidates, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated) != 1 || rotated[0].Correlation.ZoneID != zoneB {
		t.Fatalf("rotated selection = %#v, want zone B after zone A", rotated)
	}
}

func retryTestPolicy() ProviderRetryPolicy {
	return ProviderRetryPolicy{
		BaseDelay: 5 * time.Second, MaxDelay: time.Hour, BudgetWindow: time.Minute,
		CircuitOpen: 2 * time.Minute, AttemptsPerZone: 2, TransientFailuresToOpen: 2,
	}
}

func retryTestNow() time.Time {
	return time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
}

func retryTestCorrelation(operationID, providerRequestID string) ProviderCorrelation {
	return ProviderCorrelation{
		TenantID:    uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ScopeID:     uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ProviderID:  uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ZoneID:      uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		OperationID: operationID, ClientRequestID: "client-" + operationID,
		ProviderRequestID: providerRequestID, Attempt: 1,
	}
}

func retryTestCorrelationForZone(operationID string, zoneID uuid.UUID) ProviderCorrelation {
	correlation := retryTestCorrelation(operationID, "provider-"+operationID)
	correlation.ZoneID = zoneID
	return correlation
}
