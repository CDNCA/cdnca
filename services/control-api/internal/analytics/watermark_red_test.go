package analytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"
)

type analyticsWatermarkAuthorityStubV1 struct {
	decision AnalyticsWatermarkDecisionV1
	err      error
	calls    int
	request  AnalyticsWatermarkRequestV1
}

func (stub *analyticsWatermarkAuthorityStubV1) DecideAndCommit(_ context.Context, request AnalyticsWatermarkRequestV1) (AnalyticsWatermarkDecisionV1, error) {
	stub.calls++
	stub.request = request
	return stub.decision, stub.err
}

func TestAnalyticsWatermarkWriteFenceValidatesDurableDecisionAndReplay(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	state := analyticsWatermarkStateV1(request, request.OccurredAt, 7)
	stub := &analyticsWatermarkAuthorityStubV1{
		decision: AnalyticsWatermarkDecisionV1{
			Outcome:               AnalyticsWatermarkOutcomeAccepted,
			Reason:                AnalyticsWatermarkReasonAccepted,
			DependencyState:       AnalyticsWatermarkDependencyReady,
			State:                 state,
			LastKnownGood:         request.LastKnownGood,
			ReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256,
			EventDigestSHA256:     request.Receipt.CanonicalEventSHA256,
		},
	}

	decision, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
	if err != nil || decision.Outcome != AnalyticsWatermarkOutcomeAccepted || stub.calls != 1 {
		t.Fatalf("accepted fence decision=%#v err=%v calls=%d", decision, err, stub.calls)
	}
	if stub.request.Key != request.Key || stub.request.Receipt.ReceiptIdentitySHA256 != request.Receipt.ReceiptIdentitySHA256 {
		t.Fatalf("authority request=%#v want key=%#v receipt=%x", stub.request, request.Key, request.Receipt.ReceiptIdentitySHA256)
	}

	stub.decision.Outcome = AnalyticsWatermarkOutcomeReplay
	stub.decision.Reason = AnalyticsWatermarkReasonReplay
	decision, err = AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
	if err != nil || decision.Outcome != AnalyticsWatermarkOutcomeReplay || stub.calls != 2 {
		t.Fatalf("replay fence decision=%#v err=%v calls=%d", decision, err, stub.calls)
	}
}

func TestAnalyticsWatermarkWriteFenceRejectsScopeAndDigestConflictsBeforeAuthority(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	stub := &analyticsWatermarkAuthorityStubV1{}

	for name, mutate := range map[string]func(*AnalyticsWatermarkRequestV1){
		"tenant scope": func(value *AnalyticsWatermarkRequestV1) {
			value.Key.TenantID = "not-a-tenant"
		},
		"installation scope": func(value *AnalyticsWatermarkRequestV1) {
			value.Key.InstallationID = "other-installation"
		},
		"kind": func(value *AnalyticsWatermarkRequestV1) {
			value.Key.Kind = "unknown.v1"
		},
		"receipt digest": func(value *AnalyticsWatermarkRequestV1) {
			value.Receipt.CanonicalEventSHA256 = [sha256.Size]byte{}
		},
		"receipt installation": func(value *AnalyticsWatermarkRequestV1) {
			value.Receipt.Key.InstallationID = "other-installation"
		},
	} {
		candidate := request
		mutate(&candidate)
		if _, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, candidate); !errors.Is(err, ErrAnalyticsWatermarkInvalidRequest) {
			t.Errorf("%s error=%v want %v", name, err, ErrAnalyticsWatermarkInvalidRequest)
		}
	}
	if stub.calls != 0 {
		t.Fatalf("invalid requests reached authority %d times", stub.calls)
	}
}

func TestAnalyticsWatermarkWriteFencePreservesBaselineLKGAndFailsClosedOnDependency(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	request.Policy.Enabled = false
	request.LastKnownGood = analyticsWatermarkStateV1(request, request.OccurredAt.Add(-time.Minute), 11)
	stub := &analyticsWatermarkAuthorityStubV1{err: errors.New("database secret: should not escape")}
	decision, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
	if err != nil || decision.Outcome != AnalyticsWatermarkOutcomeBaselineOff || decision.Reason != AnalyticsWatermarkReasonBaselineOff || decision.State != request.LastKnownGood || stub.calls != 0 {
		t.Fatalf("baseline decision=%#v err=%v calls=%d", decision, err, stub.calls)
	}

	request.Policy.Enabled = true
	decision, err = AuthorizeAnalyticsWriteV1(context.Background(), nil, request)
	if !errors.Is(err, ErrAnalyticsWatermarkUnavailable) || decision.Outcome != AnalyticsWatermarkOutcomeRejected {
		t.Fatalf("nil authority decision=%#v err=%v", decision, err)
	}
	stub.err = errors.New("database secret: should be mapped")
	decision, err = AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
	if !errors.Is(err, ErrAnalyticsWatermarkUnavailable) || decision.Outcome != AnalyticsWatermarkOutcomeRejected || stub.calls != 1 {
		t.Fatalf("dependency decision=%#v err=%v calls=%d", decision, err, stub.calls)
	}
}

func TestAnalyticsWatermarkDecisionRejectsFinalizedAndUnboundedLateRevision(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	stub := &analyticsWatermarkAuthorityStubV1{}
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "finalized", err: ErrAnalyticsWatermarkFinalized},
		{name: "late revision bound", err: ErrAnalyticsWatermarkLateRevisionExceeded},
		{name: "out of order", err: ErrAnalyticsWatermarkOutOfOrder},
		{name: "digest conflict", err: ErrAnalyticsWatermarkConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub.err = test.err
			decision, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
			if !errors.Is(err, test.err) || decision.Outcome != AnalyticsWatermarkOutcomeRejected {
				t.Fatalf("decision=%#v err=%v want=%v", decision, err, test.err)
			}
		})
	}
}

func TestAnalyticsWatermarkContractBoundsRevisionAndCarriesDependencyLKG(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	request.Policy.MaxLateRevision = 90 * 24 * time.Hour
	state := analyticsWatermarkStateV1(request, request.OccurredAt, 7)
	stub := &analyticsWatermarkAuthorityStubV1{decision: AnalyticsWatermarkDecisionV1{
		Outcome: AnalyticsWatermarkOutcomeAccepted, Reason: AnalyticsWatermarkReasonAccepted,
		DependencyState: AnalyticsWatermarkDependencyReady, State: state, LastKnownGood: request.LastKnownGood,
		ReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256, EventDigestSHA256: request.Receipt.CanonicalEventSHA256,
	}}
	if _, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, request); !errors.Is(err, ErrAnalyticsWatermarkInvalidRequest) {
		t.Errorf("90d late revision error=%v, want %v", err, ErrAnalyticsWatermarkInvalidRequest)
	}

	requestType := reflect.TypeOf(request)
	if _, ok := requestType.FieldByName("DependencyState"); !ok {
		t.Errorf("request lacks stable DependencyState field")
	}
	if _, ok := requestType.FieldByName("LastKnownGood"); !ok {
		t.Errorf("request lacks stable LastKnownGood field")
	}
	decisionType := reflect.TypeOf(AnalyticsWatermarkDecisionV1{})
	if _, ok := decisionType.FieldByName("DependencyState"); !ok {
		t.Errorf("decision lacks stable DependencyState field")
	}
	if _, ok := decisionType.FieldByName("LastKnownGood"); !ok {
		t.Errorf("decision lacks stable LastKnownGood field")
	}
}

func TestAnalyticsWatermarkDependencyFailurePreservesLKGWithoutAuthority(t *testing.T) {
	request := analyticsWatermarkRequestV1(t)
	request.LastKnownGood = analyticsWatermarkStateV1(request, request.OccurredAt, 9)
	stub := &analyticsWatermarkAuthorityStubV1{decision: AnalyticsWatermarkDecisionV1{
		Outcome: AnalyticsWatermarkOutcomeAccepted,
	}}
	for _, dependency := range []AnalyticsWatermarkDependencyStateV1{
		AnalyticsWatermarkDependencyUnknown,
		AnalyticsWatermarkDependencyUnavailable,
	} {
		request.DependencyState = dependency
		decision, err := AuthorizeAnalyticsWriteV1(context.Background(), stub, request)
		if !errors.Is(err, ErrAnalyticsWatermarkUnavailable) || decision.Outcome != AnalyticsWatermarkOutcomeRejected ||
			decision.State != request.LastKnownGood || decision.LastKnownGood != request.LastKnownGood ||
			decision.DependencyState != dependency || stub.calls != 0 {
			t.Errorf("dependency=%q decision=%#v err=%v calls=%d", dependency, decision, err, stub.calls)
		}
	}
}

func analyticsWatermarkRequestV1(t *testing.T) AnalyticsWatermarkRequestV1 {
	t.Helper()
	payload := sha256.Sum256([]byte("watermark-payload"))
	canonical := sha256.Sum256([]byte("watermark-canonical"))
	identity := sha256.Sum256([]byte("watermark-receipt"))
	return AnalyticsWatermarkRequestV1{
		Policy:          AnalyticsWatermarkPolicyV1{Enabled: true, MaxLateRevision: 2 * time.Hour},
		DependencyState: AnalyticsWatermarkDependencyReady,
		Key: AnalyticsWatermarkKeyV1{
			TenantID: "10000000-0000-4000-8000-000000000001", InstallationID: "installation-107", Kind: AccessEnvelopeType,
		},
		OccurredAt: time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC),
		Receipt: IngestReceiptV1{
			SchemaVersion: 1,
			Key:           IngestReceiptKeyV1{InstallationID: "installation-107", HistoryEpoch: "11111111-1111-4111-8111-111111111111", StreamSequence: 107},
			MessageID:     "watermark-message", PayloadSHA256: payload, CanonicalEventSHA256: canonical,
			GenerationSHA256: payload, ReceiptIdentitySHA256: identity, ClickHouseToken: "analytics-history-v1-watermark",
		},
	}
}

func analyticsWatermarkStateV1(request AnalyticsWatermarkRequestV1, watermark time.Time, revision uint64) AnalyticsWatermarkStateV1 {
	return AnalyticsWatermarkStateV1{
		Key: request.Key, Watermark: watermark, FinalizedThrough: watermark.Add(-time.Hour), Revision: revision,
		LastEventAt: watermark, LastReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256,
		LastEventDigestSHA256: request.Receipt.CanonicalEventSHA256,
	}
}
