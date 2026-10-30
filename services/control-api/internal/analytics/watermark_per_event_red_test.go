package analytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestAnalyticsWatermarkPerEventBatchUsesMaxAndBoundsLateEvents(t *testing.T) {
	request := analyticsWatermarkBatchRequestV1(t)
	maxOccurred := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	request.Events = []AnalyticsWatermarkEventV1{
		{Kind: request.Key.Kind, EventID: "event-before-max", OccurredAt: maxOccurred.Add(-time.Minute), CanonicalDigest: sha256.Sum256([]byte("event-before-max"))},
		{Kind: request.Key.Kind, EventID: "event-at-max", OccurredAt: maxOccurred, CanonicalDigest: sha256.Sum256([]byte("event-at-max"))},
	}
	decision, err := EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, request)
	if err != nil || len(decision.Events) != 2 || decision.MaxOccurredAt != maxOccurred ||
		decision.Events[0].Outcome != AnalyticsWatermarkOutcomeLateRevision ||
		decision.Events[1].Outcome != AnalyticsWatermarkOutcomeAccepted ||
		decision.State.Watermark != maxOccurred || decision.State.FinalizedThrough != maxOccurred.Add(-request.Policy.MaxLateRevision) {
		t.Fatalf("batch decision=%#v err=%v", decision, err)
	}
	exact := request
	exact.Events = []AnalyticsWatermarkEventV1{
		{Kind: request.Key.Kind, EventID: "event-exact-bound", OccurredAt: maxOccurred.Add(-request.Policy.MaxLateRevision), CanonicalDigest: sha256.Sum256([]byte("event-exact-bound"))},
		{Kind: request.Key.Kind, EventID: "event-exact-max", OccurredAt: maxOccurred, CanonicalDigest: sha256.Sum256([]byte("event-exact-max"))},
	}
	decision, err = EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, exact)
	if err != nil || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeLateRevision {
		t.Fatalf("exact late bound decision=%#v err=%v", decision, err)
	}
}

func TestAnalyticsWatermarkLKGUsesCurrentWatermarkForLateBounds(t *testing.T) {
	request := analyticsWatermarkBatchRequestV1(t)
	currentWatermark := time.Date(2026, 8, 6, 10, 30, 0, 0, time.UTC)
	current := analyticsWatermarkStateV1(analyticsWatermarkRequestV1(t), currentWatermark, 7)
	current.LastReceiptIdentitySHA256 = sha256.Sum256([]byte("prior-lkg-receipt"))
	current.LastEventDigestSHA256 = sha256.Sum256([]byte("prior-lkg-event"))
	request.LastKnownGood = current
	request.Events = []AnalyticsWatermarkEventV1{{
		Kind: request.Key.Kind, EventID: "event-behind-current-watermark",
		OccurredAt: currentWatermark.Add(-30 * time.Minute), CanonicalDigest: sha256.Sum256([]byte("event-behind-current-watermark")),
	}}

	decision, err := EvaluateAnalyticsWatermarkBatchV1(current, request)
	if err != nil || decision.MaxOccurredAt != request.Events[0].OccurredAt ||
		decision.Events[0].Outcome != AnalyticsWatermarkOutcomeLateRevision || decision.Events[0].Reason != AnalyticsWatermarkReasonLateRevision ||
		decision.State.Watermark != current.Watermark || decision.State.FinalizedThrough != current.FinalizedThrough ||
		decision.State.LastEventAt != current.LastEventAt || decision.State.Revision != current.Revision+1 || decision.LastKnownGood != current {
		t.Fatalf("current watermark late decision=%#v err=%v", decision, err)
	}

	overBoundCurrent := current
	overBoundCurrent.FinalizedThrough = currentWatermark.Add(-request.Policy.MaxLateRevision - time.Hour)
	overBound := request
	overBound.LastKnownGood = overBoundCurrent
	overBound.Events = []AnalyticsWatermarkEventV1{{
		Kind: request.Key.Kind, EventID: "event-beyond-current-watermark-bound",
		OccurredAt: currentWatermark.Add(-request.Policy.MaxLateRevision - time.Minute), CanonicalDigest: sha256.Sum256([]byte("event-beyond-current-watermark-bound")),
	}}
	decision, err = EvaluateAnalyticsWatermarkBatchV1(overBoundCurrent, overBound)
	if !errors.Is(err, ErrAnalyticsWatermarkLateRevisionExceeded) || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeRejected ||
		decision.Events[0].Reason != AnalyticsWatermarkReasonTooLate || decision.State != overBoundCurrent || decision.LastKnownGood != overBoundCurrent {
		t.Fatalf("current watermark over-bound decision=%#v err=%v", decision, err)
	}

	baseline := request
	baseline.Policy.Enabled = false
	decision, err = EvaluateAnalyticsWatermarkBatchV1(current, baseline)
	if err != nil || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeBaselineOff ||
		decision.Events[0].Reason != AnalyticsWatermarkReasonBaselineOff || decision.State != current || decision.LastKnownGood != current {
		t.Fatalf("baseline-off decision=%#v err=%v", decision, err)
	}
}

func TestAnalyticsWatermarkPerEventBatchReplayConflictAndDependencyFailClosed(t *testing.T) {
	request := analyticsWatermarkBatchRequestV1(t)
	occurredAt := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	digest := sha256.Sum256([]byte("duplicate"))
	request.Events = []AnalyticsWatermarkEventV1{
		{Kind: request.Key.Kind, EventID: "duplicate", OccurredAt: occurredAt, CanonicalDigest: digest},
		{Kind: request.Key.Kind, EventID: "duplicate", OccurredAt: occurredAt, CanonicalDigest: digest},
	}
	decision, err := EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, request)
	if err != nil || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeAccepted || decision.Events[1].Outcome != AnalyticsWatermarkOutcomeReplay {
		t.Fatalf("same digest replay decision=%#v err=%v", decision, err)
	}

	request.Events[1].CanonicalDigest[0]++
	decision, err = EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, request)
	if !errors.Is(err, ErrAnalyticsWatermarkConflict) || decision.State != (AnalyticsWatermarkStateV1{}) || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeRejected {
		t.Fatalf("digest conflict decision=%#v err=%v", decision, err)
	}

	request.Events = []AnalyticsWatermarkEventV1{{Kind: request.Key.Kind, EventID: "dependency-event", OccurredAt: occurredAt, CanonicalDigest: digest}}
	request.DependencyState = AnalyticsWatermarkDependencyUnknown
	single := analyticsWatermarkRequestV1(t)
	request.LastKnownGood = analyticsWatermarkStateV1(single, occurredAt.Add(-time.Minute), 3)
	decision, err = AuthorizeAnalyticsWriteBatchV1(context.Background(), nil, request)
	if !errors.Is(err, ErrAnalyticsWatermarkUnavailable) || decision.State != request.LastKnownGood || decision.LastKnownGood != request.LastKnownGood || decision.Events[0].Outcome != AnalyticsWatermarkOutcomeRejected {
		t.Fatalf("dependency decision=%#v err=%v", decision, err)
	}
}

func TestAnalyticsWatermarkPerEventBatchRejectsMalformedAndMixedEvents(t *testing.T) {
	base := analyticsWatermarkBatchRequestV1(t)
	occurredAt := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	validDigest := sha256.Sum256([]byte("valid"))
	for name, event := range map[string]AnalyticsWatermarkEventV1{
		"empty event id": {Kind: base.Key.Kind, OccurredAt: occurredAt, CanonicalDigest: validDigest},
		"wrong kind":     {Kind: AnalyticsWatermarkKindSecurity, EventID: "mixed-kind", OccurredAt: occurredAt, CanonicalDigest: validDigest},
		"non UTC":        {Kind: base.Key.Kind, EventID: "non-utc", OccurredAt: occurredAt.In(time.FixedZone("offset", 3600)), CanonicalDigest: validDigest},
		"zero digest":    {Kind: base.Key.Kind, EventID: "zero-digest", OccurredAt: occurredAt},
	} {
		base.Events = []AnalyticsWatermarkEventV1{event}
		if _, err := EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, base); !errors.Is(err, ErrAnalyticsWatermarkInvalidRequest) {
			t.Errorf("%s error=%v want %v", name, err, ErrAnalyticsWatermarkInvalidRequest)
		}
	}
	base.Events = nil
	if _, err := EvaluateAnalyticsWatermarkBatchV1(AnalyticsWatermarkStateV1{}, base); !errors.Is(err, ErrAnalyticsWatermarkInvalidRequest) {
		t.Fatalf("empty batch error=%v", err)
	}
}

func analyticsWatermarkBatchRequestV1(t *testing.T) AnalyticsWatermarkBatchRequestV1 {
	t.Helper()
	single := analyticsWatermarkRequestV1(t)
	return AnalyticsWatermarkBatchRequestV1{Policy: single.Policy, DependencyState: single.DependencyState, Key: single.Key, Receipt: single.Receipt, LastKnownGood: single.LastKnownGood}
}
