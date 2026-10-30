package analytics

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

const (
	AnalyticsWatermarkSchemaVersionV1   uint16 = 1
	AnalyticsWatermarkKindAccess               = AccessEnvelopeType
	AnalyticsWatermarkKindSecurity             = SecurityEnvelopeType
	analyticsWatermarkMaxRevisionWindow        = 24 * time.Hour
)

var (
	ErrAnalyticsWatermarkInvalidRequest       = errors.New("invalid analytics watermark request")
	ErrAnalyticsWatermarkInvalidDecision      = errors.New("invalid analytics watermark decision")
	ErrAnalyticsWatermarkUnavailable          = errors.New("analytics watermark authority unavailable")
	ErrAnalyticsWatermarkFinalized            = errors.New("analytics watermark finalized window")
	ErrAnalyticsWatermarkLateRevisionExceeded = errors.New("analytics watermark late revision exceeds bound")
	ErrAnalyticsWatermarkOutOfOrder           = errors.New("analytics watermark event is out of order")
	ErrAnalyticsWatermarkConflict             = errors.New("analytics watermark receipt digest conflict")
)

const (
	AnalyticsWatermarkReasonBaselineOff           = "baseline_off"
	AnalyticsWatermarkReasonAccepted              = "accepted"
	AnalyticsWatermarkReasonReplay                = "replay"
	AnalyticsWatermarkReasonLateRevision          = "late_revision"
	AnalyticsWatermarkReasonFinalized             = "finalized_window"
	AnalyticsWatermarkReasonLateRevisionExceeded  = "late_revision_exceeded"
	AnalyticsWatermarkReasonOutOfOrder            = "out_of_order"
	AnalyticsWatermarkReasonDigestConflict        = "digest_conflict"
	AnalyticsWatermarkReasonAuthorityUnavailable  = "authority_unavailable"
	AnalyticsWatermarkReasonDependencyUnknown     = "dependency_unknown"
	AnalyticsWatermarkReasonDependencyUnavailable = "dependency_unavailable"
	AnalyticsWatermarkReasonTooLate               = "too_late"
)

type AnalyticsWatermarkOutcomeV1 uint8

const (
	AnalyticsWatermarkOutcomeRejected AnalyticsWatermarkOutcomeV1 = iota
	AnalyticsWatermarkOutcomeBaselineOff
	AnalyticsWatermarkOutcomeAccepted
	AnalyticsWatermarkOutcomeReplay
	AnalyticsWatermarkOutcomeLateRevision
)

type AnalyticsWatermarkPolicyV1 struct {
	Enabled         bool
	MaxLateRevision time.Duration
}

type AnalyticsWatermarkDependencyStateV1 string

const (
	AnalyticsWatermarkDependencyUnknown     AnalyticsWatermarkDependencyStateV1 = "unknown"
	AnalyticsWatermarkDependencyReady       AnalyticsWatermarkDependencyStateV1 = "ready"
	AnalyticsWatermarkDependencyUnavailable AnalyticsWatermarkDependencyStateV1 = "unavailable"
)

type AnalyticsWatermarkKeyV1 struct {
	TenantID       string
	InstallationID string
	Kind           string
}

type AnalyticsWatermarkStateV1 struct {
	Key                       AnalyticsWatermarkKeyV1
	Watermark                 time.Time
	FinalizedThrough          time.Time
	Revision                  uint64
	LastEventAt               time.Time
	LastReceiptIdentitySHA256 [sha256.Size]byte
	LastEventDigestSHA256     [sha256.Size]byte
}

type AnalyticsWatermarkRequestV1 struct {
	Policy          AnalyticsWatermarkPolicyV1
	DependencyState AnalyticsWatermarkDependencyStateV1
	Key             AnalyticsWatermarkKeyV1
	OccurredAt      time.Time
	Receipt         IngestReceiptV1
	LastKnownGood   AnalyticsWatermarkStateV1
}

type AnalyticsWatermarkDecisionV1 struct {
	Outcome               AnalyticsWatermarkOutcomeV1
	Reason                string
	DependencyState       AnalyticsWatermarkDependencyStateV1
	State                 AnalyticsWatermarkStateV1
	LastKnownGood         AnalyticsWatermarkStateV1
	ReceiptIdentitySHA256 [sha256.Size]byte
	EventDigestSHA256     [sha256.Size]byte
}

type AnalyticsWatermarkEventV1 struct {
	Kind            string
	EventID         string
	OccurredAt      time.Time
	CanonicalDigest [sha256.Size]byte
}

type AnalyticsWatermarkBatchRequestV1 struct {
	Policy          AnalyticsWatermarkPolicyV1
	DependencyState AnalyticsWatermarkDependencyStateV1
	Key             AnalyticsWatermarkKeyV1
	Receipt         IngestReceiptV1
	LastKnownGood   AnalyticsWatermarkStateV1
	Events          []AnalyticsWatermarkEventV1
}

type AnalyticsWatermarkEventDecisionV1 struct {
	Kind       string
	EventID    string
	OccurredAt time.Time
	Outcome    AnalyticsWatermarkOutcomeV1
	Reason     string
}

type AnalyticsWatermarkBatchDecisionV1 struct {
	DependencyState AnalyticsWatermarkDependencyStateV1
	Events          []AnalyticsWatermarkEventDecisionV1
	MaxOccurredAt   time.Time
	State           AnalyticsWatermarkStateV1
	LastKnownGood   AnalyticsWatermarkStateV1
}

// AnalyticsWatermarkAuthorityV1 is implemented by the durable PG transaction.
// DecideAndCommit must fence the finalized window and receipt identity before
// returning; this package intentionally provides no in-memory implementation.
type AnalyticsWatermarkAuthorityV1 interface {
	DecideAndCommit(context.Context, AnalyticsWatermarkRequestV1) (AnalyticsWatermarkDecisionV1, error)
}

type AnalyticsWatermarkBatchAuthorityV1 interface {
	DecideAndCommitBatch(context.Context, AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error)
}

// AuthorizeAnalyticsWriteV1 is the mandatory pre-ClickHouse write fence. When
// the enhancement is disabled it returns the caller's validated LKG snapshot,
// preserving baseline behavior without inventing a new authority.
func AuthorizeAnalyticsWriteV1(ctx context.Context, authority AnalyticsWatermarkAuthorityV1, request AnalyticsWatermarkRequestV1) (AnalyticsWatermarkDecisionV1, error) {
	if ctx == nil {
		return rejectedAnalyticsWatermarkDecision(request), ErrAnalyticsWatermarkInvalidRequest
	}
	if err := validateAnalyticsWatermarkRequestV1(request); err != nil {
		return rejectedAnalyticsWatermarkDecision(request), err
	}
	if !request.Policy.Enabled {
		if request.LastKnownGood != (AnalyticsWatermarkStateV1{}) {
			if err := validateAnalyticsWatermarkStateV1(request.LastKnownGood, request.Key); err != nil {
				return rejectedAnalyticsWatermarkDecision(request), err
			}
		}
		return AnalyticsWatermarkDecisionV1{
			Outcome:               AnalyticsWatermarkOutcomeBaselineOff,
			Reason:                AnalyticsWatermarkReasonBaselineOff,
			DependencyState:       request.DependencyState,
			State:                 request.LastKnownGood,
			LastKnownGood:         request.LastKnownGood,
			ReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256,
			EventDigestSHA256:     request.Receipt.CanonicalEventSHA256,
		}, nil
	}
	if request.DependencyState != AnalyticsWatermarkDependencyReady {
		reason := AnalyticsWatermarkReasonDependencyUnknown
		if request.DependencyState == AnalyticsWatermarkDependencyUnavailable {
			reason = AnalyticsWatermarkReasonDependencyUnavailable
		}
		return rejectedAnalyticsWatermarkDecisionWithReason(request, reason), ErrAnalyticsWatermarkUnavailable
	}
	if authority == nil {
		return rejectedAnalyticsWatermarkDecision(request), ErrAnalyticsWatermarkUnavailable
	}
	if err := ctx.Err(); err != nil {
		return rejectedAnalyticsWatermarkDecision(request), err
	}
	decision, err := authority.DecideAndCommit(ctx, request)
	if err != nil {
		return rejectedAnalyticsWatermarkDecision(request), mapAnalyticsWatermarkAuthorityError(err)
	}
	if err := ValidateAnalyticsWatermarkDecisionV1(request, decision); err != nil {
		return rejectedAnalyticsWatermarkDecision(request), err
	}
	return decision, nil
}

func AuthorizeAnalyticsWriteBatchV1(ctx context.Context, authority AnalyticsWatermarkBatchAuthorityV1, request AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error) {
	if ctx == nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, ""), ErrAnalyticsWatermarkInvalidRequest
	}
	if err := validateAnalyticsWatermarkBatchRequestV1(request); err != nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, ""), err
	}
	if !request.Policy.Enabled {
		return baselineAnalyticsWatermarkBatchDecision(request), nil
	}
	if request.DependencyState != AnalyticsWatermarkDependencyReady {
		reason := AnalyticsWatermarkReasonDependencyUnknown
		if request.DependencyState == AnalyticsWatermarkDependencyUnavailable {
			reason = AnalyticsWatermarkReasonDependencyUnavailable
		}
		return rejectedAnalyticsWatermarkBatchDecision(request, reason), ErrAnalyticsWatermarkUnavailable
	}
	if authority == nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, AnalyticsWatermarkReasonAuthorityUnavailable), ErrAnalyticsWatermarkUnavailable
	}
	if err := ctx.Err(); err != nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, ""), err
	}
	decision, err := authority.DecideAndCommitBatch(ctx, request)
	if err != nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, watermarkBatchReasonForError(err)), mapAnalyticsWatermarkAuthorityError(err)
	}
	if err := ValidateAnalyticsWatermarkBatchDecisionV1(request, decision); err != nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, ""), err
	}
	return decision, nil
}

func EvaluateAnalyticsWatermarkBatchV1(current AnalyticsWatermarkStateV1, request AnalyticsWatermarkBatchRequestV1) (AnalyticsWatermarkBatchDecisionV1, error) {
	if err := validateAnalyticsWatermarkBatchRequestV1(request); err != nil {
		return rejectedAnalyticsWatermarkBatchDecision(request, ""), err
	}
	if !request.Policy.Enabled {
		return baselineAnalyticsWatermarkBatchDecision(request), nil
	}
	if request.DependencyState != AnalyticsWatermarkDependencyReady {
		reason := AnalyticsWatermarkReasonDependencyUnknown
		if request.DependencyState == AnalyticsWatermarkDependencyUnavailable {
			reason = AnalyticsWatermarkReasonDependencyUnavailable
		}
		return rejectedAnalyticsWatermarkBatchDecision(request, reason), ErrAnalyticsWatermarkUnavailable
	}
	if current != (AnalyticsWatermarkStateV1{}) {
		if err := validateAnalyticsWatermarkStateV1(current, request.Key); err != nil {
			return rejectedAnalyticsWatermarkBatchDecision(request, ""), err
		}
	}
	maxOccurred := maxAnalyticsWatermarkEventTime(request.Events)
	if current != (AnalyticsWatermarkStateV1{}) && current.LastReceiptIdentitySHA256 == request.Receipt.ReceiptIdentitySHA256 &&
		current.LastEventDigestSHA256 == request.Receipt.CanonicalEventSHA256 {
		outcomes := make([]AnalyticsWatermarkEventDecisionV1, len(request.Events))
		for index, event := range request.Events {
			outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeReplay, Reason: AnalyticsWatermarkReasonReplay}
		}
		return AnalyticsWatermarkBatchDecisionV1{DependencyState: AnalyticsWatermarkDependencyReady, Events: outcomes, MaxOccurredAt: maxOccurred, State: current, LastKnownGood: request.LastKnownGood}, nil
	}

	seen := make(map[string][sha256.Size]byte, len(request.Events))
	outcomes := make([]AnalyticsWatermarkEventDecisionV1, len(request.Events))
	latenessReference := maxOccurred
	if current.Watermark.After(latenessReference) {
		latenessReference = current.Watermark
	}
	for index, event := range request.Events {
		if previous, ok := seen[event.EventID]; ok {
			if previous != event.CanonicalDigest {
				return rejectedAnalyticsWatermarkBatchDecision(request, AnalyticsWatermarkReasonDigestConflict), ErrAnalyticsWatermarkConflict
			}
			outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeReplay, Reason: AnalyticsWatermarkReasonReplay}
			continue
		}
		seen[event.EventID] = event.CanonicalDigest
		if !current.FinalizedThrough.IsZero() && !event.OccurredAt.After(current.FinalizedThrough) {
			return rejectedAnalyticsWatermarkBatchDecision(request, AnalyticsWatermarkReasonFinalized), ErrAnalyticsWatermarkFinalized
		}
		age := latenessReference.Sub(event.OccurredAt)
		if age > request.Policy.MaxLateRevision {
			return rejectedAnalyticsWatermarkBatchDecision(request, AnalyticsWatermarkReasonTooLate), ErrAnalyticsWatermarkLateRevisionExceeded
		}
		if age > 0 {
			outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeLateRevision, Reason: AnalyticsWatermarkReasonLateRevision}
		} else {
			outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeAccepted, Reason: AnalyticsWatermarkReasonAccepted}
		}
	}
	next := advanceAnalyticsWatermarkBatchState(current, request, maxOccurred)
	return AnalyticsWatermarkBatchDecisionV1{DependencyState: AnalyticsWatermarkDependencyReady, Events: outcomes, MaxOccurredAt: maxOccurred, State: next, LastKnownGood: request.LastKnownGood}, nil
}

func ValidateAnalyticsWatermarkBatchDecisionV1(request AnalyticsWatermarkBatchRequestV1, decision AnalyticsWatermarkBatchDecisionV1) error {
	if err := validateAnalyticsWatermarkBatchRequestV1(request); err != nil {
		return err
	}
	if decision.DependencyState != AnalyticsWatermarkDependencyReady || decision.LastKnownGood != request.LastKnownGood || len(decision.Events) != len(request.Events) {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	if decision.State.Key != request.Key || validateAnalyticsWatermarkStateV1(decision.State, request.Key) != nil {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	maxOccurred := maxAnalyticsWatermarkEventTime(request.Events)
	if decision.MaxOccurredAt != maxOccurred {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	for index, event := range request.Events {
		outcome := decision.Events[index]
		if outcome.Kind != event.Kind || outcome.EventID != event.EventID || !outcome.OccurredAt.Equal(event.OccurredAt) {
			return ErrAnalyticsWatermarkInvalidDecision
		}
		switch outcome.Outcome {
		case AnalyticsWatermarkOutcomeAccepted:
			if outcome.Reason != AnalyticsWatermarkReasonAccepted {
				return ErrAnalyticsWatermarkInvalidDecision
			}
		case AnalyticsWatermarkOutcomeReplay:
			if outcome.Reason != AnalyticsWatermarkReasonReplay {
				return ErrAnalyticsWatermarkInvalidDecision
			}
		case AnalyticsWatermarkOutcomeLateRevision:
			if outcome.Reason != AnalyticsWatermarkReasonLateRevision {
				return ErrAnalyticsWatermarkInvalidDecision
			}
		default:
			return ErrAnalyticsWatermarkInvalidDecision
		}
	}
	return nil
}

func validateAnalyticsWatermarkBatchRequestV1(request AnalyticsWatermarkBatchRequestV1) error {
	if len(request.Events) == 0 {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	maxOccurred := maxAnalyticsWatermarkEventTime(request.Events)
	base := AnalyticsWatermarkRequestV1{Policy: request.Policy, DependencyState: request.DependencyState, Key: request.Key,
		OccurredAt: maxOccurred, Receipt: request.Receipt, LastKnownGood: request.LastKnownGood}
	if err := validateAnalyticsWatermarkRequestV1(base); err != nil {
		return err
	}
	for _, event := range request.Events {
		if event.Kind != request.Key.Kind || !validBatchID(event.EventID) || event.OccurredAt.IsZero() || event.OccurredAt.Location() != time.UTC || event.CanonicalDigest == ([sha256.Size]byte{}) {
			return ErrAnalyticsWatermarkInvalidRequest
		}
	}
	return nil
}

func baselineAnalyticsWatermarkBatchDecision(request AnalyticsWatermarkBatchRequestV1) AnalyticsWatermarkBatchDecisionV1 {
	outcomes := make([]AnalyticsWatermarkEventDecisionV1, len(request.Events))
	for index, event := range request.Events {
		outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeBaselineOff, Reason: AnalyticsWatermarkReasonBaselineOff}
	}
	return AnalyticsWatermarkBatchDecisionV1{DependencyState: request.DependencyState, Events: outcomes, MaxOccurredAt: maxAnalyticsWatermarkEventTime(request.Events), State: request.LastKnownGood, LastKnownGood: request.LastKnownGood}
}

func rejectedAnalyticsWatermarkBatchDecision(request AnalyticsWatermarkBatchRequestV1, reason string) AnalyticsWatermarkBatchDecisionV1 {
	outcomes := make([]AnalyticsWatermarkEventDecisionV1, len(request.Events))
	for index, event := range request.Events {
		outcomes[index] = AnalyticsWatermarkEventDecisionV1{Kind: event.Kind, EventID: event.EventID, OccurredAt: event.OccurredAt, Outcome: AnalyticsWatermarkOutcomeRejected, Reason: reason}
	}
	return AnalyticsWatermarkBatchDecisionV1{DependencyState: request.DependencyState, Events: outcomes, State: request.LastKnownGood, LastKnownGood: request.LastKnownGood}
}

func advanceAnalyticsWatermarkBatchState(current AnalyticsWatermarkStateV1, request AnalyticsWatermarkBatchRequestV1, maxOccurred time.Time) AnalyticsWatermarkStateV1 {
	next := current
	if next.Revision == 0 {
		next.Revision = 1
	} else {
		next.Revision++
	}
	next.Key = request.Key
	if next.Watermark.IsZero() || maxOccurred.After(next.Watermark) {
		next.Watermark = maxOccurred
	}
	candidateFinalized := maxOccurred.Add(-request.Policy.MaxLateRevision)
	if next.FinalizedThrough.IsZero() || candidateFinalized.After(next.FinalizedThrough) {
		next.FinalizedThrough = candidateFinalized
	}
	if next.LastEventAt.IsZero() || maxOccurred.After(next.LastEventAt) {
		next.LastEventAt = maxOccurred
	}
	next.LastReceiptIdentitySHA256 = request.Receipt.ReceiptIdentitySHA256
	next.LastEventDigestSHA256 = request.Receipt.CanonicalEventSHA256
	return next
}

func maxAnalyticsWatermarkEventTime(events []AnalyticsWatermarkEventV1) time.Time {
	var maximum time.Time
	for _, event := range events {
		if maximum.IsZero() || event.OccurredAt.After(maximum) {
			maximum = event.OccurredAt
		}
	}
	return maximum
}

func watermarkBatchReasonForError(err error) string {
	switch {
	case errors.Is(err, ErrAnalyticsWatermarkConflict):
		return AnalyticsWatermarkReasonDigestConflict
	case errors.Is(err, ErrAnalyticsWatermarkFinalized):
		return AnalyticsWatermarkReasonFinalized
	case errors.Is(err, ErrAnalyticsWatermarkLateRevisionExceeded):
		return AnalyticsWatermarkReasonTooLate
	case errors.Is(err, ErrAnalyticsWatermarkUnavailable):
		return AnalyticsWatermarkReasonAuthorityUnavailable
	default:
		return ""
	}
}

// EvaluateAnalyticsWatermarkV1 is a storage-free decision kernel for the
// durable authority transaction. It never persists or retains state itself.
func EvaluateAnalyticsWatermarkV1(current AnalyticsWatermarkStateV1, request AnalyticsWatermarkRequestV1) (AnalyticsWatermarkDecisionV1, error) {
	if !request.Policy.Enabled {
		return AuthorizeAnalyticsWriteV1(context.Background(), nil, request)
	}
	if err := validateAnalyticsWatermarkRequestV1(request); err != nil {
		return rejectedAnalyticsWatermarkDecision(request), err
	}
	if request.DependencyState != AnalyticsWatermarkDependencyReady {
		reason := AnalyticsWatermarkReasonDependencyUnknown
		if request.DependencyState == AnalyticsWatermarkDependencyUnavailable {
			reason = AnalyticsWatermarkReasonDependencyUnavailable
		}
		return rejectedAnalyticsWatermarkDecisionWithReason(request, reason), ErrAnalyticsWatermarkUnavailable
	}
	if current != (AnalyticsWatermarkStateV1{}) {
		if err := validateAnalyticsWatermarkStateV1(current, request.Key); err != nil {
			return rejectedAnalyticsWatermarkDecision(request), err
		}
		if current.LastReceiptIdentitySHA256 != ([sha256.Size]byte{}) {
			if current.LastReceiptIdentitySHA256 == request.Receipt.ReceiptIdentitySHA256 {
				if current.LastEventDigestSHA256 != request.Receipt.CanonicalEventSHA256 {
					return rejectedAnalyticsWatermarkDecisionWithReason(request, AnalyticsWatermarkReasonDigestConflict), ErrAnalyticsWatermarkConflict
				}
				return analyticsWatermarkDecision(request, AnalyticsWatermarkOutcomeReplay, AnalyticsWatermarkReasonReplay, current), nil
			}
		}
		if !current.FinalizedThrough.IsZero() && !request.OccurredAt.After(current.FinalizedThrough) {
			return rejectedAnalyticsWatermarkDecisionWithReason(request, AnalyticsWatermarkReasonFinalized), ErrAnalyticsWatermarkFinalized
		}
		if !current.Watermark.IsZero() && request.OccurredAt.Before(current.Watermark) {
			age := current.Watermark.Sub(request.OccurredAt)
			if age > request.Policy.MaxLateRevision {
				return rejectedAnalyticsWatermarkDecisionWithReason(request, AnalyticsWatermarkReasonLateRevisionExceeded), ErrAnalyticsWatermarkLateRevisionExceeded
			}
			if age == 0 {
				return rejectedAnalyticsWatermarkDecisionWithReason(request, AnalyticsWatermarkReasonOutOfOrder), ErrAnalyticsWatermarkOutOfOrder
			}
			return analyticsWatermarkDecision(request, AnalyticsWatermarkOutcomeLateRevision, AnalyticsWatermarkReasonLateRevision, advanceAnalyticsWatermarkState(current, request)), nil
		}
	}
	return analyticsWatermarkDecision(request, AnalyticsWatermarkOutcomeAccepted, AnalyticsWatermarkReasonAccepted, advanceAnalyticsWatermarkState(current, request)), nil
}

func ValidateAnalyticsWatermarkDecisionV1(request AnalyticsWatermarkRequestV1, decision AnalyticsWatermarkDecisionV1) error {
	if err := validateAnalyticsWatermarkRequestV1(request); err != nil {
		return err
	}
	if decision.Outcome != AnalyticsWatermarkOutcomeAccepted && decision.Outcome != AnalyticsWatermarkOutcomeReplay && decision.Outcome != AnalyticsWatermarkOutcomeLateRevision {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	if decision.ReceiptIdentitySHA256 != request.Receipt.ReceiptIdentitySHA256 || decision.EventDigestSHA256 != request.Receipt.CanonicalEventSHA256 {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	if decision.State.Key != request.Key || validateAnalyticsWatermarkStateV1(decision.State, request.Key) != nil {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	if decision.DependencyState != AnalyticsWatermarkDependencyReady || decision.LastKnownGood != request.LastKnownGood {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	wantReason := map[AnalyticsWatermarkOutcomeV1]string{
		AnalyticsWatermarkOutcomeAccepted:     AnalyticsWatermarkReasonAccepted,
		AnalyticsWatermarkOutcomeReplay:       AnalyticsWatermarkReasonReplay,
		AnalyticsWatermarkOutcomeLateRevision: AnalyticsWatermarkReasonLateRevision,
	}[decision.Outcome]
	if decision.Reason != wantReason {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	return nil
}

func CanonicalAccessEventDigestV1(event AccessEvent) ([sha256.Size]byte, error) {
	if validateAccessEvent(event) != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	encoded, err := canonicalJSONV1(canonicalAccessEventsV1([]AccessEvent{event})[0])
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func CanonicalSecurityEventDigestV1(event SecurityEvent) ([sha256.Size]byte, error) {
	if validateSecurityEvent(event) != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	encoded, err := canonicalJSONV1(canonicalSecurityEventsV1([]SecurityEvent{event})[0])
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validateAnalyticsWatermarkRequestV1(request AnalyticsWatermarkRequestV1) error {
	if err := validateAnalyticsWatermarkKeyV1(request.Key, request.OccurredAt); err != nil {
		return err
	}
	if request.Policy.Enabled && (request.Policy.MaxLateRevision <= 0 || request.Policy.MaxLateRevision > analyticsWatermarkMaxRevisionWindow) {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	if request.DependencyState != AnalyticsWatermarkDependencyUnknown && request.DependencyState != AnalyticsWatermarkDependencyReady && request.DependencyState != AnalyticsWatermarkDependencyUnavailable {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	if request.LastKnownGood != (AnalyticsWatermarkStateV1{}) {
		if err := validateAnalyticsWatermarkStateV1(request.LastKnownGood, request.Key); err != nil {
			return ErrAnalyticsWatermarkInvalidRequest
		}
	}
	receipt := request.Receipt
	if receipt.SchemaVersion != AnalyticsWatermarkSchemaVersionV1 || !validBatchID(receipt.MessageID) ||
		receipt.Key.InstallationID != request.Key.InstallationID || receipt.CanonicalEventSHA256 == ([sha256.Size]byte{}) ||
		receipt.ReceiptIdentitySHA256 == ([sha256.Size]byte{}) || receipt.ClickHouseToken == "" {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	return nil
}

func validateAnalyticsWatermarkKeyV1(key AnalyticsWatermarkKeyV1, occurredAt time.Time) error {
	if !validUUID(key.TenantID) || nilUUID(key.TenantID) || !validBatchID(key.InstallationID) ||
		(key.Kind != AnalyticsWatermarkKindAccess && key.Kind != AnalyticsWatermarkKindSecurity) ||
		occurredAt.IsZero() || occurredAt.Location() != time.UTC {
		return ErrAnalyticsWatermarkInvalidRequest
	}
	return nil
}

func validateAnalyticsWatermarkStateV1(state AnalyticsWatermarkStateV1, key AnalyticsWatermarkKeyV1) error {
	if state.Key != key || state.Revision == 0 || state.Watermark.IsZero() || state.Watermark.Location() != time.UTC ||
		(!state.FinalizedThrough.IsZero() && (state.FinalizedThrough.Location() != time.UTC || state.FinalizedThrough.After(state.Watermark))) ||
		(!state.LastEventAt.IsZero() && (state.LastEventAt.Location() != time.UTC || state.LastEventAt.After(state.Watermark))) ||
		state.LastReceiptIdentitySHA256 == ([sha256.Size]byte{}) || state.LastEventDigestSHA256 == ([sha256.Size]byte{}) {
		return ErrAnalyticsWatermarkInvalidDecision
	}
	return nil
}

func analyticsWatermarkDecision(request AnalyticsWatermarkRequestV1, outcome AnalyticsWatermarkOutcomeV1, reason string, state AnalyticsWatermarkStateV1) AnalyticsWatermarkDecisionV1 {
	return AnalyticsWatermarkDecisionV1{
		Outcome: outcome, Reason: reason, DependencyState: AnalyticsWatermarkDependencyReady, State: state, LastKnownGood: request.LastKnownGood,
		ReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256,
		EventDigestSHA256:     request.Receipt.CanonicalEventSHA256,
	}
}

func rejectedAnalyticsWatermarkDecision(request AnalyticsWatermarkRequestV1) AnalyticsWatermarkDecisionV1 {
	return rejectedAnalyticsWatermarkDecisionWithReason(request, "")
}

func rejectedAnalyticsWatermarkDecisionWithReason(request AnalyticsWatermarkRequestV1, reason string) AnalyticsWatermarkDecisionV1 {
	return AnalyticsWatermarkDecisionV1{
		Outcome: AnalyticsWatermarkOutcomeRejected, Reason: reason, DependencyState: request.DependencyState, State: request.LastKnownGood, LastKnownGood: request.LastKnownGood,
		ReceiptIdentitySHA256: request.Receipt.ReceiptIdentitySHA256,
		EventDigestSHA256:     request.Receipt.CanonicalEventSHA256,
	}
}

func advanceAnalyticsWatermarkState(current AnalyticsWatermarkStateV1, request AnalyticsWatermarkRequestV1) AnalyticsWatermarkStateV1 {
	next := current
	if next.Revision == 0 {
		next.Revision = 1
	} else {
		next.Revision++
	}
	next.Key = request.Key
	if next.Watermark.IsZero() || request.OccurredAt.After(next.Watermark) {
		next.Watermark = request.OccurredAt
	}
	if next.LastEventAt.IsZero() || request.OccurredAt.After(next.LastEventAt) {
		next.LastEventAt = request.OccurredAt
	}
	next.LastReceiptIdentitySHA256 = request.Receipt.ReceiptIdentitySHA256
	next.LastEventDigestSHA256 = request.Receipt.CanonicalEventSHA256
	return next
}

func mapAnalyticsWatermarkAuthorityError(err error) error {
	switch {
	case errors.Is(err, ErrAnalyticsWatermarkConflict), errors.Is(err, ErrAnalyticsWatermarkFinalized),
		errors.Is(err, ErrAnalyticsWatermarkLateRevisionExceeded), errors.Is(err, ErrAnalyticsWatermarkOutOfOrder):
		return err
	default:
		return ErrAnalyticsWatermarkUnavailable
	}
}
