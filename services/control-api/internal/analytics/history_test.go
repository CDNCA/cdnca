package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const canonicalPackageSubscriptionIDV1 = "40000000-0000-4000-8000-000000000001"

func TestIngestHistoryV1ReceiptIdentityReplayAndFixedToken(t *testing.T) {
	generation := authorityGenerationV1()
	decoded := authorityDecodedIngestV1(t)
	receipt, err := NewIngestReceiptV1(generation, 42, decoded)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Key.InstallationID != generation.InstallationID || receipt.Key.NATSDomain != generation.NATSDomain ||
		receipt.Key.StreamName != generation.StreamName || receipt.Key.DurableName != generation.DurableName ||
		receipt.Key.StreamCreatedUnixNano != generation.StreamCreatedUnixNano ||
		receipt.Key.ConsumerCreatedUnixNano != generation.ConsumerCreatedUnixNano ||
		receipt.Key.HistoryEpoch != generation.HistoryEpoch || receipt.Key.StreamSequence != 42 {
		t.Fatalf("receipt key = %#v, generation = %#v", receipt.Key, generation)
	}
	if receipt.MessageID != decoded.MessageID || receipt.PayloadSHA256 != decoded.PayloadDigest ||
		receipt.CanonicalEventSHA256 == ([sha256.Size]byte{}) || receipt.GenerationSHA256 == ([sha256.Size]byte{}) ||
		receipt.ReceiptIdentitySHA256 == ([sha256.Size]byte{}) || receipt.SchemaVersion != 1 {
		t.Fatalf("receipt does not bind payload and canonical event: %#v", receipt)
	}
	// V1 hashes NUL-delimited schema, installation, NATS domain, stream, durable,
	// stream/consumer creation nanos, history epoch, sequence and payload SHA-256 hex.
	const wantToken = "analytics-history-v1-ffb5fed49d695ed2f62c17a26f357e625effbfa563b11a5ae08edb0590f9e41c"
	if receipt.ClickHouseToken != wantToken || ClickHouseIngestTokenV1(receipt) != wantToken {
		t.Fatalf("ClickHouse token = %q / %q, want %q", receipt.ClickHouseToken, ClickHouseIngestTokenV1(receipt), wantToken)
	}

	replay, err := ClassifyIngestReceiptReplayV1(receipt, receipt)
	if err != nil || replay != IngestReceiptReplaySame {
		t.Fatalf("same receipt replay = (%v, %v)", replay, err)
	}
	conflicts := []struct {
		name   string
		mutate func(*IngestReceiptV1)
	}{
		{name: "schema version", mutate: func(value *IngestReceiptV1) { value.SchemaVersion++ }},
		{name: "message ID", mutate: func(value *IngestReceiptV1) { value.MessageID += "-changed" }},
		{name: "payload digest", mutate: func(value *IngestReceiptV1) { value.PayloadSHA256[0]++ }},
		{name: "canonical event digest", mutate: func(value *IngestReceiptV1) { value.CanonicalEventSHA256[0]++ }},
		{name: "ClickHouse token", mutate: func(value *IngestReceiptV1) { value.ClickHouseToken += "-changed" }},
		{name: "generation binding", mutate: func(value *IngestReceiptV1) { value.GenerationSHA256[0]++ }},
		{name: "receipt state identity", mutate: func(value *IngestReceiptV1) { value.ReceiptIdentitySHA256[0]++ }},
	}
	for _, test := range conflicts {
		t.Run("same key conflict/"+test.name, func(t *testing.T) {
			conflict := receipt
			test.mutate(&conflict)
			if conflict.Key != receipt.Key {
				t.Fatalf("%s mutation changed key", test.name)
			}
			if _, err := ClassifyIngestReceiptReplayV1(receipt, conflict); !errors.Is(err, ErrIngestReceiptConflict) {
				t.Fatalf("%s replay error = %v", test.name, err)
			}
		})
	}
	changedGeneration := receipt
	changedGeneration.Key.ConsumerCreatedUnixNano++
	if _, err := ClassifyIngestReceiptReplayV1(receipt, changedGeneration); !errors.Is(err, ErrIngestHistoryGenerationChanged) {
		t.Fatalf("consumer generation replay error = %v", err)
	}

	changedSubscription := decoded
	changedSubscription.PackageSubscriptionID = "40000000-0000-4000-8000-000000000002"
	changedSubscription.AccessEvents[0].PackageSubscriptionID = changedSubscription.PackageSubscriptionID
	changedReceipt, err := NewIngestReceiptV1(generation, 42, changedSubscription)
	if err != nil {
		t.Fatal(err)
	}
	if changedReceipt.CanonicalEventSHA256 == receipt.CanonicalEventSHA256 || changedReceipt.ReceiptIdentitySHA256 == receipt.ReceiptIdentitySHA256 {
		t.Fatal("package subscription identity did not change canonical receipt identity")
	}
	if _, err := ClassifyIngestReceiptReplayV1(receipt, changedReceipt); !errors.Is(err, ErrIngestReceiptConflict) {
		t.Fatalf("package subscription replay error = %v", err)
	}
}

func TestIngestHistoryV1RejectsEveryGenerationAndKeyMismatch(t *testing.T) {
	generation := authorityGenerationV1()
	receipt, err := NewIngestReceiptV1(generation, 42, authorityDecodedIngestV1(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		wantErr error
		mutate  func(*IngestHistoryGenerationV1, *IngestReceiptKeyV1)
	}{
		{name: "installation", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) {
			key.InstallationID = "22222222-2222-4222-8222-222222222222"
		}},
		{name: "NATS domain", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.NATSDomain = "other-domain" }},
		{name: "stream", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.StreamName += "_OTHER" }},
		{name: "durable", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.DurableName += "_other" }},
		{name: "stream created", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.StreamCreatedUnixNano++ }},
		{name: "consumer created", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.ConsumerCreatedUnixNano++ }},
		{name: "history epoch", wantErr: ErrIngestHistoryGenerationChanged, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) {
			key.HistoryEpoch = "44444444-4444-4444-8444-444444444444"
		}},
		{name: "history start", wantErr: ErrInvalidInput, mutate: func(generation *IngestHistoryGenerationV1, _ *IngestReceiptKeyV1) {
			generation.HistoryStartSequence = 43
		}},
		{name: "incompatible sequence", wantErr: ErrInvalidInput, mutate: func(_ *IngestHistoryGenerationV1, key *IngestReceiptKeyV1) { key.StreamSequence = 40 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateGeneration, candidateKey := generation, receipt.Key
			test.mutate(&candidateGeneration, &candidateKey)
			if err := ValidateIngestReceiptKeyV1(candidateGeneration, candidateKey); !errors.Is(err, test.wantErr) {
				t.Fatalf("validation error = %v, want %v; generation=%#v key=%#v", err, test.wantErr, candidateGeneration, candidateKey)
			}
		})
	}
}

func TestCanonicalIngestDigestV1PreservesNullableMapsAndExactNumbers(t *testing.T) {
	base := authorityDecodedIngestV1(t)
	baseDigest, err := CanonicalIngestDigestV1(base)
	if err != nil {
		t.Fatal(err)
	}
	reordered := authorityDecodedIngestV1(t)
	reordered.AccessEvents[0].RequestHeaders = map[string]string{}
	reordered.AccessEvents[0].RequestHeaders["X-Zeta"] = "last"
	reordered.AccessEvents[0].RequestHeaders["X-Alpha"] = "first"
	reordered.AccessEvents[0].RequestBody = map[string]any{}
	reordered.AccessEvents[0].RequestBody["z"] = json.Number("9007199254740993")
	reordered.AccessEvents[0].RequestBody["a"] = map[string]any{"beta": json.Number("2"), "alpha": json.Number("1")}
	reorderedDigest, err := CanonicalIngestDigestV1(reordered)
	if err != nil || reorderedDigest != baseDigest {
		t.Fatalf("map insertion order changed digest: base=%x reordered=%x err=%v", baseDigest, reorderedDigest, err)
	}

	variants := []struct {
		name   string
		mutate func(*DecodedIngest)
	}{
		{name: "nullable task", mutate: func(value *DecodedIngest) { empty := ""; value.AccessEvents[0].TaskID = &empty }},
		{name: "nil versus empty headers", mutate: func(value *DecodedIngest) { value.AccessEvents[0].ResponseHeaders = map[string]string{} }},
		{name: "exact integer", mutate: func(value *DecodedIngest) { value.AccessEvents[0].RequestBody["z"] = json.Number("9007199254740992") }},
		{name: "installation authority", mutate: func(value *DecodedIngest) { value.InstallationID = "22222222-2222-4222-8222-222222222222" }},
	}
	for _, test := range variants {
		t.Run(test.name, func(t *testing.T) {
			value := authorityDecodedIngestV1(t)
			test.mutate(&value)
			digest, digestErr := CanonicalIngestDigestV1(value)
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			if digest == baseDigest {
				t.Fatalf("semantic variant retained canonical digest %x", digest)
			}
		})
	}
}

func TestCanonicalIngestDigestV1AllowsLegacyEmptySubscription(t *testing.T) {
	value := authorityDecodedIngestV1(t)
	value.PackageSubscriptionID = ""
	value.AccessEvents[0].PackageSubscriptionID = ""
	receipt, err := NewIngestReceiptV1(authorityGenerationV1(), 42, value)
	if err != nil || receipt.CanonicalEventSHA256 == ([sha256.Size]byte{}) || receipt.ReceiptIdentitySHA256 == ([sha256.Size]byte{}) {
		t.Fatalf("legacy empty subscription receipt = %#v, err=%v", receipt, err)
	}
}

func TestCanonicalIngestDigestV1RejectsEventSubscriptionClaimMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DecodedIngest)
	}{
		{name: "different valid access claim", mutate: func(value *DecodedIngest) {
			value.AccessEvents[0].PackageSubscriptionID = "40000000-0000-4000-8000-000000000002"
		}},
		{name: "malformed security claim", mutate: func(value *DecodedIngest) {
			security := canonicalSecurityDecodedV1()
			security.SecurityEvents[0].PackageSubscriptionID = "not-a-uuid"
			*value = security
		}},
		{name: "legacy root with non-empty event claim", mutate: func(value *DecodedIngest) {
			value.PackageSubscriptionID = ""
			value.AccessEvents[0].PackageSubscriptionID = canonicalPackageSubscriptionIDV1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := canonicalAccessDecodedV1()
			test.mutate(&value)
			if _, err := CanonicalIngestDigestV1(value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("canonical event claim error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func TestCanonicalIngestDigestV1GoldenAccessSecurityAndPublicFieldSensitivity(t *testing.T) {
	// Golden V1 is SHA-256 over recursively lexicographic-key JSON with no omitted
	// fields, UTC RFC3339Nano times, lowercase payload SHA hex and exact json.Number lexemes.
	tests := []struct {
		name    string
		fixture func() DecodedIngest
		golden  string
		event   func(*DecodedIngest) reflect.Value
	}{
		{
			name: "access", fixture: canonicalAccessDecodedV1,
			golden: "b9d77ab94e63b1148989f7fecbcc6a7c677e1b8f85a36b0f179aaeeee590fe71",
			event:  func(value *DecodedIngest) reflect.Value { return reflect.ValueOf(&value.AccessEvents[0]).Elem() },
		},
		{
			name: "security", fixture: canonicalSecurityDecodedV1,
			golden: "f1cb0f256eb74f8abeeb204d6938fb86f01585eef35bafd0837ece1b993bef78",
			event:  func(value *DecodedIngest) reflect.Value { return reflect.ValueOf(&value.SecurityEvents[0]).Elem() },
		},
	}
	for _, test := range tests {
		t.Run(test.name+" golden", func(t *testing.T) {
			fixture := test.fixture()
			digest, err := CanonicalIngestDigestV1(fixture)
			if err != nil || hex.EncodeToString(digest[:]) != test.golden {
				t.Fatalf("digest=%x err=%v, want %s", digest, err, test.golden)
			}
		})
		t.Run(test.name+" every public event field", func(t *testing.T) {
			base := test.fixture()
			baseDigest, err := CanonicalIngestDigestV1(base)
			if err != nil {
				t.Fatal(err)
			}
			typeOfEvent := test.event(&base).Type()
			alternatives := canonicalPublicFieldAlternativesV1(test.name)
			for index := 0; index < typeOfEvent.NumField(); index++ {
				fieldName := typeOfEvent.Field(index).Name
				t.Run(fieldName, func(t *testing.T) {
					candidate := test.fixture()
					alternative, ok := alternatives[fieldName]
					if !ok {
						t.Fatalf("no valid canonical alternative for %s.%s", test.name, fieldName)
					}
					setCanonicalPublicFieldAlternativeV1(t, &candidate, test.event(&candidate).Field(index), fieldName, alternative)
					digest, digestErr := CanonicalIngestDigestV1(candidate)
					if digestErr != nil {
						t.Fatalf("valid %s.%s alternative was rejected: %v", test.name, fieldName, digestErr)
					}
					if digest == baseDigest {
						t.Fatalf("public field %s did not affect digest %x", fieldName, digest)
					}
				})
			}
		})
	}

	rootVariants := []struct {
		name   string
		mutate func(*DecodedIngest)
	}{
		{name: "schema version", mutate: func(value *DecodedIngest) { value.SchemaVersion++ }},
		{name: "kind", mutate: func(value *DecodedIngest) { value.Kind += "-changed" }},
		{name: "message ID", mutate: func(value *DecodedIngest) { value.MessageID += "-changed" }},
		{name: "produced at", mutate: func(value *DecodedIngest) { value.ProducedAt = value.ProducedAt.Add(time.Nanosecond) }},
		{name: "tenant", mutate: func(value *DecodedIngest) { value.TenantID = "10000000-0000-0000-0000-000000000002" }},
		{name: "package subscription", mutate: func(value *DecodedIngest) {
			value.PackageSubscriptionID = "40000000-0000-4000-8000-000000000002"
			value.AccessEvents[0].PackageSubscriptionID = value.PackageSubscriptionID
		}},
		{name: "node", mutate: func(value *DecodedIngest) { value.NodeID = "30000000-0000-0000-0000-000000000002" }},
		{name: "installation", mutate: func(value *DecodedIngest) { value.InstallationID = "22222222-2222-4222-8222-222222222222" }},
		{name: "payload digest", mutate: func(value *DecodedIngest) { value.PayloadDigest[0]++ }},
	}
	for _, test := range rootVariants {
		t.Run("root/"+test.name, func(t *testing.T) {
			base, candidate := canonicalAccessDecodedV1(), canonicalAccessDecodedV1()
			baseDigest, err := CanonicalIngestDigestV1(base)
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			digest, digestErr := CanonicalIngestDigestV1(candidate)
			if digestErr == nil && digest == baseDigest {
				t.Fatalf("root field %s did not affect digest %x", test.name, digest)
			}
		})
	}
}

func TestCanonicalIngestDigestV1InvalidFieldAlternativesAreRejectedSeparately(t *testing.T) {
	tests := []struct {
		name     string
		validate func() error
	}{
		{name: "access malformed UUID", validate: func() error {
			value := canonicalAccessDecodedV1().AccessEvents[0]
			value.TenantID = "not-a-uuid"
			return validateAccessEvent(value)
		}},
		{name: "access invalid status", validate: func() error {
			value := canonicalAccessDecodedV1().AccessEvents[0]
			value.StatusCode = 99
			return validateAccessEvent(value)
		}},
		{name: "security non-UTC time", validate: func() error {
			value := canonicalSecurityDecodedV1().SecurityEvents[0]
			value.OccurredAt = value.OccurredAt.In(time.FixedZone("invalid-canonical-zone", 8*60*60))
			return validateSecurityEvent(value)
		}},
		{name: "security invalid capture number", validate: func() error {
			value := canonicalSecurityDecodedV1().SecurityEvents[0]
			value.RequestBody = map[string]any{"invalid": json.Number("not-a-number")}
			return validateSecurityEvent(value)
		}},
		{name: "canonical malformed package subscription", validate: func() error {
			value := canonicalSecurityDecodedV1()
			value.PackageSubscriptionID = "not-a-uuid"
			_, err := CanonicalIngestDigestV1(value)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.validate(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid alternative error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func TestIngestHistoryV1PreparedBrokerAndCommittedFloors(t *testing.T) {
	generation := authorityGenerationV1()
	progress, err := NewIngestHistoryProgressV1(generation)
	if err != nil {
		t.Fatal(err)
	}
	if progress.PreparedStreamFloor != 40 || progress.BrokerStreamAckFloor != 40 || progress.CommittedStreamAckFloor != 40 || progress.Revision != 1 {
		t.Fatalf("initial progress = %#v", progress)
	}
	progress, err = PrepareIngestHistoryV1(progress, 41)
	if err != nil {
		t.Fatal(err)
	}
	if progress.PreparedStreamFloor != 41 || progress.CommittedStreamAckFloor != 40 || progress.Revision != 2 {
		t.Fatalf("prepared progress = %#v", progress)
	}
	progress, err = ReconcileIngestHistoryV1(progress, IngestBrokerHistorySnapshotV1{
		Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 41,
	})
	if err != nil {
		t.Fatal(err)
	}
	if progress.BrokerStreamAckFloor != 41 || progress.CommittedStreamAckFloor != 41 || progress.Revision != 3 {
		t.Fatalf("reconciled progress = %#v", progress)
	}
	progress, err = ReconcileIngestHistoryV1(progress, IngestBrokerHistorySnapshotV1{
		Generation: generation, ConsumerAckFloor: 2, StreamAckFloor: 42,
	})
	if err != nil {
		t.Fatal(err)
	}
	if progress.BrokerStreamAckFloor != 42 || progress.PreparedStreamFloor != 41 || progress.CommittedStreamAckFloor != 41 || progress.Revision != 4 {
		t.Fatalf("broker-ahead progress = %#v", progress)
	}
	// JetStream counts every redelivery in the consumer sequence, so after a
	// NAK the consumer ack floor is ahead of the stream ack floor (seen on
	// NATS 2.11.4 and 2.12.15: one message, NAK then ACK -> consumer=2 stream=1).
	progress, err = ReconcileIngestHistoryV1(progress, IngestBrokerHistorySnapshotV1{
		Generation: generation, ConsumerAckFloor: 50, StreamAckFloor: 42,
	})
	if err != nil || progress.BrokerConsumerAckFloor != 50 {
		t.Fatalf("consumer floor above stream floor progress = %#v err=%v", progress, err)
	}
	changed := generation
	changed.ConsumerCreatedUnixNano++
	if _, err := ReconcileIngestHistoryV1(progress, IngestBrokerHistorySnapshotV1{Generation: changed, ConsumerAckFloor: 2, StreamAckFloor: 42}); !errors.Is(err, ErrIngestHistoryGenerationChanged) {
		t.Fatalf("generation change error = %v", err)
	}
}

type recordingIngestHistoryAuthorityV1 struct {
	mu                    sync.Mutex
	operations            []string
	receipts              []IngestReceiptV1
	receiveState          IngestReceiptStateV1
	receiveErr            error
	prepareErr            error
	brokerAckErr          error
	reconcileErr          error
	prepared              bool
	brokerAckCount        int
	recoveryCount         int
	recoveryClaimCount    int
	recoveryCompleteCount int
	recoveryScheduled     bool
	recoveryNow           time.Time
	recoveryLease         time.Duration
	activeRecoveryClaim   IngestRecoveryClaimV1
	progress              IngestHistoryProgressV1
}

func newRecordingIngestHistoryAuthorityV1(t *testing.T, generation IngestHistoryGenerationV1) *recordingIngestHistoryAuthorityV1 {
	t.Helper()
	progress, err := NewIngestHistoryProgressV1(generation)
	if err != nil {
		t.Fatal(err)
	}
	return &recordingIngestHistoryAuthorityV1{
		receiveState:  IngestReceiptStateReceived,
		recoveryNow:   time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		recoveryLease: time.Minute,
		progress:      progress,
	}
}

func (history *recordingIngestHistoryAuthorityV1) record(operation string) {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.operations = append(history.operations, operation)
}

func (history *recordingIngestHistoryAuthorityV1) Receive(_ context.Context, receipt IngestReceiptV1) (IngestReceiptStateV1, error) {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.operations = append(history.operations, "received")
	if history.receiveErr != nil {
		return history.receiveState, history.receiveErr
	}
	for _, persisted := range history.receipts {
		if persisted.Key != receipt.Key {
			continue
		}
		if _, err := ClassifyIngestReceiptReplayV1(persisted, receipt); err != nil {
			return history.receiveState, err
		}
		return history.receiveState, nil
	}
	history.receipts = append(history.receipts, receipt)
	return history.receiveState, nil
}

func (history *recordingIngestHistoryAuthorityV1) MarkPrepared(_ context.Context, receipt IngestReceiptV1) (IngestHistoryProgressV1, error) {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.operations = append(history.operations, "pg-prepared")
	if history.prepareErr != nil {
		return history.progress, history.prepareErr
	}
	progress, err := PrepareIngestHistoryV1(history.progress, receipt.Key.StreamSequence)
	if err != nil {
		return history.progress, err
	}
	history.progress = progress
	history.prepared = true
	history.receiveState = IngestReceiptStatePrepared
	return progress, nil
}

func (history *recordingIngestHistoryAuthorityV1) MarkBrokerAckObserved(_ context.Context, _ IngestReceiptKeyV1) error {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.operations = append(history.operations, "broker-ack-observed")
	if history.brokerAckErr == nil {
		history.brokerAckCount++
	}
	return history.brokerAckErr
}

func (history *recordingIngestHistoryAuthorityV1) ReconcileBroker(
	_ context.Context,
	claim IngestRecoveryClaimV1,
	snapshot IngestBrokerHistorySnapshotV1,
) (IngestHistoryProgressV1, error) {
	history.mu.Lock()
	defer history.mu.Unlock()
	if claim.RecoveryID == "" || claim.RecoveryID != history.activeRecoveryClaim.RecoveryID ||
		claim.Token == "" || claim.Token != history.activeRecoveryClaim.Token ||
		!history.recoveryNow.Before(history.activeRecoveryClaim.LeaseExpiresAt) {
		return history.progress, ErrIngestRecoveryFenced
	}
	history.operations = append(history.operations, "broker-reconciled")
	if history.reconcileErr != nil {
		return history.progress, history.reconcileErr
	}
	progress, err := ReconcileIngestHistoryV1(history.progress, snapshot)
	if err != nil {
		return history.progress, err
	}
	history.progress = progress
	return progress, nil
}

func (history *recordingIngestHistoryAuthorityV1) ScheduleRecovery(
	_ context.Context,
	_ IngestHistoryGenerationV1,
) error {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.operations = append(history.operations, "recovery-scheduled")
	history.recoveryCount++
	history.recoveryScheduled = true
	return nil
}

func (history *recordingIngestHistoryAuthorityV1) ClaimScheduledRecovery(
	_ context.Context,
	_ IngestHistoryGenerationV1,
) (IngestRecoveryClaimV1, bool, error) {
	history.mu.Lock()
	defer history.mu.Unlock()
	if !history.recoveryScheduled {
		return IngestRecoveryClaimV1{}, false, nil
	}
	if history.activeRecoveryClaim.Token != "" && history.recoveryNow.Before(history.activeRecoveryClaim.LeaseExpiresAt) {
		return IngestRecoveryClaimV1{}, false, nil
	}
	history.recoveryClaimCount++
	claim := IngestRecoveryClaimV1{
		RecoveryID:     "66666666-6666-4666-8666-666666666666",
		ClaimedBy:      "server-history-recovery-worker",
		Token:          fmt.Sprintf("server-history-recovery-claim-%d", history.recoveryClaimCount),
		LeaseExpiresAt: history.recoveryNow.Add(history.recoveryLease),
	}
	history.activeRecoveryClaim = claim
	history.operations = append(history.operations, "recovery-claimed")
	return claim, true, nil
}

func (history *recordingIngestHistoryAuthorityV1) CompleteScheduledRecovery(
	_ context.Context,
	claim IngestRecoveryClaimV1,
) error {
	history.mu.Lock()
	defer history.mu.Unlock()
	if !history.recoveryScheduled || claim.RecoveryID == "" || claim.RecoveryID != history.activeRecoveryClaim.RecoveryID ||
		claim.Token == "" || claim.Token != history.activeRecoveryClaim.Token ||
		!history.recoveryNow.Before(history.activeRecoveryClaim.LeaseExpiresAt) {
		return ErrIngestRecoveryFenced
	}
	history.operations = append(history.operations, "recovery-completed")
	history.recoveryScheduled = false
	history.activeRecoveryClaim = IngestRecoveryClaimV1{}
	history.recoveryCompleteCount++
	return nil
}

func TestIngestHistoryRecoveryClaimFencesWrongTokenAndExpiredOwner(t *testing.T) {
	generation := authorityGenerationV1()
	history := newRecordingIngestHistoryAuthorityV1(t, generation)
	if err := history.ScheduleRecovery(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
	first, ok, err := history.ClaimScheduledRecovery(context.Background(), generation)
	if err != nil || !ok {
		t.Fatalf("first claim = (%#v, %t, %v)", first, ok, err)
	}
	wrong := first
	wrong.Token = "77777777-7777-4777-8777-777777777777"
	snapshot := IngestBrokerHistorySnapshotV1{Generation: generation, ConsumerAckFloor: 1, StreamAckFloor: 41}
	if _, err := history.ReconcileBroker(context.Background(), wrong, snapshot); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-token reconcile error = %v", err)
	}
	if err := history.CompleteScheduledRecovery(context.Background(), wrong); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-token completion error = %v", err)
	}
	history.advanceRecoveryClock(history.recoveryLease)
	second, ok, err := history.ClaimScheduledRecovery(context.Background(), generation)
	if err != nil || !ok || second.Token == first.Token {
		t.Fatalf("takeover claim = (%#v, %t, %v), first=%#v", second, ok, err, first)
	}
	if _, err := history.ReconcileBroker(context.Background(), first, snapshot); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("expired-owner reconcile error = %v", err)
	}
	if err := history.CompleteScheduledRecovery(context.Background(), first); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("expired-owner completion error = %v", err)
	}
	if _, err := history.ReconcileBroker(context.Background(), second, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := history.CompleteScheduledRecovery(context.Background(), second); err != nil {
		t.Fatal(err)
	}
}

func (history *recordingIngestHistoryAuthorityV1) advanceRecoveryClock(delta time.Duration) {
	history.mu.Lock()
	defer history.mu.Unlock()
	history.recoveryNow = history.recoveryNow.Add(delta)
}

type authorityOrderWriterV1 struct {
	history *recordingIngestHistoryAuthorityV1
	err     error
	token   string
	calls   int
}

func (writer *authorityOrderWriterV1) WriteAccessEvents(_ context.Context, token string, _ []AccessEvent) error {
	writer.calls++
	writer.token = token
	writer.history.record("clickhouse")
	return writer.err
}

func (writer *authorityOrderWriterV1) WriteSecurityEvents(_ context.Context, token string, _ []SecurityEvent) error {
	writer.calls++
	writer.token = token
	writer.history.record("clickhouse")
	return writer.err
}

type authorityOrderDeliveryV1 struct {
	*fakeIngestDelivery
	history *recordingIngestHistoryAuthorityV1
	ackErr  error
}

func (delivery *authorityOrderDeliveryV1) Ack(ctx context.Context) error {
	delivery.history.record("nats-ack")
	delivery.history.mu.Lock()
	prepared := delivery.history.prepared || delivery.history.receiveState >= IngestReceiptStatePrepared
	delivery.history.mu.Unlock()
	if !prepared {
		return errors.New("NATS ACK attempted before durable PostgreSQL prepared fact")
	}
	delivery.ackCount++
	delivery.ackDeadline, _ = ctx.Deadline()
	return delivery.ackErr
}

func canonicalAccessDecodedV1() DecodedIngest {
	taskID, ja4 := "task-access", "t13d1516h2_8daaf6152771"
	originConnect, originFirstByte, originTotal := uint64(11), uint64(22), uint64(33)
	return DecodedIngest{
		SchemaVersion: IngestSchemaVersion, Kind: AccessEnvelopeType, MessageID: "golden-access-message",
		ProducedAt: time.Date(2100, 1, 1, 0, 1, 2, 654321000, time.UTC),
		TenantID:   testTenantID, PackageSubscriptionID: canonicalPackageSubscriptionIDV1,
		NodeID: testNodeID, InstallationID: authorityGenerationV1().InstallationID,
		PayloadDigest: sha256.Sum256([]byte("canonical-access-wire-v1")),
		AccessEvents: []AccessEvent{{
			MetricVersion: MetricVersion, EventID: "golden-access-event",
			OccurredAt: time.Date(2100, 1, 1, 0, 0, 1, 123456000, time.UTC),
			TenantID:   testTenantID, PackageSubscriptionID: canonicalPackageSubscriptionIDV1,
			SiteID: testSiteID, NodeID: testNodeID,
			RequestID: "request-access", TraceID: "trace-access", ConfigVersion: "config-access",
			Host: "access.example.test", Path: "/golden/access?x=1", ClientIP: "2001:db8::10",
			CountryCode: "CN", Carrier: "carrier-access", Method: "POST", Protocol: "HTTP/3",
			CacheStatus: "MISS", UpstreamResult: "origin-ok", StatusCode: 206,
			RequestBytes: 123, ResponseBytes: 4567, DurationUS: 890,
			RequestHeaders:  map[string]string{"X-Zeta": "last", "X-Alpha": "first"},
			ResponseHeaders: map[string]string{"Content-Type": "application/json"},
			RequestBody: map[string]any{
				"z": json.Number("9007199254740993"),
				"a": map[string]any{"beta": json.Number("2"), "alpha": json.Number("1")},
			},
			ResponseBody: map[string]any{"ok": true, "count": json.Number("3")},
			TaskID:       &taskID, InstallationID: authorityGenerationV1().InstallationID, JA4: &ja4,
			OriginConnectUS: &originConnect, OriginFirstByteUS: &originFirstByte, OriginTotalUS: &originTotal,
		}},
		SecurityEvents: []SecurityEvent{},
	}
}

func canonicalSecurityDecodedV1() DecodedIngest {
	taskID, ja4 := "task-security", "t13d1517h2_8daaf6152772"
	originConnect, originFirstByte, originTotal := uint64(44), uint64(55), uint64(66)
	return DecodedIngest{
		SchemaVersion: IngestSchemaVersion, Kind: SecurityEnvelopeType, MessageID: "golden-security-message",
		ProducedAt: time.Date(2100, 1, 1, 0, 1, 3, 654321000, time.UTC),
		TenantID:   testTenantID, PackageSubscriptionID: canonicalPackageSubscriptionIDV1,
		NodeID: testNodeID, InstallationID: authorityGenerationV1().InstallationID,
		PayloadDigest: sha256.Sum256([]byte("canonical-security-wire-v1")),
		AccessEvents:  []AccessEvent{},
		SecurityEvents: []SecurityEvent{{
			MetricVersion: MetricVersion, EventID: "golden-security-event",
			OccurredAt: time.Date(2100, 1, 1, 0, 0, 2, 123456000, time.UTC),
			TenantID:   testTenantID, PackageSubscriptionID: canonicalPackageSubscriptionIDV1,
			SiteID: testSiteID, NodeID: testNodeID,
			RequestID: "request-security", TraceID: "trace-security", ConfigVersion: "config-security",
			Host: "security.example.test", Path: "/golden/security", ClientIP: "2001:db8::20",
			CountryCode: "US", Carrier: "carrier-security", EventType: "waf", Action: "block",
			Severity: "high", RuleID: "rule-42", StatusCode: 403, RequestBytes: 321, ResponseBytes: 654,
			RequestHeaders:  map[string]string{"X-Request": "security"},
			ResponseHeaders: map[string]string{"X-Decision": "blocked"},
			RequestBody:     map[string]any{"account": json.Number("9007199254740993")},
			ResponseBody:    map[string]any{}, TaskID: &taskID,
			InstallationID: authorityGenerationV1().InstallationID, JA4: &ja4,
			OriginConnectUS: &originConnect, OriginFirstByteUS: &originFirstByte, OriginTotalUS: &originTotal,
		}},
	}
}

func canonicalPublicFieldAlternativesV1(kind string) map[string]any {
	accessTask, accessJA4 := "task-access-alternative", "t13d1516h2_8daaf6152773"
	accessConnect, accessFirstByte, accessTotal := uint64(12), uint64(23), uint64(34)
	securityTask, securityJA4 := "task-security-alternative", "t13d1517h2_8daaf6152774"
	securityConnect, securityFirstByte, securityTotal := uint64(45), uint64(56), uint64(67)
	alternatives := map[string]any{
		"MetricVersion":         uint16(MetricVersion + 1),
		"OccurredAt":            time.Date(2100, 1, 1, 0, 0, 3, 123456001, time.UTC),
		"TenantID":              "10000000-0000-4000-8000-000000000002",
		"PackageSubscriptionID": "40000000-0000-4000-8000-000000000002",
		"SiteID":                "20000000-0000-4000-8000-000000000002",
		"NodeID":                "30000000-0000-4000-8000-000000000002",
		"RequestID":             "request-alternative",
		"TraceID":               "trace-alternative",
		"ConfigVersion":         "config-alternative",
		"Host":                  "alternative.example.test",
		"Path":                  "/canonical/alternative",
		"ClientIP":              "2001:db8::30",
		"CountryCode":           "GB",
		"Carrier":               "carrier-alternative",
		"StatusCode":            uint16(207),
		"RequestBytes":          uint64(777),
		"ResponseBytes":         uint64(888),
		"RequestHeaders":        map[string]string{"X-Alternative": "request"},
		"ResponseHeaders":       map[string]string{"X-Alternative": "response"},
		"RequestBody":           map[string]any{"alternative": json.Number("9007199254740995")},
		"ResponseBody":          map[string]any{"alternative": true},
		"InstallationID":        "11111111-1111-4111-8111-111111111112",
	}
	if kind == "access" {
		alternatives["EventID"] = "golden-access-event-alternative"
		alternatives["Method"] = "PUT"
		alternatives["ListenPort"] = uint16(8443)
		alternatives["Protocol"] = "HTTP/2"
		alternatives["CacheStatus"] = "HIT"
		alternatives["UpstreamResult"] = "origin-alternative"
		alternatives["DurationUS"] = uint64(999)
		alternatives["TaskID"] = &accessTask
		alternatives["JA4"] = &accessJA4
		alternatives["OriginConnectUS"] = &accessConnect
		alternatives["OriginFirstByteUS"] = &accessFirstByte
		alternatives["OriginTotalUS"] = &accessTotal
		alternatives["Blocked"] = true
		alternatives["ClientBrowser"] = "firefox"
		alternatives["ClientOS"] = "linux"
		alternatives["UpstreamAddr"] = "192.0.2.10:8080"
		alternatives["Province"] = "440000"
		return alternatives
	}
	alternatives["Province"] = "110000"
	alternatives["EventID"] = "golden-security-event-alternative"
	alternatives["Method"] = "POST"
	alternatives["ListenPort"] = uint16(8443)
	alternatives["DestinationPort"] = uint16(8443)
	alternatives["Protocol"] = "http"
	alternatives["RequestClass"] = "websocket"
	alternatives["EventType"] = "cc"
	alternatives["Action"] = "challenge"
	alternatives["Severity"] = "medium"
	alternatives["RuleID"] = "rule-alternative"
	alternatives["StatusCode"] = uint16(429)
	alternatives["TaskID"] = &securityTask
	alternatives["JA4"] = &securityJA4
	alternatives["OriginConnectUS"] = &securityConnect
	alternatives["OriginFirstByteUS"] = &securityFirstByte
	alternatives["OriginTotalUS"] = &securityTotal
	// ge-waf S4 attack evidence.
	alternatives["PolicyID"] = "22222222-2222-4222-8222-222222222299"
	alternatives["Detector"] = "xss"
	alternatives["Matched"] = "<script>alternative"
	alternatives["UserAgent"] = "alternative-agent/1.0"
	alternatives["RequestBodyExcerpt"] = "alternative=body"
	// sec-log-agg aggregated line count.
	alternatives["Count"] = uint32(10)
	return alternatives
}

func setCanonicalPublicFieldAlternativeV1(
	t *testing.T,
	decoded *DecodedIngest,
	field reflect.Value,
	fieldName string,
	alternative any,
) {
	t.Helper()
	value := reflect.ValueOf(alternative)
	if !value.IsValid() || !value.Type().AssignableTo(field.Type()) {
		t.Fatalf("canonical alternative %s has type %T, want %s", fieldName, alternative, field.Type())
	}
	if decoded.Kind == SecurityEnvelopeType {
		event := &decoded.SecurityEvents[0]
		switch fieldName {
		case "DestinationPort":
			event.Method, event.ListenPort, event.Protocol, event.RequestClass = "NETWORK", 8443, "tcp", "network"
		default:
			if fieldName == "Method" || fieldName == "ListenPort" || fieldName == "Protocol" || fieldName == "RequestClass" {
				event.Method, event.ListenPort, event.DestinationPort, event.Protocol, event.RequestClass = "GET", 443, 0, "https", "standard"
			}
		}
	}
	field.Set(value)
	switch fieldName {
	case "TenantID":
		decoded.TenantID = alternative.(string)
	case "PackageSubscriptionID":
		decoded.PackageSubscriptionID = alternative.(string)
	case "NodeID":
		decoded.NodeID = alternative.(string)
	case "InstallationID":
		decoded.InstallationID = alternative.(string)
	}
}

func authorityGenerationV1() IngestHistoryGenerationV1 {
	return IngestHistoryGenerationV1{
		InstallationID: "11111111-1111-4111-8111-111111111111",
		NATSDomain:     "", StreamName: DefaultIngestStream, DurableName: DefaultIngestDurable,
		StreamCreatedUnixNano:   4_102_444_800_000_000_000,
		ConsumerCreatedUnixNano: 4_102_444_801_000_000_000,
		HistoryEpoch:            "33333333-3333-4333-8333-333333333333", HistoryStartSequence: 41,
	}
}

func processorFixtureGenerationV1() IngestHistoryGenerationV1 {
	generation := authorityGenerationV1()
	generation.InstallationID = "test-installation"
	generation.HistoryEpoch = "55555555-5555-4555-8555-555555555555"
	generation.HistoryStartSequence = 1
	return generation
}

func authorityDecodedIngestV1(t *testing.T) DecodedIngest {
	t.Helper()
	now := time.Date(2100, 1, 1, 0, 0, 0, 123456000, time.UTC)
	event := eventAt(validAccessEvent("authority-event"), now.Add(-time.Minute))
	event.InstallationID = authorityGenerationV1().InstallationID
	event.PackageSubscriptionID = canonicalPackageSubscriptionIDV1
	event.RequestHeaders = map[string]string{"X-Alpha": "first", "X-Zeta": "last"}
	event.ResponseHeaders = nil
	event.RequestBody = map[string]any{
		"a": map[string]any{"alpha": json.Number("1"), "beta": json.Number("2")},
		"z": json.Number("9007199254740993"),
	}
	event.ResponseBody = map[string]any{}
	return DecodedIngest{
		SchemaVersion: IngestSchemaVersion, Kind: AccessEnvelopeType, MessageID: "authority-message",
		ProducedAt: now, TenantID: event.TenantID, PackageSubscriptionID: event.PackageSubscriptionID, NodeID: event.NodeID,
		InstallationID: authorityGenerationV1().InstallationID, AccessEvents: []AccessEvent{event},
		PayloadDigest: sha256.Sum256([]byte("authority-wire-payload-v1")),
	}
}

func authorityProcessorV1(
	t *testing.T,
	now time.Time,
	writer IngestWriter,
	history IngestHistoryAuthorityV1,
	generation IngestHistoryGenerationV1,
	sink IsolationSink,
) *IngestProcessor {
	t.Helper()
	decoder := mustIngestDecoder(t, now, IngestDecoderConfig{})
	processor, err := NewIngestProcessor(decoder, writer, sink, IngestProcessorConfig{
		OperationTimeout: time.Second, NakBaseDelay: time.Second, NakMaxDelay: 5 * time.Second,
		MaxDeliver: 4, MaxBatchEvents: DefaultMaxEventsPerEnvelope, Now: func() time.Time { return now },
		History: history, HistoryGeneration: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func authorityOperationsV1(history *recordingIngestHistoryAuthorityV1) string {
	history.mu.Lock()
	defer history.mu.Unlock()
	return strings.Join(history.operations, ",")
}

func authorityReceiptDigestV1(receipt IngestReceiptV1) string {
	return hex.EncodeToString(receipt.CanonicalEventSHA256[:])
}
