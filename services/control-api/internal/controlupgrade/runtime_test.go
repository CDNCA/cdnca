package controlupgrade

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

const statusInteropFixture = `{"schema":"cdnca.edge.upgrade.status/v1","status_id":"00000000-0000-4000-8000-000000000031","status_revision":1,"command_id":"00000000-0000-4000-8000-000000000021","plan_id":"00000000-0000-4000-8000-000000000011","plan_revision":2,"installation_id":"00000000-0000-4000-8000-000000000004","node_id":"00000000-0000-4000-8000-000000000022","command_sha256":"0000000000000000000000000000000000000000000000000000000000000000","state":"accepted","current_version":"","previous_version":"","installer_transaction_id":"","error_code":"","alert_required":false,"observed_at":"2026-08-05T01:02:03Z"}`

func TestDecodeRolloutStatusDeliveryExactInterop(t *testing.T) {
	delivery := exactStatusDelivery()
	receipt, reason := decodeRolloutStatusDelivery(delivery, DefaultStatusRuntimeConfig())
	if reason != "" || receipt.StatusID != "00000000-0000-4000-8000-000000000031" ||
		receipt.CommandID != "00000000-0000-4000-8000-000000000021" ||
		receipt.StatusSHA256 != rolloutWireDigest([]byte(statusInteropFixture)) {
		t.Fatalf("decodeRolloutStatusDelivery() = (%#v,%q)", receipt, reason)
	}
	for _, test := range []struct {
		name   string
		mutate func(*fakeStatusDelivery)
	}{
		{"subject", func(value *fakeStatusDelivery) { value.subject += ".other" }},
		{"message id", func(value *fakeStatusDelivery) { value.header.Set(nats.MsgIdHdr, receipt.CommandID) }},
		{"stream", func(value *fakeStatusDelivery) { value.header.Set(nats.ExpectedStreamHdr, "OTHER") }},
		{"digest", func(value *fakeStatusDelivery) {
			value.header.Set(upgradePayloadSHA256Header, string(bytes.Repeat([]byte{'0'}, 64)))
		}},
		{"key", func(value *fakeStatusDelivery) { value.header.Set(upgradeMessageKeyHeader, receipt.CommandID) }},
		{"duplicate", func(value *fakeStatusDelivery) { value.header.Add(upgradeMessageKeyHeader, receipt.StatusID) }},
		{"extra", func(value *fakeStatusDelivery) { value.header.Set("X-CDNCA-Extra", "forbidden") }},
		{"noncanonical data", func(value *fakeStatusDelivery) { value.data = append(value.data, ' ') }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := delivery.clone()
			test.mutate(candidate)
			if _, reason := decodeRolloutStatusDelivery(candidate, DefaultStatusRuntimeConfig()); reason == "" {
				t.Fatal("invalid status delivery was accepted")
			}
		})
	}
	v2 := delivery.clone()
	v2.subject = "cdnca.agent.deployment-status.upgrade-v2." + receipt.StatusID
	v2.header.Set(nats.MsgIdHdr, "gateway-upgrade-status-v2-"+receipt.StatusID)
	v2.header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	if decoded, reason := decodeRolloutStatusDelivery(v2, DefaultStatusRuntimeConfig()); reason != "" ||
		decoded.StatusID != receipt.StatusID || decoded.NodeID != receipt.NodeID {
		t.Fatalf("v2 decodeRolloutStatusDelivery() = (%#v,%q)", decoded, reason)
	}
	v2.subject = "cdnca.agent.deployment-status.upgrade-v2.00000000-0000-4000-8000-000000000099"
	if _, reason := decodeRolloutStatusDelivery(v2, DefaultStatusRuntimeConfig()); reason != "status_identity" {
		t.Fatalf("v2 mismatched StatusID reason=%q", reason)
	}
}

func TestOutboxDispatcherSettlesExactBrokerOutcomes(t *testing.T) {
	message := RolloutOutboxMessage{ID: "00000000-0000-4000-8000-000000000021",
		PlanID: "00000000-0000-4000-8000-000000000011", PlanRevision: 2,
		Topic:      "cdnca.agent.commands.upgrade.00000000-0000-4000-8000-000000000022",
		MessageKey: "00000000-0000-4000-8000-000000000021", PayloadBytes: []byte(`{"schema":"cdnca.edge.upgrade.command/v1"}`)}
	message.PayloadSHA256 = rolloutWireDigest(message.PayloadBytes)
	claim := RolloutOutboxClaim{Message: message, ClaimToken: "00000000-0000-4000-8000-000000000041"}
	for _, test := range []struct {
		name        string
		publish     PublishResult
		publishErr  error
		disposition RolloutOutboxDisposition
	}{
		{"published", PublishResult{Stream: upgradeCommandStream, Sequence: 17, Duplicate: true}, nil, RolloutOutboxPublished},
		{"unknown", PublishResult{}, ErrPublishOutcomeUnknown, RolloutOutboxUnknownOutcome},
		{"rejected", PublishResult{}, ErrPublishRejected, RolloutOutboxRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeOutboxRuntimeStore{claims: []RolloutOutboxClaim{claim}}
			publisher := &fakeRolloutPublisher{result: test.publish, err: test.publishErr}
			dispatcher, err := NewOutboxDispatcher(store, publisher, OutboxDispatcherConfig{
				WorkerID: "upgrade-worker", ClaimLease: time.Minute, ClaimBatch: 1,
				Clock: func() time.Time { return time.Date(2026, 8, 5, 1, 0, 0, 0, time.UTC) },
			})
			if err != nil {
				t.Fatal(err)
			}
			if count, err := dispatcher.DispatchOnce(context.Background()); count != 1 || err != nil {
				t.Fatalf("DispatchOnce() = (%d,%v)", count, err)
			}
			if len(store.settlements) != 1 || store.settlements[0].Disposition != test.disposition ||
				store.settlements[0].OutboxID != message.ID || store.settlements[0].ClaimToken != claim.ClaimToken ||
				store.settlements[0].PayloadSHA256 != message.PayloadSHA256 {
				t.Fatalf("settlement = %#v", store.settlements)
			}
			if test.disposition == RolloutOutboxPublished &&
				(store.settlements[0].PublishedStream != upgradeCommandStream || store.settlements[0].PublishedSequence != 17) {
				t.Fatalf("published acknowledgement was not persisted: %#v", store.settlements[0])
			}
		})
	}
}

func TestRolloutOutboxRetryDelayIsDeterministicAndBounded(t *testing.T) {
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 0, want: time.Second},
		{attempt: 1, want: time.Second},
		{attempt: 2, want: 2 * time.Second},
		{attempt: 6, want: 32 * time.Second},
		{attempt: 7, want: time.Minute},
		{attempt: 1_000_000, want: time.Minute},
	} {
		if got := rolloutOutboxRetryDelay(test.attempt); got != test.want {
			t.Fatalf("rolloutOutboxRetryDelay(%d) = %v, want %v", test.attempt, got, test.want)
		}
	}
}

func TestStatusProcessorCommitsBeforeAckAndPersistsPoisonBeforeTerm(t *testing.T) {
	t.Run("commit then ack", func(t *testing.T) {
		steps := []string{}
		delivery := exactStatusDelivery()
		delivery.steps = &steps
		store := &fakeStatusRuntimeStore{steps: &steps,
			identity: RolloutIdentity{ActorScopeID: planID(91), ActorUserID: planID(92), InstallationID: planID(4)}}
		processor := mustStatusProcessor(t, store, delivery)
		if disposition, err := processor.ProcessOnce(context.Background()); disposition != StatusDispositionAck || err != nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		want := []string{"resolve", "record", "ack"}
		if !equalStrings(steps, want) {
			t.Fatalf("steps = %#v, want %#v", steps, want)
		}
	})

	t.Run("status before durable publish naks", func(t *testing.T) {
		delivery := exactStatusDelivery()
		store := &fakeStatusRuntimeStore{identity: RolloutIdentity{ActorScopeID: planID(91), ActorUserID: planID(92), InstallationID: planID(4)},
			recordErr: ErrResourceUnavailable}
		processor := mustStatusProcessor(t, store, delivery)
		if disposition, err := processor.ProcessOnce(context.Background()); disposition != StatusDispositionNak || err == nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		if delivery.naks != 1 || delivery.acks != 0 || delivery.terms != 0 || len(store.rejections) != 0 {
			t.Fatalf("delivery/store = %#v / %#v", delivery, store)
		}
	})

	t.Run("plan revision race naks", func(t *testing.T) {
		delivery := exactStatusDelivery()
		store := &fakeStatusRuntimeStore{identity: RolloutIdentity{ActorScopeID: planID(91),
			ActorUserID: planID(92), InstallationID: planID(4)}, recordErr: ErrStalePlanRevision}
		processor := mustStatusProcessor(t, store, delivery)
		if disposition, err := processor.ProcessOnce(context.Background()); disposition != StatusDispositionNak ||
			!errors.Is(err, ErrStalePlanRevision) {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		if delivery.naks != 1 || delivery.acks != 0 || delivery.terms != 0 || len(store.rejections) != 0 {
			t.Fatalf("delivery/store = %#v / %#v", delivery, store)
		}
	})

	t.Run("poison persists then terms", func(t *testing.T) {
		steps := []string{}
		delivery := exactStatusDelivery()
		delivery.header.Set(nats.ExpectedStreamHdr, "OTHER")
		delivery.steps = &steps
		store := &fakeStatusRuntimeStore{steps: &steps}
		processor := mustStatusProcessor(t, store, delivery)
		if disposition, err := processor.ProcessOnce(context.Background()); disposition != StatusDispositionTerm || err != nil {
			t.Fatalf("ProcessOnce() = (%q,%v)", disposition, err)
		}
		want := []string{"reject", "term"}
		if !equalStrings(steps, want) || len(store.rejections) != 1 {
			t.Fatalf("steps/rejections = %#v / %#v", steps, store.rejections)
		}
	})
}

func TestUpgradeStatusConsumerConfigRejectsBehaviorDrift(t *testing.T) {
	config := DefaultStatusConsumerConfig()
	expected := expectedUpgradeStatusConsumer(config)
	wantFilters := []string{
		"cdnca.agent.deployment-status.upgrade.*",
		"cdnca.agent.deployment-status.upgrade-v2.*",
	}
	if expected.FilterSubject != "" || !equalStrings(expected.FilterSubjects, wantFilters) {
		t.Fatalf("consumer filters=(%q,%v), want empty/%v", expected.FilterSubject, expected.FilterSubjects, wantFilters)
	}
	base := &nats.ConsumerInfo{Stream: config.Stream, Name: config.Durable, Config: *expected}
	if !sameUpgradeStatusConsumer(base, config.Stream, expected) {
		t.Fatal("exact consumer config was rejected")
	}
	mutations := []func(*nats.ConsumerConfig){
		func(value *nats.ConsumerConfig) { value.DeliverPolicy = nats.DeliverLastPolicy },
		func(value *nats.ConsumerConfig) { value.AckPolicy = nats.AckAllPolicy },
		func(value *nats.ConsumerConfig) { value.MaxDeliver = 8 },
		func(value *nats.ConsumerConfig) { value.BackOff = []time.Duration{time.Second} },
		func(value *nats.ConsumerConfig) { value.FilterSubject = "cdnca.agent.deployment-status.upgrade.>" },
		func(value *nats.ConsumerConfig) {
			value.FilterSubjects = []string{"cdnca.agent.deployment-status.upgrade.>"}
		},
		func(value *nats.ConsumerConfig) { value.FilterSubjects = []string{wantFilters[1], wantFilters[0]} },
		func(value *nats.ConsumerConfig) { value.HeadersOnly = true },
		func(value *nats.ConsumerConfig) { value.MaxAckPending++ },
		func(value *nats.ConsumerConfig) { value.InactiveThreshold = time.Minute },
		func(value *nats.ConsumerConfig) { value.Replicas = 2 },
		func(value *nats.ConsumerConfig) { value.MemoryStorage = true },
	}
	for index, mutate := range mutations {
		candidate := *expected
		mutate(&candidate)
		if sameUpgradeStatusConsumer(&nats.ConsumerInfo{Stream: config.Stream, Name: config.Durable, Config: candidate}, config.Stream, expected) {
			t.Fatalf("consumer mismatch %d accepted", index)
		}
	}
}

func exactStatusDelivery() *fakeStatusDelivery {
	data := []byte(statusInteropFixture)
	statusID := "00000000-0000-4000-8000-000000000031"
	header := nats.Header{}
	header.Set(nats.MsgIdHdr, statusID)
	header.Set(nats.ExpectedStreamHdr, upgradeStatusStream)
	header.Set(upgradePayloadSHA256Header, rolloutWireDigest(data))
	header.Set(upgradeMessageKeyHeader, statusID)
	return &fakeStatusDelivery{subject: upgradeStatusSubjectPrefix + ".00000000-0000-4000-8000-000000000022",
		data: data, header: header, stream: upgradeStatusStream, consumer: upgradeStatusConsumer,
		sequence: 31, delivered: 1}
}

func mustStatusProcessor(t *testing.T, store statusRuntimeStore, delivery statusDelivery) *StatusProcessor {
	t.Helper()
	processor, err := NewStatusProcessor(store, &fakeStatusConsumer{delivery: delivery}, DefaultStatusRuntimeConfig())
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

type fakeOutboxRuntimeStore struct {
	claims      []RolloutOutboxClaim
	settlements []RolloutOutboxSettlement
}

func (store *fakeOutboxRuntimeStore) ClaimOutbox(context.Context, string, time.Time, time.Duration, int) ([]RolloutOutboxClaim, error) {
	return append([]RolloutOutboxClaim(nil), store.claims...), nil
}
func (store *fakeOutboxRuntimeStore) SettleOutbox(_ context.Context, settlement RolloutOutboxSettlement) error {
	store.settlements = append(store.settlements, settlement)
	return nil
}

type fakeRolloutPublisher struct {
	result PublishResult
	err    error
}

func (publisher *fakeRolloutPublisher) Publish(context.Context, RolloutOutboxMessage) (PublishResult, error) {
	return publisher.result, publisher.err
}
func (*fakeRolloutPublisher) Stream() string { return upgradeCommandStream }

type fakeStatusConsumer struct{ delivery statusDelivery }

func (consumer *fakeStatusConsumer) Next(context.Context) (statusDelivery, error) {
	return consumer.delivery, nil
}
func (*fakeStatusConsumer) Close() error { return nil }

type fakeStatusDelivery struct {
	subject   string
	data      []byte
	header    nats.Header
	stream    string
	consumer  string
	sequence  uint64
	delivered uint64
	acks      int
	naks      int
	terms     int
	steps     *[]string
}

func (delivery *fakeStatusDelivery) clone() *fakeStatusDelivery {
	header := make(nats.Header, len(delivery.header))
	for name, values := range delivery.header {
		header[name] = append([]string(nil), values...)
	}
	return &fakeStatusDelivery{subject: delivery.subject, data: bytes.Clone(delivery.data),
		header: header, stream: delivery.stream, consumer: delivery.consumer,
		sequence: delivery.sequence, delivered: delivery.delivered}
}
func (delivery *fakeStatusDelivery) Subject() string        { return delivery.subject }
func (delivery *fakeStatusDelivery) Data() []byte           { return delivery.data }
func (delivery *fakeStatusDelivery) Header() nats.Header    { return delivery.header }
func (delivery *fakeStatusDelivery) Stream() string         { return delivery.stream }
func (delivery *fakeStatusDelivery) Consumer() string       { return delivery.consumer }
func (delivery *fakeStatusDelivery) StreamSequence() uint64 { return delivery.sequence }
func (delivery *fakeStatusDelivery) NumDelivered() uint64   { return delivery.delivered }
func (delivery *fakeStatusDelivery) Ack(context.Context) error {
	delivery.acks++
	if delivery.steps != nil {
		*delivery.steps = append(*delivery.steps, "ack")
	}
	return nil
}
func (delivery *fakeStatusDelivery) Nak(context.Context, time.Duration) error {
	delivery.naks++
	if delivery.steps != nil {
		*delivery.steps = append(*delivery.steps, "nak")
	}
	return nil
}
func (delivery *fakeStatusDelivery) Term(context.Context) error {
	delivery.terms++
	if delivery.steps != nil {
		*delivery.steps = append(*delivery.steps, "term")
	}
	return nil
}

type fakeStatusRuntimeStore struct {
	identity   RolloutIdentity
	recordErr  error
	rejections []RolloutStatusRejection
	steps      *[]string
}

func (store *fakeStatusRuntimeStore) ResolveStatusIdentity(context.Context, string) (RolloutIdentity, error) {
	if store.steps != nil {
		*store.steps = append(*store.steps, "resolve")
	}
	return store.identity, nil
}
func (store *fakeStatusRuntimeStore) RecordStatus(context.Context, RolloutIdentity, RolloutStatusReceipt) (bool, error) {
	if store.steps != nil {
		*store.steps = append(*store.steps, "record")
	}
	return false, store.recordErr
}
func (store *fakeStatusRuntimeStore) RejectStatus(_ context.Context, rejection RolloutStatusRejection) error {
	if store.steps != nil {
		*store.steps = append(*store.steps, "reject")
	}
	store.rejections = append(store.rejections, rejection)
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
