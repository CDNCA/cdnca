package cachecontrolruntime

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeCancelStore struct {
	pending   []cachecontrol.CancelDelivery
	published []uuid.UUID
	expired   int
	settled   []cachecontrol.CancelReceipt
}

func (store *fakeCancelStore) PendingCancels(context.Context, int) ([]cachecontrol.CancelDelivery, error) {
	return store.pending, nil
}
func (store *fakeCancelStore) MarkCancelPublished(_ context.Context, id uuid.UUID) error {
	store.published = append(store.published, id)
	return nil
}
func (store *fakeCancelStore) ExpireCancels(context.Context) (int, error) { store.expired++; return 0, nil }
func (store *fakeCancelStore) SettleCancel(_ context.Context, receipt cachecontrol.CancelReceipt) (bool, error) {
	store.settled = append(store.settled, receipt)
	return true, nil
}

func testCancelDelivery() cachecontrol.CancelDelivery {
	return cachecontrol.CancelDelivery{
		ID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), ScopeID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		TenantID: uuid.MustParse("77777777-7777-4777-8777-777777777777"), SiteID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		OperationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), NodeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		Attempt: 2, LeaseID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), RequestedAt: runtimeTestNow,
	}
}

// CACHE-ADD-07: the scheduler expires overdue cancels, publishes queued
// ones bound to the attempt's task identity, and marks them published.
func TestPublishCancelsBindsTaskIdentity(t *testing.T) {
	store := &fakeCancelStore{pending: []cachecontrol.CancelDelivery{testCancelDelivery()}}
	bus := &fakeBus{}
	runtime := &Runtime{config: DefaultConfig(), cancels: store, bus: bus}
	if err := runtime.publishCancels(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.expired != 1 || len(bus.cancels) != 1 || len(store.published) != 1 || store.published[0] != store.pending[0].ID {
		t.Fatalf("expired=%d cancels=%d published=%v", store.expired, len(bus.cancels), store.published)
	}
	cancel := bus.cancels[0]
	want := "cc-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-2"
	if cancel.TaskId != want || cancel.CancelId != store.pending[0].ID.String() || cancel.Attempt != 2 ||
		cancel.LeaseId != store.pending[0].LeaseID.String() || cancel.GetEvent().GetTaskId() != want {
		t.Fatalf("cancel=%+v", cancel)
	}
	again := buildCancel(store.pending[0])
	if again.Event.EventId != cancel.Event.EventId {
		t.Fatal("a republished cancel changed its event id")
	}
}

func cancelReceiptDelivery(t *testing.T, config Config, receipt *agentv1.CacheControlCancelReceipt) *fakeDelivery {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeDelivery{subject: config.StatusSubjectPrefix + "." + receipt.NodeId, kind: cancelReceiptKind, data: payload, delivered: 1}
}

func TestProcessCancelReceiptMapsOutcomes(t *testing.T) {
	config := DefaultConfig()
	delivery := testCancelDelivery()
	for outcome, want := range map[agentv1.CacheControlCancelOutcome]cachecontrol.CancelConfirmation{
		agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED:         cachecontrol.CancelConfirmed,
		agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_ALREADY_COMPLETED: cachecontrol.CancelCompleted,
		agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED:      cachecontrol.CancelUnresponsive,
	} {
		receipt := &agentv1.CacheControlCancelReceipt{
			Event:    &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
			CancelId: delivery.ID.String(), TaskId: buildCancel(delivery).TaskId, NodeId: delivery.NodeID.String(),
			LeaseId: delivery.LeaseID.String(), Attempt: delivery.Attempt, Outcome: outcome,
			SucceededTargets: 1, CancelledTargets: 2, SettledTime: timestamppb.New(runtimeTestNow.Add(time.Second)),
		}
		store := &fakeCancelStore{}
		source := cancelReceiptDelivery(t, config, receipt)
		runtime := &Runtime{config: config, cancels: store, bus: &fakeBus{}, consumer: &fakeConsumer{delivery: source}}
		disposition, err := runtime.ProcessStatusOnce(context.Background())
		if err != nil || disposition != DispositionAck || source.acks != 1 || len(store.settled) != 1 {
			t.Fatalf("%v: disposition=%q err=%v source=%+v", outcome, disposition, err, source)
		}
		settled := store.settled[0]
		if settled.Outcome != want || settled.DeliveryID != delivery.ID || settled.SucceededTargets != 1 || settled.CancelledTargets != 2 {
			t.Fatalf("%v: settled=%+v", outcome, settled)
		}
	}
}

func TestProcessCancelReceiptQuarantinesInvalid(t *testing.T) {
	config := DefaultConfig()
	delivery := testCancelDelivery()
	receipt := &agentv1.CacheControlCancelReceipt{
		Event:    &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		CancelId: delivery.ID.String(), NodeId: delivery.NodeID.String(), LeaseId: delivery.LeaseID.String(), Attempt: 1,
		Outcome: agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_UNSPECIFIED, SettledTime: timestamppb.Now(),
	}
	store := &fakeCancelStore{}
	bus := &fakeBus{}
	source := cancelReceiptDelivery(t, config, receipt)
	runtime := &Runtime{config: config, cancels: store, bus: bus, consumer: &fakeConsumer{delivery: source}}
	if _, err := runtime.ProcessStatusOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.settled) != 0 || bus.dlq != 1 {
		t.Fatalf("an invalid receipt was settled: settled=%d dlq=%d", len(store.settled), bus.dlq)
	}
	receipt.Outcome = agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED
	source = cancelReceiptDelivery(t, config, receipt)
	source.subject = config.StatusSubjectPrefix + "." + uuid.NewString()
	runtime.consumer = &fakeConsumer{delivery: source}
	if _, err := runtime.ProcessStatusOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.settled) != 0 || bus.dlq != 2 {
		t.Fatalf("a receipt on another node's subject was settled: settled=%d dlq=%d", len(store.settled), bus.dlq)
	}
}
