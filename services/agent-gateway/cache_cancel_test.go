package gateway

import (
	"context"
	"errors"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func validGatewayCacheCancel(command *agentv1.CacheControlCommand) *agentv1.CacheControlCancel {
	return &agentv1.CacheControlCancel{
		Event:    &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		CancelId: uuid.NewString(), TaskId: command.TaskId, ScopeId: command.ScopeId, TenantId: command.TenantId,
		SiteId: command.SiteId, NodeId: command.NodeId, ControlOperationId: command.ControlOperationId,
		LeaseId: command.LeaseId, Attempt: command.Attempt, RequestedTime: timestamppb.Now(),
	}
}

func gatewayCancelReceipt(cancel *agentv1.CacheControlCancel, outcome agentv1.CacheControlCancelOutcome) *agentv1.CacheControlCancelReceipt {
	causation := cancel.Event.EventId
	return &agentv1.CacheControlCancelReceipt{
		Event:    &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: cancel.Event.RequestId, OccurredTime: timestamppb.Now(), CausationId: &causation},
		CancelId: cancel.CancelId, TaskId: cancel.TaskId, NodeId: cancel.NodeId, LeaseId: cancel.LeaseId, Attempt: cancel.Attempt,
		Outcome: outcome, SettledTime: timestamppb.Now(),
	}
}

func testCancelGateway(t *testing.T, bus *testCacheCommandBus) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.cache = bus
	return gateway
}

// CACHE-ADD-07: the receipt is published before the cancel delivery is
// acknowledged; a failed publish leaves the cancel queued.
func TestCacheCancelReceiptIsPublishedBeforeAcknowledgement(t *testing.T) {
	command := validGatewayCacheCommand()
	cancel := validGatewayCacheCancel(command)
	bus := &testCacheCommandBus{}
	delivery := &testCacheDelivery{onAck: func() error {
		if len(bus.receipts) != 1 {
			return errors.New("receipt was not published before acknowledgement")
		}
		return nil
	}}
	gateway := testCancelGateway(t, bus)
	if err := gateway.validateCacheControlCancel(cancel, command.NodeId); err != nil {
		t.Fatal(err)
	}
	pending := pendingCacheCancelSet{cancel.CancelId: {cancel: cancel, deliveries: []CacheCommandDelivery{delivery}}}
	receipt := gatewayCancelReceipt(cancel, agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED)
	if err := gateway.settleCacheCancelReceipt(context.Background(), command.NodeId, receipt, pending); err != nil {
		t.Fatal(err)
	}
	if delivery.acks != 1 || len(pending) != 0 {
		t.Fatalf("acks=%d pending=%d", delivery.acks, len(pending))
	}

	failing := testCancelGateway(t, &testCacheCommandBus{publishErr: errors.New("unavailable")})
	delivery = &testCacheDelivery{}
	pending = pendingCacheCancelSet{cancel.CancelId: {cancel: cancel, deliveries: []CacheCommandDelivery{delivery}}}
	if err := failing.settleCacheCancelReceipt(context.Background(), command.NodeId, receipt, pending); err == nil ||
		delivery.acks != 0 || len(pending) != 1 {
		t.Fatalf("publish failure: err=%v acks=%d pending=%d", err, delivery.acks, len(pending))
	}
}

func TestCacheCancelValidationBindsNodeTaskAndReceipt(t *testing.T) {
	command := validGatewayCacheCommand()
	gateway := testCancelGateway(t, &testCacheCommandBus{})
	cancel := validGatewayCacheCancel(command)
	if err := gateway.validateCacheControlCancel(cancel, uuid.NewString()); err == nil {
		t.Fatal("a cancel for another node was accepted")
	}
	other := validGatewayCacheCancel(command)
	other.TaskId += "x"
	if err := gateway.validateCacheControlCancel(other, command.NodeId); err == nil {
		t.Fatal("a cancel with a forged task id was accepted")
	}
	pending := pendingCacheCancelSet{cancel.CancelId: {cancel: cancel, deliveries: []CacheCommandDelivery{&testCacheDelivery{}}}}
	for name, receipt := range map[string]*agentv1.CacheControlCancelReceipt{
		"lease":   func() *agentv1.CacheControlCancelReceipt { r := gatewayCancelReceipt(cancel, 1); r.LeaseId = uuid.NewString(); return r }(),
		"outcome": gatewayCancelReceipt(cancel, agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_UNSPECIFIED),
		"unknown": func() *agentv1.CacheControlCancelReceipt { r := gatewayCancelReceipt(cancel, 1); r.CancelId = uuid.NewString(); return r }(),
	} {
		if err := gateway.settleCacheCancelReceipt(context.Background(), command.NodeId, receipt, pending); err == nil {
			t.Fatalf("%s: receipt accepted", name)
		}
	}
	if len(pending) != 1 {
		t.Fatal("a rejected receipt settled the cancel")
	}
}

func TestCacheCancelCapabilityVersion(t *testing.T) {
	features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL, ApiVersion: 1}}
	if capable, err := cacheControlCancelCapabilityFromFeatures(features); err != nil || !capable {
		t.Fatalf("v1: %v %v", capable, err)
	}
	features[0].ApiVersion = 2
	if _, err := cacheControlCancelCapabilityFromFeatures(features); err == nil {
		t.Fatal("unknown version accepted")
	}
}
