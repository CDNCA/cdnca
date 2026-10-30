package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCacheControlWireContractHasTenantAndDurableStatusAck(t *testing.T) {
	commandTenant := (&agentv1.CacheControlCommand{}).ProtoReflect().Descriptor().Fields().ByNumber(protoreflect.FieldNumber(17))
	statusTenant := (&agentv1.CacheControlStatus{}).ProtoReflect().Descriptor().Fields().ByNumber(protoreflect.FieldNumber(20))
	responseAck := (&agentv1.ConnectResponse{}).ProtoReflect().Descriptor().Fields().ByNumber(protoreflect.FieldNumber(8))
	if commandTenant == nil || string(commandTenant.Name()) != "tenant_id" {
		t.Fatalf("command field 17 = %v, want tenant_id", commandTenant)
	}
	if statusTenant == nil || string(statusTenant.Name()) != "tenant_id" {
		t.Fatalf("status field 20 = %v, want tenant_id", statusTenant)
	}
	if responseAck == nil || string(responseAck.Name()) != "cache_control_status_ack" {
		t.Fatalf("response field 8 = %v, want cache_control_status_ack", responseAck)
	}
}

func TestCacheCommandValidationAllowsSparseStableOrdinals(t *testing.T) {
	command := validGatewayCacheCommand()
	secondURL := "https://cache.example.test/assets/vendor.js"
	secondDigest := sha256.Sum256([]byte(secondURL))
	command.Targets = append(command.Targets, &agentv1.CacheControlTarget{
		Index: 1, TargetOrdinal: 9, CanonicalUrl: secondURL, Sha256: secondDigest[:],
	})
	gateway := testCacheGateway(t)
	if err := gateway.validateCacheControlCommand(command, command.NodeId); err != nil {
		t.Fatalf("sparse stable ordinal rejected: %v", err)
	}
	status := failedGatewayCacheStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_PARTIAL_FAILED)
	status.Results[0].State = agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS
	status.Results[0].ResultCode = "cache_task_succeeded"
	if err := gateway.validateCacheControlStatus(status, command.NodeId); err != nil {
		t.Fatalf("sparse status ordinal rejected: %v", err)
	}
}

func TestCacheValidationRejectsRecursiveProtobufUnknownFields(t *testing.T) {
	gateway := testCacheGateway(t)
	command := validGatewayCacheCommand()
	command.Targets[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := gateway.validateCacheControlCommand(command, command.NodeId); err == nil {
		t.Fatal("cache command nested unknown field was accepted")
	}
	status := deliveredGatewayCacheStatus(validGatewayCacheCommand())
	status.Event.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := gateway.validateCacheControlStatus(status, status.NodeId); err == nil {
		t.Fatal("cache status nested unknown field was accepted")
	}
	request := &agentv1.ConnectRequest{Payload: &agentv1.ConnectRequest_CacheControlStatus{CacheControlStatus: deliveredGatewayCacheStatus(validGatewayCacheCommand())}}
	request.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if !cacheControlMessageHasUnknown(request.ProtoReflect()) {
		t.Fatal("cache status envelope unknown field was accepted")
	}
}

func TestCacheCommandValidationBindsCanonicalTargets(t *testing.T) {
	target := "https://cache.example.test/assets/app.js"
	digest := sha256.Sum256([]byte(target))
	taskID := "cc-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-1"
	command := &agentv1.CacheControlCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), TaskId: &taskID,
		},
		TaskId:  taskID,
		ScopeId: "33333333-3333-4333-8333-333333333333", TenantId: "77777777-7777-4777-8777-777777777777", SiteId: "44444444-4444-4444-8444-444444444444",
		NodeId: "22222222-2222-4222-8222-222222222222", ControlOperationId: "11111111-1111-4111-8111-111111111111",
		LeaseId: "55555555-5555-4555-8555-555555555555", Attempt: 1,
		ConfigVersionId: "version-1", ConfigRevision: 7,
		Action:        agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM,
		Scope:         agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL,
		Priority:      agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL,
		RequestDigest: digest[:], DeadlineTime: timestamppb.New(time.Now().Add(time.Minute)),
		Targets: []*agentv1.CacheControlTarget{{Index: 0, TargetOrdinal: 1, CanonicalUrl: target, Sha256: digest[:]}},
	}
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.validateCacheControlCommand(command, command.NodeId); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	command.Targets[0].Sha256[0] ^= 0xff
	if err := gateway.validateCacheControlCommand(command, command.NodeId); err == nil {
		t.Fatal("target digest tampering accepted")
	}
}

func testCacheGateway(t *testing.T) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func TestCacheStatusPublishesBeforeAcknowledgingCommand(t *testing.T) {
	command := validGatewayCacheCommand()
	bus := &testCacheCommandBus{}
	delivery := &testCacheDelivery{onAck: func() error {
		if len(bus.statuses) != 1 {
			return errors.New("status was not published before acknowledgement")
		}
		return nil
	}}
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.cache = bus
	pending := pendingCacheCommandSet{
		cacheCommandIdentity(command): {command: command, deliveries: []CacheCommandDelivery{delivery}},
	}
	ack, err := gateway.persistCacheStatusAndAckCommand(context.Background(), command.NodeId, deliveredGatewayCacheStatus(command), pending)
	if err != nil {
		t.Fatal(err)
	}
	if ack == nil || ack.TaskId != command.TaskId || ack.TransitionSequence != 1 || ack.PersistedTime == nil {
		t.Fatalf("status acknowledgement=%+v", ack)
	}
	if delivery.acks != 1 || len(pending) != 0 {
		t.Fatalf("acks=%d pending=%d", delivery.acks, len(pending))
	}
}

func TestCacheStatusPublishFailureLeavesCommandUnacknowledged(t *testing.T) {
	command := validGatewayCacheCommand()
	bus := &testCacheCommandBus{publishErr: errors.New("unavailable")}
	delivery := &testCacheDelivery{}
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway.cache = bus
	pending := pendingCacheCommandSet{
		cacheCommandIdentity(command): {command: command, deliveries: []CacheCommandDelivery{delivery}},
	}
	ack, err := gateway.persistCacheStatusAndAckCommand(context.Background(), command.NodeId, deliveredGatewayCacheStatus(command), pending)
	if err == nil || ack != nil {
		t.Fatal("publish failure accepted")
	}
	if delivery.acks != 0 || len(pending) != 1 {
		t.Fatalf("acks=%d pending=%d", delivery.acks, len(pending))
	}
}

func TestCacheStatusSequenceMismatchIsNotPersistedOrAcknowledged(t *testing.T) {
	command := validGatewayCacheCommand()
	for _, test := range []struct {
		name   string
		status *agentv1.CacheControlStatus
	}{
		{name: "delivered at running sequence", status: func() *agentv1.CacheControlStatus {
			status := deliveredGatewayCacheStatus(command)
			status.TransitionSequence = 2
			return status
		}()},
		{name: "running at delivered sequence", status: func() *agentv1.CacheControlStatus {
			status := deliveredGatewayCacheStatus(command)
			status.State = agentv1.CacheControlState_CACHE_CONTROL_STATE_RUNNING
			return status
		}()},
		{name: "terminal at running sequence", status: func() *agentv1.CacheControlStatus {
			status := failedGatewayCacheStatus(command, agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED)
			status.TransitionSequence = 2
			return status
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			bus := &testCacheCommandBus{}
			delivery := &testCacheDelivery{}
			gateway := testCacheGateway(t)
			gateway.cache = bus
			pending := pendingCacheCommandSet{
				cacheCommandIdentity(command): {command: command, deliveries: []CacheCommandDelivery{delivery}},
			}
			ack, err := gateway.persistCacheStatusAndAckCommand(
				context.Background(), command.NodeId, test.status, pending,
			)
			if err == nil || ack != nil || len(bus.statuses) != 0 || delivery.acks != 0 || len(pending) != 1 {
				t.Fatalf("ack=%+v err=%v statuses=%d delivery_acks=%d pending=%d",
					ack, err, len(bus.statuses), delivery.acks, len(pending))
			}
		})
	}
}

func TestCacheStatusTenantMustMatchInFlightCommand(t *testing.T) {
	command := validGatewayCacheCommand()
	status := deliveredGatewayCacheStatus(command)
	status.TenantId = "88888888-8888-4888-8888-888888888888"
	if cacheStatusMatchesCommand(status, command) {
		t.Fatal("cache status with a different tenant matched the in-flight command")
	}
}

func TestCacheControlCapabilityRequiresVersionOne(t *testing.T) {
	capabilities := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 2,
	}}}
	if hasCacheControlCapability(capabilities) {
		t.Fatal("unsupported cache capability version accepted")
	}
	capabilities.Features[0].ApiVersion = 1
	if !hasCacheControlCapability(capabilities) {
		t.Fatal("cache capability v1 rejected")
	}
}

func TestCacheControlCapabilityRejectsDuplicateAndUnsupportedHello(t *testing.T) {
	gateway := testCacheGateway(t)
	for _, test := range []struct {
		name     string
		features []*agentv1.Capability
	}{
		{
			name: "unsupported version",
			features: []*agentv1.Capability{{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 2,
			}},
		},
		{
			name: "duplicate",
			features: []*agentv1.Capability{
				{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1},
				{Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
			hello.Capabilities.Features = test.features
			if err := gateway.validateHello(hello); err == nil {
				t.Fatal("invalid cache control capability was accepted")
			}
		})
	}

	hello := validHello(testNodeID, versionRange(1, 0), 1).GetHello()
	hello.Capabilities.Features = []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL, ApiVersion: 1,
	}}
	if err := gateway.validateHello(hello); err != nil {
		t.Fatalf("cache control capability v1 rejected: %v", err)
	}
}

func TestCacheTerminalStatusRequiresBoundResults(t *testing.T) {
	command := validGatewayCacheCommand()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-cache-test"
	config.GatewayVersion = "test"
	gateway, err := newGateway(config, defaultFakeControl(), NewMemorySessionCoordinator(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []agentv1.CacheControlState{
		agentv1.CacheControlState_CACHE_CONTROL_STATE_FAILED,
		agentv1.CacheControlState_CACHE_CONTROL_STATE_CANCELLED,
	} {
		status := failedGatewayCacheStatus(command, state)
		if err := gateway.validateCacheControlStatus(status, command.NodeId); err != nil {
			t.Fatalf("valid terminal %s rejected: %v", state, err)
		}
		status.Results = nil
		if err := gateway.validateCacheControlStatus(status, command.NodeId); err == nil {
			t.Fatalf("terminal %s without results accepted", state)
		}
		status = failedGatewayCacheStatus(command, state)
		status.Results[0].State = agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_SUCCESS
		if err := gateway.validateCacheControlStatus(status, command.NodeId); err == nil {
			t.Fatalf("terminal %s with a successful result accepted", state)
		}
	}
}

func TestCacheNAKBackoffAndDeadLetterEnvelopeAreBounded(t *testing.T) {
	if got := cacheNakDelay(1); got != 250*time.Millisecond {
		t.Fatalf("first NAK delay=%v", got)
	}
	if got := cacheNakDelay(100); got != 30*time.Second {
		t.Fatalf("bounded NAK delay=%v", got)
	}
	original := nats.NewMsg(CacheCommandSubjectPrefix + ".22222222-2222-4222-8222-222222222222")
	original.Data = []byte("command-bytes")
	original.Header.Set(nats.MsgIdHdr, "command-event")
	deadLetter := cacheDeadLetterMessage(original, CacheDeadLetterSubjectPrefix+".22222222-2222-4222-8222-222222222222")
	if deadLetter.Subject != CacheDeadLetterSubjectPrefix+".22222222-2222-4222-8222-222222222222" ||
		string(deadLetter.Data) != string(original.Data) || deadLetter.Header.Get(nats.MsgIdHdr) != "command-event.dlq" ||
		deadLetter.Header.Get("X-CDNCA-Dead-Letter-Reason") != "delivery_attempts_exhausted" {
		t.Fatalf("invalid dead letter envelope: %+v", deadLetter)
	}
}

func validGatewayCacheCommand() *agentv1.CacheControlCommand {
	target := "https://cache.example.test/assets/app.js"
	digest := sha256.Sum256([]byte(target))
	taskID := "cc-11111111-1111-4111-8111-111111111111-22222222-2222-4222-8222-222222222222-1"
	return &agentv1.CacheControlCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), TaskId: &taskID,
		},
		TaskId: taskID, ScopeId: "33333333-3333-4333-8333-333333333333", TenantId: "77777777-7777-4777-8777-777777777777", SiteId: "44444444-4444-4444-8444-444444444444",
		NodeId: "22222222-2222-4222-8222-222222222222", ControlOperationId: "11111111-1111-4111-8111-111111111111",
		LeaseId: "55555555-5555-4555-8555-555555555555", Attempt: 1, ConfigVersionId: "version-1", ConfigRevision: 7,
		Action: agentv1.CacheControlAction_CACHE_CONTROL_ACTION_PREWARM, Scope: agentv1.CacheControlScope_CACHE_CONTROL_SCOPE_URL,
		Priority: agentv1.CacheControlPriority_CACHE_CONTROL_PRIORITY_NORMAL, RequestDigest: digest[:],
		DeadlineTime: timestamppb.New(time.Now().Add(time.Minute)),
		Targets:      []*agentv1.CacheControlTarget{{Index: 0, TargetOrdinal: 1, CanonicalUrl: target, Sha256: digest[:]}},
	}
}

func deliveredGatewayCacheStatus(command *agentv1.CacheControlCommand) *agentv1.CacheControlStatus {
	causationID := command.Event.EventId
	taskID := command.TaskId
	return &agentv1.CacheControlStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
			CausationId: &causationID, TaskId: &taskID,
		},
		TaskId: command.TaskId, ScopeId: command.ScopeId, TenantId: command.TenantId, SiteId: command.SiteId, NodeId: command.NodeId,
		ControlOperationId: command.ControlOperationId, LeaseId: command.LeaseId, Attempt: command.Attempt,
		ConfigVersionId: command.ConfigVersionId, ConfigRevision: command.ConfigRevision, Action: command.Action, Scope: command.Scope,
		State: agentv1.CacheControlState_CACHE_CONTROL_STATE_DELIVERED, TransitionSequence: 1,
		RequestDigest: append([]byte(nil), command.RequestDigest...), ActiveConfigUnchanged: true,
	}
}

func failedGatewayCacheStatus(command *agentv1.CacheControlCommand, state agentv1.CacheControlState) *agentv1.CacheControlStatus {
	status := deliveredGatewayCacheStatus(command)
	status.State = state
	status.TransitionSequence = 3
	status.ErrorCode = "cache_task_unavailable"
	status.Results = make([]*agentv1.CacheControlTargetResult, 0, len(command.Targets))
	for _, target := range command.Targets {
		status.Results = append(status.Results, &agentv1.CacheControlTargetResult{
			Index: target.Index, TargetOrdinal: target.TargetOrdinal, Sha256: append([]byte(nil), target.Sha256...),
			State:      agentv1.CacheControlTargetState_CACHE_CONTROL_TARGET_STATE_FAILED,
			ResultCode: "cache_task_failed", CauseCode: "cache_task_unavailable", Attempts: 1, CompletedTime: timestamppb.Now(),
		})
	}
	return status
}

type testCacheCommandBus struct {
	statuses   []*agentv1.CacheControlStatus
	receipts   []*agentv1.CacheControlCancelReceipt
	publishErr error
}

func (b *testCacheCommandBus) SubscribeCache(context.Context, string) (CacheCommandSubscription, error) {
	return nil, errors.New("not implemented")
}

func (b *testCacheCommandBus) PublishCacheCancelReceipt(_ context.Context, _ string, receipt *agentv1.CacheControlCancelReceipt) error {
	if b.publishErr != nil {
		return b.publishErr
	}
	b.receipts = append(b.receipts, receipt)
	return nil
}

func (b *testCacheCommandBus) PublishCacheStatus(_ context.Context, _ string, status *agentv1.CacheControlStatus) error {
	if b.publishErr != nil {
		return b.publishErr
	}
	b.statuses = append(b.statuses, status)
	return nil
}

type testCacheDelivery struct {
	acks  int
	naks  int
	onAck func() error
}

func (*testCacheDelivery) Command() *agentv1.CacheControlCommand { return nil }
func (*testCacheDelivery) Cancel() *agentv1.CacheControlCancel   { return nil }

func (d *testCacheDelivery) Ack(context.Context) error {
	if d.onAck != nil {
		if err := d.onAck(); err != nil {
			return err
		}
	}
	d.acks++
	return nil
}

func (d *testCacheDelivery) Nak(context.Context) error {
	d.naks++
	return nil
}
