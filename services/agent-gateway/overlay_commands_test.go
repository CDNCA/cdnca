package gateway

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeOverlayBus struct {
	subscription *fakeOverlaySubscription
	publishErr   error
	mu           sync.Mutex
	published    []*agentv1.AcmeHTTP01OverlayStatus
}

func (b *fakeOverlayBus) SubscribeOverlay(context.Context, string) (OverlayCommandSubscription, error) {
	if b.subscription == nil {
		b.subscription = &fakeOverlaySubscription{deliveries: make(chan OverlayCommandDelivery, 8), closed: make(chan struct{})}
	}
	return b.subscription, nil
}

func (b *fakeOverlayBus) PublishOverlayStatus(_ context.Context, _ string, value *agentv1.AcmeHTTP01OverlayStatus) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.publishErr != nil {
		return b.publishErr
	}
	b.published = append(b.published, proto.Clone(value).(*agentv1.AcmeHTTP01OverlayStatus))
	return nil
}

type fakeOverlaySubscription struct {
	deliveries chan OverlayCommandDelivery
	closed     chan struct{}
	closeOnce  sync.Once
}

func (s *fakeOverlaySubscription) Next(ctx context.Context) (OverlayCommandDelivery, error) {
	select {
	case value := <-s.deliveries:
		return value, nil
	case <-s.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeOverlaySubscription) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type fakeOverlayDelivery struct {
	command *agentv1.AcmeHTTP01OverlayCommand
	ack     func() error
	acks    atomic.Int32
	naks    atomic.Int32
}

func (d *fakeOverlayDelivery) Command() *agentv1.AcmeHTTP01OverlayCommand { return d.command }
func (d *fakeOverlayDelivery) Ack(context.Context) error {
	d.acks.Add(1)
	if d.ack != nil {
		return d.ack()
	}
	return nil
}
func (d *fakeOverlayDelivery) Nak(context.Context) error { d.naks.Add(1); return nil }

func TestOverlayStatusPersistsBeforeCommandAck(t *testing.T) {
	bus := &fakeOverlayBus{}
	gateway := newOverlayGateway(t, bus)
	command := validOverlayCommand()
	delivery := &fakeOverlayDelivery{command: command, ack: func() error {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		if len(bus.published) != 1 {
			t.Fatal("overlay command was acknowledged before durable status publication")
		}
		return nil
	}}
	pending := pendingOverlayCommandSet{overlayCommandKey(command): {
		command: command, deliveries: []OverlayCommandDelivery{delivery},
	}}
	if err := gateway.persistOverlayStatusAndAckCommand(context.Background(), testNodeID, validOverlayStatus(command), pending); err != nil {
		t.Fatal(err)
	}
	if delivery.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("acks=%d pending=%d", delivery.acks.Load(), len(pending))
	}
}

func TestOverlayStatusIdentityConflictDoesNotPersistOrAck(t *testing.T) {
	bus := &fakeOverlayBus{}
	gateway := newOverlayGateway(t, bus)
	command := validOverlayCommand()
	delivery := &fakeOverlayDelivery{command: command}
	pending := pendingOverlayCommandSet{overlayCommandKey(command): {
		command: command, deliveries: []OverlayCommandDelivery{delivery},
	}}
	for _, mutate := range []func(*agentv1.AcmeHTTP01OverlayStatus){
		func(value *agentv1.AcmeHTTP01OverlayStatus) { value.OverlayRevision++ },
		func(value *agentv1.AcmeHTTP01OverlayStatus) {
			other := uuid.NewString()
			value.Event.CausationId = &other
		},
		func(value *agentv1.AcmeHTTP01OverlayStatus) { value.Event.RequestId = uuid.NewString() },
	} {
		value := validOverlayStatus(command)
		mutate(value)
		err := gateway.persistOverlayStatusAndAckCommand(context.Background(), testNodeID, value, pending)
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("identity conflict code = %v", status.Code(err))
		}
	}
	if len(bus.published) != 0 || delivery.acks.Load() != 0 || len(pending) != 1 {
		t.Fatalf("published=%d acks=%d pending=%d", len(bus.published), delivery.acks.Load(), len(pending))
	}
}

func TestOverlayStatusPublishFailureKeepsDeliveryPending(t *testing.T) {
	bus := &fakeOverlayBus{publishErr: errors.New("status stream unavailable")}
	gateway := newOverlayGateway(t, bus)
	command := validOverlayCommand()
	delivery := &fakeOverlayDelivery{command: command}
	pending := pendingOverlayCommandSet{overlayCommandKey(command): {
		command: command, deliveries: []OverlayCommandDelivery{delivery},
	}}
	err := gateway.persistOverlayStatusAndAckCommand(context.Background(), testNodeID, validOverlayStatus(command), pending)
	if status.Code(err) != codes.Unavailable || delivery.acks.Load() != 0 || len(pending) != 1 {
		t.Fatalf("code=%v acks=%d pending=%d", status.Code(err), delivery.acks.Load(), len(pending))
	}
}

func TestStopSessionOverlayCommandsNaksPendingAndInflight(t *testing.T) {
	subscription := &fakeOverlaySubscription{deliveries: make(chan OverlayCommandDelivery, 1), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	source := &sessionOverlayCommandSource{ctx: ctx, cancel: cancel, subscription: subscription}
	pendingDelivery := &fakeOverlayDelivery{command: validOverlayCommand()}
	inflightDelivery := &fakeOverlayDelivery{command: validOverlayCommand()}
	pending := pendingOverlayCommandSet{overlayCommandKey(pendingDelivery.command): {
		command: pendingDelivery.command, deliveries: []OverlayCommandDelivery{pendingDelivery},
	}}
	source.arm()
	subscription.deliveries <- inflightDelivery
	waitForTest(t, time.Second, func() bool { return len(source.next) == 1 })
	stopSessionOverlayCommands(source, pending, time.Second)
	if pendingDelivery.naks.Load() != 1 || inflightDelivery.naks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("pending_naks=%d inflight_naks=%d pending=%d", pendingDelivery.naks.Load(), inflightDelivery.naks.Load(), len(pending))
	}
}

func TestACMEHTTP01OverlayCapabilityRequiresVersionOne(t *testing.T) {
	tests := []struct {
		name         string
		capabilities *agentv1.AgentCapabilities
		want         bool
	}{
		{name: "missing"},
		{name: "nil feature", capabilities: &agentv1.AgentCapabilities{Features: []*agentv1.Capability{nil}}},
		{name: "wrong capability", capabilities: &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}}}},
		{name: "old overlay API", capabilities: &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, ApiVersion: 2}}}},
		{name: "overlay API v1", capabilities: &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, ApiVersion: 1}}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasACMEHTTP01OverlayCapability(test.capabilities); got != test.want {
				t.Fatalf("hasACMEHTTP01OverlayCapability() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestACMEHTTP01OverlayStatusLegalityMatrix(t *testing.T) {
	tests := []struct {
		name       string
		state      agentv1.AcmeHTTP01OverlayState
		result     agentv1.AcmeHTTP01OverlayResultCode
		hasError   bool
		wantResult bool
		wantError  bool
	}{
		{name: "delivered", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, wantResult: true, wantError: true},
		{name: "delivered with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, hasError: true, wantResult: true},
		{name: "healthy", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK, wantResult: true, wantError: true},
		{name: "healthy failure result", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_HEALTHY, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, wantError: true},
		{name: "failed without error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED, wantResult: true},
		{name: "failed with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ACTIVATION_FAILED, hasError: true, wantResult: true, wantError: true},
		{name: "reverting transition", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, wantResult: true, wantError: true},
		{name: "reverting with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTING, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_HEALTH_FAILED, hasError: true, wantResult: true, wantError: true},
		{name: "reverted transition", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK, wantResult: true, wantError: true},
		{name: "reverted terminal error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_REVERTED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLED_BACK, hasError: true, wantResult: true, wantError: true},
		{name: "rollback failed without error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED, wantResult: true},
		{name: "rollback failed with error", state: agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_ROLLBACK_FAILED, result: agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_ROLLBACK_FAILED, hasError: true, wantResult: true, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validACMEHTTP01OverlayStateResult(test.state, test.result); got != test.wantResult {
				t.Fatalf("state/result legality = %v, want %v", got, test.wantResult)
			}
			if got := validACMEHTTP01OverlayErrorPresence(test.state, test.hasError); got != test.wantError {
				t.Fatalf("error presence legality = %v, want %v", got, test.wantError)
			}
		})
	}
}

func TestOverlayCapabilityGatesMixedVersionSession(t *testing.T) {
	t.Run("old agent leaves overlay command pending and rejects status", func(t *testing.T) {
		bus := &fakeOverlayBus{}
		gateway := newOverlayGateway(t, bus)
		lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		command := validOverlayCommand()
		received := make(chan connectReceive, 1)
		received <- connectReceive{request: &agentv1.ConnectRequest{
			Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
			Payload: &agentv1.ConnectRequest_AcmeHttp01OverlayStatus{
				AcmeHttp01OverlayStatus: validOverlayStatus(command),
			},
		}}
		err = gateway.serveSession(
			&capturingBidiStream{ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 1)},
			received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "legacy", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false,
		)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("status code = %v, want PermissionDenied", status.Code(err))
		}
		if bus.subscription == nil || len(bus.published) != 0 {
			t.Fatalf("old agent overlay subscription=%v published=%d", bus.subscription != nil, len(bus.published))
		}
	})

	t.Run("old agent command fails fast without delivery", func(t *testing.T) {
		bus := &fakeOverlayBus{subscription: &fakeOverlaySubscription{
			deliveries: make(chan OverlayCommandDelivery, 1), closed: make(chan struct{}),
		}}
		gateway := newOverlayGateway(t, bus)
		delivery := &fakeOverlayDelivery{command: validOverlayCommand()}
		bus.subscription.deliveries <- delivery
		lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
		done := make(chan error, 1)
		go func() {
			done <- gateway.serveSession(
				stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "legacy", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false,
			)
		}()
		waitForTest(t, time.Second, func() bool { return delivery.acks.Load() == 1 })
		bus.mu.Lock()
		if len(bus.published) != 1 || bus.published[0].State != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED ||
			bus.published[0].ResultCode != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSUPPORTED {
			t.Fatalf("unsupported status = %+v", bus.published)
		}
		bus.mu.Unlock()
		select {
		case response := <-stream.sent:
			t.Fatalf("unsupported agent received overlay command: %+v", response)
		default:
		}
		cancel()
		if err := <-done; status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
	})

	t.Run("capable agent receives overlay command", func(t *testing.T) {
		bus := &fakeOverlayBus{subscription: &fakeOverlaySubscription{
			deliveries: make(chan OverlayCommandDelivery, 1), closed: make(chan struct{}),
		}}
		gateway := newOverlayGateway(t, bus)
		delivery := &fakeOverlayDelivery{command: validOverlayCommand()}
		bus.subscription.deliveries <- delivery
		lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
		done := make(chan error, 1)
		go func() {
			done <- gateway.serveSession(
				stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "current", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, true,
			)
		}()
		select {
		case response := <-stream.sent:
			if !proto.Equal(response.GetAcmeHttp01OverlayCommand(), delivery.command) {
				t.Fatalf("overlay response = %+v", response)
			}
		case <-time.After(time.Second):
			t.Fatal("capable agent did not receive overlay command")
		}
		cancel()
		if err := <-done; status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
		if delivery.acks.Load() != 0 || delivery.naks.Load() != 1 {
			t.Fatalf("overlay delivery acks=%d naks=%d", delivery.acks.Load(), delivery.naks.Load())
		}
	})
}

func newOverlayGateway(t *testing.T, overlay OverlayCommandBus) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-overlay-test"
	config.GatewayVersion = "test"
	gateway, err := NewWithOverlayMessaging(
		config, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{}, overlay, &fakeHeartbeatSink{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func validOverlayCommand() *agentv1.AcmeHTTP01OverlayCommand {
	return &agentv1.AcmeHTTP01OverlayCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(),
			CorrelationId: uuid.NewString(),
		},
		OverlayDeploymentId: uuid.NewString(), Attempt: 1,
		OverlayVersionId: uuid.NewString(), OverlayRevision: 1,
		Artifact: &agentv1.ArtifactDescriptor{
			ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_ACME_HTTP01_OVERLAY,
			SizeBytes: 1, Sha256: make([]byte, 32), Signature: make([]byte, 64), SigningKeyId: "overlay-signing-key",
			SignatureAlgorithm: agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:        agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE, MediaType: acmeHTTP01OverlayMediaType,
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Minute), ObservationWindowDuration: durationpb.New(time.Second),
			RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
		Purpose:      agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_APPLY,
	}
}

func cleanupOnlyOverlayCommand() *agentv1.AcmeHTTP01OverlayCommand {
	command := validOverlayCommand()
	command.Purpose = agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_CLEANUP_ONLY
	return command
}

func TestValidateOverlayCommandRequiresKnownPurpose(t *testing.T) {
	gateway := newOverlayGateway(t, &fakeOverlayBus{})
	for _, purpose := range []agentv1.AcmeHTTP01OverlayPurpose{
		agentv1.AcmeHTTP01OverlayPurpose_ACME_HTTP01_OVERLAY_PURPOSE_UNSPECIFIED, 3,
	} {
		command := validOverlayCommand()
		command.Purpose = purpose
		if err := gateway.validateACMEHTTP01OverlayCommand(command); err == nil {
			t.Fatalf("purpose %v accepted", purpose)
		}
	}
	if err := gateway.validateACMEHTTP01OverlayCommand(cleanupOnlyOverlayCommand()); err != nil {
		t.Fatal(err)
	}
}

// ADR-0003: a node whose session does not allow deployments (draining) still
// receives CLEANUP_ONLY overlays and reports their status; an APPLY overlay is
// answered UNSUPPORTED for it and never relayed.
func TestOverlayRelayWithoutDeployments(t *testing.T) {
	run := func(t *testing.T, delivery *fakeOverlayDelivery, received chan connectReceive) (*fakeOverlayBus, *capturingBidiStream, func() error) {
		bus := &fakeOverlayBus{subscription: &fakeOverlaySubscription{
			deliveries: make(chan OverlayCommandDelivery, 1), closed: make(chan struct{}),
		}}
		if delivery != nil {
			bus.subscription.deliveries <- delivery
		}
		gateway := newOverlayGateway(t, bus)
		lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 1)}
		done := make(chan error, 1)
		go func() {
			done <- gateway.serveSession(
				stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
				nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "current", versionRange(1, 0),
				&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), false, true,
			)
		}()
		return bus, stream, func() error {
			cancel()
			lease.Release()
			return <-done
		}
	}

	t.Run("cleanup_only is relayed", func(t *testing.T) {
		delivery := &fakeOverlayDelivery{command: cleanupOnlyOverlayCommand()}
		_, stream, stop := run(t, delivery, make(chan connectReceive))
		select {
		case response := <-stream.sent:
			if !proto.Equal(response.GetAcmeHttp01OverlayCommand(), delivery.command) {
				t.Fatalf("overlay response = %+v", response)
			}
		case <-time.After(time.Second):
			t.Fatal("draining node did not receive its cleanup_only overlay")
		}
		if err := stop(); status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
	})

	t.Run("apply is answered unsupported", func(t *testing.T) {
		delivery := &fakeOverlayDelivery{command: validOverlayCommand()}
		bus, stream, stop := run(t, delivery, make(chan connectReceive))
		waitForTest(t, time.Second, func() bool { return delivery.acks.Load() == 1 })
		bus.mu.Lock()
		if len(bus.published) != 1 || bus.published[0].State != agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_FAILED ||
			bus.published[0].ResultCode != agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_UNSUPPORTED ||
			bus.published[0].Event.GetCausationId() != delivery.command.Event.EventId {
			t.Fatalf("unsupported status = %+v", bus.published)
		}
		bus.mu.Unlock()
		select {
		case response := <-stream.sent:
			t.Fatalf("apply overlay relayed without deployments: %+v", response)
		default:
		}
		if err := stop(); status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
	})

	t.Run("status is accepted", func(t *testing.T) {
		received := make(chan connectReceive, 1)
		received <- connectReceive{request: &agentv1.ConnectRequest{
			Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
			Payload: &agentv1.ConnectRequest_AcmeHttp01OverlayStatus{
				AcmeHttp01OverlayStatus: validOverlayStatus(cleanupOnlyOverlayCommand()),
			},
		}}
		bus, _, stop := run(t, nil, received)
		waitForTest(t, time.Second, func() bool {
			bus.mu.Lock()
			defer bus.mu.Unlock()
			return len(bus.published) == 1
		})
		if err := stop(); status.Code(err) != codes.Canceled {
			t.Fatalf("serveSession() code = %v, want Canceled", status.Code(err))
		}
	})
}

func validOverlayStatus(command *agentv1.AcmeHTTP01OverlayCommand) *agentv1.AcmeHTTP01OverlayStatus {
	causation := command.Event.EventId
	return &agentv1.AcmeHTTP01OverlayStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(),
			Traceparent: command.Event.Traceparent, CausationId: &causation,
			CorrelationId: command.Event.CorrelationId, TaskId: command.Event.TaskId,
		},
		OverlayDeploymentId: command.OverlayDeploymentId, Attempt: command.Attempt,
		OverlayVersionId: command.OverlayVersionId, OverlayRevision: command.OverlayRevision,
		State:              agentv1.AcmeHTTP01OverlayState_ACME_HTTP01_OVERLAY_STATE_DELIVERED,
		TransitionSequence: 1, ActiveOverlayUnchanged: true,
		ResultCode:        agentv1.AcmeHTTP01OverlayResultCode_ACME_HTTP01_OVERLAY_RESULT_CODE_OK,
		ActivationSummary: "overlay command delivered",
	}
}

// FX05①: the production gateway enables overlay relaying with this setter.
func TestConfigureOverlayMessaging(t *testing.T) {
	var nilBus *fakeOverlayBus
	if err := (&Gateway{}).ConfigureOverlayMessaging(nilBus); err == nil {
		t.Fatal("nil overlay bus accepted")
	}
	gateway := &Gateway{}
	bus := &fakeOverlayBus{}
	if err := gateway.ConfigureOverlayMessaging(bus); err != nil || gateway.overlays != bus {
		t.Fatalf("configure: %v", err)
	}
	if err := gateway.ConfigureOverlayMessaging(bus); err == nil {
		t.Fatal("overlay bus configured twice")
	}
}
