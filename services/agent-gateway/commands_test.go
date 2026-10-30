package gateway

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)


type fakeCommandBus struct {
	subscription *fakeCommandSubscription
	publishErr   error
	publication  DeploymentStatusPublication

	mu        sync.Mutex
	published []*agentv1.DeploymentStatus
}

func (b *fakeCommandBus) Subscribe(context.Context, string) (CommandSubscription, error) {
	if b.subscription == nil {
		b.subscription = newFakeCommandSubscription()
	}
	b.subscription.subscribed.Add(1)
	return b.subscription, nil
}

func (b *fakeCommandBus) PublishStatus(_ context.Context, _ string,
	deploymentStatus *agentv1.DeploymentStatus,
) (DeploymentStatusPublication, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.publishErr != nil {
		return DeploymentStatusPublication{}, b.publishErr
	}
	b.published = append(b.published, deploymentStatus)
	if b.publication == (DeploymentStatusPublication{}) {
		return DeploymentStatusPublication{Stream: DefaultNATSCommandBusConfig().StatusStream, Sequence: 41}, nil
	}
	return b.publication, nil
}

type fakeCommandSubscription struct {
	deliveries chan CommandDelivery
	closed     chan struct{}
	closeOnce  sync.Once
	subscribed atomic.Int32
}

func newFakeCommandSubscription() *fakeCommandSubscription {
	return &fakeCommandSubscription{deliveries: make(chan CommandDelivery, 8), closed: make(chan struct{})}
}

func (s *fakeCommandSubscription) Next(ctx context.Context) (CommandDelivery, error) {
	select {
	case delivery := <-s.deliveries:
		return delivery, nil
	case <-s.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakeCommandSubscription) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

type fakeCommandDelivery struct {
	command *agentv1.DeploymentCommand
	ack     func() error
	acks    atomic.Int32
	naks    atomic.Int32
}

func (d *fakeCommandDelivery) Command() *agentv1.DeploymentCommand { return d.command }
func (d *fakeCommandDelivery) Ack(context.Context) error {
	d.acks.Add(1)
	if d.ack != nil {
		return d.ack()
	}
	return nil
}
func (d *fakeCommandDelivery) Nak(context.Context) error { d.naks.Add(1); return nil }

func TestDeploymentStatusPersistsBeforeCommandAck(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	statusUpdate := validDeploymentStatus(command)
	order := make([]string, 0, 2)
	delivery := &fakeCommandDelivery{command: command, ack: func() error {
		bus.mu.Lock()
		defer bus.mu.Unlock()
		if len(bus.published) != 1 {
			t.Fatal("command was acknowledged before durable status publication")
		}
		order = append(order, "ack")
		return nil
	}}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
	bus.mu.Lock()
	order = append(order, "publish")
	bus.mu.Unlock()

	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pending); err != nil {
		t.Fatalf("persistStatusAndAckCommand() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"publish", "ack"}) || delivery.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("order=%v acks=%d pending=%d", order, delivery.acks.Load(), len(pending))
	}
}

func TestDeploymentStatusPublishFailureDoesNotAckCommand(t *testing.T) {
	bus := &fakeCommandBus{publishErr: errors.New("status stream unavailable")}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	delivery := &fakeCommandDelivery{command: command}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}

	err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, validDeploymentStatus(command), pending)
	if status.Code(err) != codes.Unavailable || delivery.acks.Load() != 0 || len(pending) != 1 {
		t.Fatalf("result=%v acks=%d pending=%d", status.Code(err), delivery.acks.Load(), len(pending))
	}
}

func TestDeploymentStatusAcknowledgesEveryDuplicateDelivery(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validRollbackDeploymentCommand()
	first := &fakeCommandDelivery{command: command}
	second := &fakeCommandDelivery{command: command}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{first, second},
	}}

	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, validDeploymentStatus(command), pending); err != nil {
		t.Fatal(err)
	}
	if first.acks.Load() != 1 || second.acks.Load() != 1 || len(pending) != 0 {
		t.Fatalf("first=%d second=%d pending=%d", first.acks.Load(), second.acks.Load(), len(pending))
	}
}

func TestCommandAckFailureKeepsPendingAfterStatusPersistence(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	delivery := &fakeCommandDelivery{command: command, ack: func() error { return errors.New("ack confirmation unavailable") }}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}

	err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, validDeploymentStatus(command), pending)
	if status.Code(err) != codes.Unavailable || len(bus.published) != 1 || len(pending) != 1 {
		t.Fatalf("code=%v published=%d pending=%d", status.Code(err), len(bus.published), len(pending))
	}
}

func TestCommandPartialAckFailureRetriesOnlyUnacknowledgedDeliveries(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	first := &fakeCommandDelivery{command: command}
	var failSecond atomic.Bool
	failSecond.Store(true)
	second := &fakeCommandDelivery{command: command, ack: func() error {
		if failSecond.Swap(false) {
			return errors.New("ack confirmation unavailable")
		}
		return nil
	}}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{first, second},
	}}
	statusUpdate := validDeploymentStatus(command)

	err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pending)
	if status.Code(err) != codes.Unavailable || first.acks.Load() != 1 || second.acks.Load() != 1 {
		t.Fatalf("first attempt: code=%v first=%d second=%d", status.Code(err), first.acks.Load(), second.acks.Load())
	}
	if len(pending) != 1 || len(pending[commandKey(command)].deliveries) != 1 {
		t.Fatalf("pending deliveries after partial failure = %+v", pending)
	}

	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pending); err != nil {
		t.Fatal(err)
	}
	if first.acks.Load() != 1 || second.acks.Load() != 2 || len(pending) != 0 || len(bus.published) != 2 {
		t.Fatalf("retry: first=%d second=%d pending=%d published=%d", first.acks.Load(), second.acks.Load(), len(pending), len(bus.published))
	}
}

func TestDuplicateDeploymentStatusIsDurableWithoutPendingCommand(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	statusUpdate := validDeploymentStatus(validDeploymentCommand())

	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pendingCommandSet{}); err != nil {
		t.Fatal(err)
	}
	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, statusUpdate, pendingCommandSet{}); err != nil {
		t.Fatal(err)
	}
	if len(bus.published) != 2 {
		t.Fatalf("published statuses = %d, want 2 bus attempts", len(bus.published))
	}
}

func TestDeploymentAuthorizationRefreshEnablesCommands(t *testing.T) {
	state := allowedAuthorization(time.Hour)
	state.deploymentsAllowed = true
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{state}}
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, control, bus, func(config *Config) {
		config.HeartbeatInterval = 10 * time.Millisecond
		config.OfflineAfter = time.Second
	})
	delivery := &fakeCommandDelivery{command: validDeploymentCommand()}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(40*time.Millisecond), false, false,
		)
	}()
	select {
	case response := <-stream.sent:
		if response.GetDeploymentCommand() == nil {
			t.Fatalf("response = %+v, want command", response)
		}
	case <-time.After(time.Second):
		t.Fatal("authorization refresh did not enable command delivery")
	}
	cancel()
	<-done
	if bus.subscription.subscribed.Load() != 1 || delivery.naks.Load() != 1 {
		t.Fatalf("subscriptions=%d naks=%d", bus.subscription.subscribed.Load(), delivery.naks.Load())
	}
}

func TestCommandSendFailureNaksWithoutAck(t *testing.T) {
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	delivery := &fakeCommandDelivery{command: validDeploymentCommand()}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	stream := &capturingBidiStream{ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 1), sendErr: errors.New("connection closed")}

	err = gateway.serveSession(
		stream, make(chan connectReceive), lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
		nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
		&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), true, false,
	)
	if status.Code(err) != codes.Unknown || delivery.acks.Load() != 0 || delivery.naks.Load() != 1 {
		t.Fatalf("code=%v acks=%d naks=%d", status.Code(err), delivery.acks.Load(), delivery.naks.Load())
	}
}

func TestDeploymentAuthorizationRefreshDrainingRevokesPendingCommands(t *testing.T) {
	state := allowedAuthorization(time.Hour)
	state.administrative = controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING
	state.deploymentsAllowed = true
	control := &scriptedControl{fakeControl: defaultFakeControl(), states: []authorizationState{state}}
	bus := &fakeCommandBus{subscription: newFakeCommandSubscription()}
	gateway := newCommandGateway(t, control, bus, func(config *Config) {
		config.HeartbeatInterval = 10 * time.Millisecond
		config.OfflineAfter = time.Second
	})
	command := validDeploymentCommand()
	delivery := &fakeCommandDelivery{command: command}
	bus.subscription.deliveries <- delivery
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	received := make(chan connectReceive, 1)
	stream := &capturingBidiStream{ctx: context.Background(), sent: make(chan *agentv1.ConnectResponse, 4)}
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(40*time.Millisecond), true, false,
		)
	}()
	select {
	case response := <-stream.sent:
		if response.GetDeploymentCommand() == nil {
			t.Fatalf("response = %+v, want command", response)
		}
	case <-time.After(time.Second):
		t.Fatal("initially authorized command was not delivered")
	}
	waitForTest(t, time.Second, func() bool { return delivery.naks.Load() == 1 })
	received <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_DeploymentStatus{DeploymentStatus: validDeploymentStatus(command)},
	}}
	select {
	case err := <-done:
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("status after authorization revocation = %v", status.Code(err))
		}
	case <-time.After(time.Second):
		t.Fatal("revoked deployment status did not terminate the session")
	}
	if delivery.acks.Load() != 0 || bus.subscription.subscribed.Load() != 1 {
		t.Fatalf("acks=%d subscriptions=%d", delivery.acks.Load(), bus.subscription.subscribed.Load())
	}
}

func TestDeploymentStatusValidation(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	command := validDeploymentCommand()
	tests := []struct {
		name   string
		change func(*agentv1.DeploymentStatus)
	}{
		{name: "missing event", change: func(value *agentv1.DeploymentStatus) { value.Event = nil }},
		{name: "zero attempt", change: func(value *agentv1.DeploymentStatus) { value.Attempt = 0 }},
		{name: "unknown state", change: func(value *agentv1.DeploymentStatus) { value.State = 99 }},
		{name: "zero transition", change: func(value *agentv1.DeploymentStatus) { value.TransitionSequence = 0 }},
		{name: "failed changed runtime", change: func(value *agentv1.DeploymentStatus) {
			value.State = agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED
			value.RunningConfigUnchanged = false
		}},
		{name: "duplicate checks", change: func(value *agentv1.DeploymentStatus) {
			value.Checks = []*agentv1.CheckResult{{Name: "openresty", LatencyDuration: durationpb.New(time.Millisecond)}, {Name: "openresty", LatencyDuration: durationpb.New(time.Millisecond)}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validDeploymentStatus(command)
			test.change(value)
			if err := gateway.validateDeploymentStatus(value); err == nil {
				t.Fatal("invalid status was accepted")
			}
		})
	}
	if err := gateway.validateDeploymentStatus(validDeploymentStatus(command)); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
}

func TestDeploymentCommandValidation(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	tests := []struct {
		name   string
		change func(*agentv1.DeploymentCommand)
	}{
		{name: "unknown command field", change: func(value *agentv1.DeploymentCommand) {
			value.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown event field", change: func(value *agentv1.DeploymentCommand) {
			value.Event.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown event time field", change: func(value *agentv1.DeploymentCommand) {
			value.Event.OccurredTime.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown artifact field", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown health check field", change: func(value *agentv1.DeploymentCommand) {
			value.HealthCheck.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown health duration field", change: func(value *agentv1.DeploymentCommand) {
			value.HealthCheck.ActivationTimeoutDuration.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "unknown deadline field", change: func(value *agentv1.DeploymentCommand) {
			value.DeadlineTime.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "missing event", change: func(value *agentv1.DeploymentCommand) { value.Event = nil }},
		{name: "zero attempt", change: func(value *agentv1.DeploymentCommand) { value.Attempt = 0 }},
		{name: "unknown action", change: func(value *agentv1.DeploymentCommand) { value.Action = 99 }},
		{name: "duplicate artifacts", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts = append(value.Artifacts, value.Artifacts[0])
		}},
		{name: "unencrypted secret", change: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE
		}},
		{name: "missing health check", change: func(value *agentv1.DeploymentCommand) { value.HealthCheck = nil }},
		{name: "invalid deadline", change: func(value *agentv1.DeploymentCommand) { value.DeadlineTime = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validDeploymentCommand()
			test.change(value)
			if err := gateway.validateDeploymentCommand(value, "artifact-key"); err == nil {
				t.Fatal("invalid command was accepted")
			}
		})
	}
	if err := gateway.validateDeploymentCommand(validDeploymentCommand(), "artifact-key"); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
}

func TestDeploymentCommandArtifactContract(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	tests := []struct {
		name    string
		command func() *agentv1.DeploymentCommand
		wantErr string
	}{
		{name: "rollback without artifacts", command: validRollbackDeploymentCommand},
		{name: "rollback with extra artifact", command: func() *agentv1.DeploymentCommand {
			value := validRollbackDeploymentCommand()
			value.Artifacts = validDeploymentCommand().Artifacts
			return value
		}, wantErr: "rollback command must not include artifacts"},
		{name: "rollback with forged artifact", command: func() *agentv1.DeploymentCommand {
			value := validRollbackDeploymentCommand()
			value.Artifacts = validDeploymentCommand().Artifacts
			value.Artifacts[0].Signature = []byte("forged")
			return value
		}, wantErr: "rollback command must not include artifacts"},
		{name: "apply without artifacts", command: func() *agentv1.DeploymentCommand {
			value := validDeploymentCommand()
			value.Artifacts = nil
			return value
		}, wantErr: "command artifacts are missing"},
		{name: "reconcile without artifacts", command: func() *agentv1.DeploymentCommand {
			value := validDeploymentCommand()
			value.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_RECONCILE
			value.Artifacts = nil
			return value
		}, wantErr: "command artifacts are missing"},
		{name: "unknown action", command: func() *agentv1.DeploymentCommand {
			value := validDeploymentCommand()
			value.Action = agentv1.DeploymentAction(99)
			value.Artifacts = nil
			return value
		}, wantErr: "command action is invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := gateway.validateDeploymentCommand(test.command(), "artifact-key")
			if test.wantErr == "" && err != nil {
				t.Fatalf("valid command rejected: %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("validation error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestDeploymentCommandConfigurationScopeFieldContract(t *testing.T) {
	field := (&agentv1.DeploymentCommand{}).ProtoReflect().Descriptor().Fields().ByNumber(12)
	if field == nil || field.Name() != "configuration_scope_id" || field.Kind() != protoreflect.StringKind || !field.HasOptionalKeyword() {
		t.Fatalf("DeploymentCommand field 12 = %v, want optional string configuration_scope_id", field)
	}
}

// A command requiring a site runtime capability must be a site object
// release; the whole site runtime bundle is rejected.
func TestSiteRuntimeBundleDeploymentCommandRejected(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	legacy := validDeploymentCommand()
	if err := gateway.validateDeploymentCommand(legacy, "artifact-key"); err != nil {
		t.Fatalf("command without site runtime capability rejected: %v", err)
	}
	for _, version := range []uint32{2, 6, 9} {
		bundle := validSiteObjectCommand(t)
		bundle.Artifacts = bundle.Artifacts[1:]
		bundle.Artifacts[0].MediaType = "application/vnd.cdnca.edge-site-runtime-bundle+json;version=2"
		bundle.RequiredCapabilities[len(bundle.RequiredCapabilities)-1].ApiVersion = version
		if err := gateway.validateDeploymentCommand(bundle, testArtifactRecipientKeyID); err == nil {
			t.Fatalf("site runtime v%d bundle command accepted", version)
		}
	}
}

func TestSiteObjectDeploymentCommandRejectsNilIdentity(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	tests := []struct {
		name   string
		change func(*agentv1.DeploymentCommand)
	}{
		{name: "nil scope", change: func(value *agentv1.DeploymentCommand) {
			setDeploymentConfigurationScope(t, value, uuid.Nil.String())
		}},
		{name: "nil config version", change: func(value *agentv1.DeploymentCommand) {
			value.ConfigVersionId = uuid.Nil.String()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := validSiteObjectCommand(t)
			test.change(command)
			if err := gateway.validateDeploymentCommand(command, testArtifactRecipientKeyID); err == nil {
				t.Fatal("site object command with nil identity was accepted")
			}
		})
	}
}

func setDeploymentConfigurationScope(t *testing.T, command *agentv1.DeploymentCommand, value string) {
	t.Helper()
	field := command.ProtoReflect().Descriptor().Fields().ByNumber(12)
	if field == nil {
		t.Fatal("DeploymentCommand configuration_scope_id field is missing")
	}
	command.ProtoReflect().Set(field, protoreflect.ValueOfString(value))
}

func clearDeploymentConfigurationScope(command *agentv1.DeploymentCommand) {
	if field := command.ProtoReflect().Descriptor().Fields().ByNumber(12); field != nil {
		command.ProtoReflect().Clear(field)
	}
}

type capturingBidiStream struct {
	ctx     context.Context
	sent    chan *agentv1.ConnectResponse
	sendErr error
}

func (s *capturingBidiStream) Context() context.Context { return s.ctx }
func (s *capturingBidiStream) Recv() (*agentv1.ConnectRequest, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *capturingBidiStream) Send(response *agentv1.ConnectResponse) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	select {
	case s.sent <- response:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *capturingBidiStream) SetHeader(metadata.MD) error  { return nil }
func (s *capturingBidiStream) SendHeader(metadata.MD) error { return nil }
func (s *capturingBidiStream) SetTrailer(metadata.MD)       {}
func (s *capturingBidiStream) SendMsg(any) error            { return nil }
func (s *capturingBidiStream) RecvMsg(any) error            { return io.EOF }

func newCommandGateway(t *testing.T, control ControlPlane, bus CommandBus, configure func(*Config)) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-command-test"
	config.GatewayVersion = "test"
	if configure != nil {
		configure(&config)
	}
	gateway, err := NewWithCommandBus(config, control, NewMemorySessionCoordinator(), bus)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func validDeploymentCommand() *agentv1.DeploymentCommand {
	return &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now(), CorrelationId: uuid.NewString(),
		},
		DeploymentId:    uuid.NewString(),
		Attempt:         1,
		RolloutId:       uuid.NewString(),
		ConfigVersionId: "cfg-v1",
		Action:          agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		Artifacts: []*agentv1.ArtifactDescriptor{{
			ArtifactId: uuid.NewString(), Kind: agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION,
			SizeBytes: 1, Sha256: make([]byte, 32), Signature: make([]byte, 64), SigningKeyId: "signing-key",
			SignatureAlgorithm:  agentv1.ArtifactSignatureAlgorithm_ARTIFACT_SIGNATURE_ALGORITHM_ED25519,
			Compression:         agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE,
			MediaType:           "application/octet-stream",
			EncryptionAlgorithm: agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE,
		}},
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration:    durationpb.New(time.Minute),
			ObservationWindowDuration:    durationpb.New(time.Second),
			RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(time.Now().Add(time.Hour)),
	}
}

func validRollbackDeploymentCommand() *agentv1.DeploymentCommand {
	command := validDeploymentCommand()
	command.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	command.Artifacts = nil
	previous := "cfg-v2"
	command.PreviousConfigVersionId = &previous
	return command
}

func validDeploymentStatus(command *agentv1.DeploymentCommand) *agentv1.DeploymentStatus {
	return &agentv1.DeploymentStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: command.Event.RequestId, OccurredTime: timestamppb.Now(), CorrelationId: command.Event.CorrelationId,
		},
		DeploymentId: command.DeploymentId, Attempt: command.Attempt, ConfigVersionId: command.ConfigVersionId,
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, TransitionSequence: 1,
	}
}

func waitForTest(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
