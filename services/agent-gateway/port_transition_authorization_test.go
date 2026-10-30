package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGatewayPortTransitionAuthorizationRefresh(t *testing.T) {
	for _, trigger := range []string{"timer", "incoming"} {
		for _, next := range []string{"restore", "late status"} {
			t.Run(trigger+"/"+next, func(t *testing.T) {
				s := newPortAuthorizationSession(t, trigger, true, true)
				subscription := portTestReceive(t, s.bus.subscribed)
				command := validPortTransitionCommand()
				command.NodeId = testNodeID
				command.CertificateSha256 = certificateIdentityHex(nodeIdentity{})
				command.CompatibilityDeadline = timestamppb.New(s.now().Add(12 * time.Hour))
				command.RollbackDeadline = timestamppb.New(s.now().Add(24 * time.Hour))
				pending := newPortAuthorizationDelivery(command)
				subscription.deliveries <- pending
				if response := portTestReceive(t, s.stream.sent); response.GetGatewayPortTransitionCommand() == nil {
					t.Fatalf("initial response = %v", response)
				}

				// Hold authorization while the already armed consumer finishes its pull.
				if trigger == "incoming" {
					s.offset.Add(int64(time.Hour))
					s.heartbeat()
				}
				reply := portTestReceive(t, s.control.refreshes)
				buffered := newPortAuthorizationDelivery(command)
				subscription.deliveries <- buffered
				portTestReceive(t, buffered.fetched)
				reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING)
				waitForTest(t, time.Second, func() bool {
					return pending.retries.Load() == 1 && buffered.retries.Load() == 1
				})
				portTestReceive(t, subscription.closed)
				if trigger == "timer" {
					s.heartbeat()
				}
				if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
					t.Fatalf("revoked session delivered a command instead of keeping heartbeat alive: %v", response)
				}
				if pending.acks.Load() != 0 || buffered.acks.Load() != 0 || s.bus.publications.Load() != 0 {
					t.Fatal("permission revocation acknowledged a command or fabricated a status")
				}

				if next == "late status" {
					s.sendStatus(command)
					portTestReceive(t, s.done)
					if status.Code(s.err) != codes.PermissionDenied || s.bus.publications.Load() != 0 {
						t.Fatalf("late status after revocation: err=%v publications=%d", s.err, s.bus.publications.Load())
					}
					return
				}

				s.offset.Add(int64(time.Hour))
				s.heartbeat()
				reply = portTestReceive(t, s.control.refreshes)
				reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE)
				restored := portTestReceive(t, s.bus.subscribed)
				if restored == subscription {
					t.Fatal("restored authorization reused the cancelled subscription")
				}
				if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
					t.Fatalf("restored heartbeat = %v", response)
				}
				restored.deliveries <- buffered
				if response := portTestReceive(t, s.stream.sent); !proto.Equal(response.GetGatewayPortTransitionCommand(), command) {
					t.Fatalf("previously pulled command was not redelivered intact: %v", response)
				}
				s.sendStatus(command)
				waitForTest(t, time.Second, func() bool { return buffered.acks.Load() == 1 })
				if s.bus.publications.Load() != 1 || pending.acks.Load() != 0 || buffered.retries.Load() != 1 {
					t.Fatal("restored command was acknowledged without exactly one status publication")
				}
			})
		}
	}
}

func TestGatewayPortTransitionAuthorizationRequiresNegotiatedCapability(t *testing.T) {
	s := newPortAuthorizationSession(t, "incoming", false, false)
	s.offset.Add(int64(time.Hour))
	s.heartbeat()
	reply := portTestReceive(t, s.control.refreshes)
	reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE)
	if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
		t.Fatalf("heartbeat = %v", response)
	}
	select {
	case <-s.bus.subscribed:
		t.Fatal("authorization refresh enabled an unnegotiated capability")
	default:
	}
}

func TestGatewayPortTransitionAuthorizationEnablesInitiallyDeniedSession(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "subscribe", true: "subscribe failure"}[fail], func(t *testing.T) {
			s := newPortAuthorizationSession(t, "timer", false, true)
			reply := portTestReceive(t, s.control.refreshes)
			s.bus.failSubscribe.Store(fail)
			reply <- s.authorization(controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE)
			if fail {
				portTestReceive(t, s.done)
				if status.Code(s.err) != codes.Unavailable {
					t.Fatalf("failed subscription = %v", s.err)
				}
				return
			}
			portTestReceive(t, s.bus.subscribed)
			s.heartbeat()
			if response := portTestReceive(t, s.stream.sent); response.GetHeartbeatAck() == nil {
				t.Fatalf("enabled session heartbeat = %v", response)
			}
		})
	}
}

func TestGatewayPortTransitionSessionExitReturnsPulledCommand(t *testing.T) {
	s := newPortAuthorizationSession(t, "incoming", true, true)
	subscription := portTestReceive(t, s.bus.subscribed)
	s.offset.Add(int64(time.Hour))
	s.heartbeat()
	portTestReceive(t, s.control.refreshes)
	buffered := newPortAuthorizationDelivery(validPortTransitionCommand())
	subscription.deliveries <- buffered
	portTestReceive(t, buffered.fetched)
	s.cancel()
	portTestReceive(t, s.done)
	if status.Code(s.err) != codes.Canceled || buffered.retries.Load() != 1 || buffered.acks.Load() != 0 || s.bus.publications.Load() != 0 {
		t.Fatalf("stream exit = %v, retries=%d acks=%d publications=%d", s.err, buffered.retries.Load(), buffered.acks.Load(), s.bus.publications.Load())
	}
}

type portAuthorizationControl struct {
	*fakeControl
	refreshes chan chan *controlv1.GetNodeAuthorizationResponse
}

func (c *portAuthorizationControl) GetNodeAuthorization(ctx context.Context, _ *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	reply := make(chan *controlv1.GetNodeAuthorizationResponse, 1)
	select {
	case c.refreshes <- reply:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case response := <-reply:
		return response, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type portAuthorizationBus struct {
	subscribed    chan *portAuthorizationSubscription
	publications  atomic.Int32
	failSubscribe atomic.Bool
}

func (b *portAuthorizationBus) SubscribePortTransitions(context.Context, string) (PortTransitionCommandSubscription, error) {
	if b.failSubscribe.Load() {
		return nil, errors.New("subscription unavailable")
	}
	s := &portAuthorizationSubscription{deliveries: make(chan *portAuthorizationDelivery, 1), closed: make(chan struct{})}
	b.subscribed <- s
	return s, nil
}

func (b *portAuthorizationBus) PublishPortTransitionStatus(context.Context, string, *agentv1.GatewayPortTransitionStatus) (PortTransitionStatusPublication, error) {
	sequence := b.publications.Add(1)
	return PortTransitionStatusPublication{Stream: "test-status", Sequence: uint64(sequence)}, nil
}

type portAuthorizationSubscription struct {
	deliveries chan *portAuthorizationDelivery
	closed     chan struct{}
	once       sync.Once
}

func (s *portAuthorizationSubscription) Next(ctx context.Context) (PortTransitionCommandDelivery, error) {
	select {
	case d := <-s.deliveries:
		d.fetched <- struct{}{}
		return d, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.closed:
		return nil, io.EOF
	}
}

func (s *portAuthorizationSubscription) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

type portAuthorizationDelivery struct {
	command *agentv1.GatewayPortTransitionCommand
	fetched chan struct{}
	retries atomic.Int32
	acks    atomic.Int32
}

func newPortAuthorizationDelivery(command *agentv1.GatewayPortTransitionCommand) *portAuthorizationDelivery {
	return &portAuthorizationDelivery{command: command, fetched: make(chan struct{}, 4)}
}
func (d *portAuthorizationDelivery) Command() *agentv1.GatewayPortTransitionCommand { return d.command }
func (d *portAuthorizationDelivery) Retry(context.Context, time.Duration) error {
	d.retries.Add(1)
	return nil
}
func (d *portAuthorizationDelivery) Ack(context.Context) error { d.acks.Add(1); return nil }

type portAuthorizationSession struct {
	control    *portAuthorizationControl
	bus        *portAuthorizationBus
	stream     *capturingBidiStream
	receive    chan connectReceive
	done       chan struct{}
	err        error
	offset     atomic.Int64
	epoch      uint64
	sequence   uint64
	heartbeats uint64
	cancel     context.CancelFunc
}

func newPortAuthorizationSession(t *testing.T, trigger string, allowed, capable bool, portBus ...PortTransitionCommandBus) *portAuthorizationSession {
	t.Helper()
	s := &portAuthorizationSession{receive: make(chan connectReceive, 2), done: make(chan struct{}), sequence: 1,
		control: &portAuthorizationControl{fakeControl: defaultFakeControl(), refreshes: make(chan chan *controlv1.GetNodeAuthorizationResponse, 1)},
		bus:     &portAuthorizationBus{subscribed: make(chan *portAuthorizationSubscription, 4)}}
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "port-authorization-test", "test"
	config.OfflineAfter = 4 * time.Hour
	config.CommandOperationTimeout = time.Second
	g, err := New(config, s.control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	g.now = s.now
	g.portTransitions = s.bus
	if len(portBus) != 0 {
		g.portTransitions = portBus[0]
	}
	g.portManager = NewPortTransitionManager(&transitionListener{address: "0.0.0.0:7443"}, "gateway.example.com:7443",
		func(_ context.Context, address string) (net.Listener, error) {
			return &transitionListener{address: address}, nil
		}, s.now)
	if err := g.portManager.ConfigureServe(func(net.Listener) error { return nil }); err != nil {
		t.Fatal(err)
	}
	lease, err := NewMemorySessionCoordinator().Acquire(t.Context(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	s.epoch = lease.Epoch()
	ctx, cancel := context.WithCancel(t.Context())
	s.cancel = cancel
	s.stream = &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 8)}
	expires := s.now().Add(time.Hour)
	if trigger == "timer" {
		expires = s.now().Add(200 * time.Millisecond)
	}
	go func() {
		s.err = g.serveSessionWithInstallation(s.stream, s.receive, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, "", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", "", expires, allowed, false,
			false, false, false, false, false, false, false, false, false, capable)
		close(s.done)
	}()
	t.Cleanup(func() { cancel(); portTestReceive(t, s.done); lease.Release() })
	return s
}

func (s *portAuthorizationSession) now() time.Time {
	return time.Now().Add(time.Duration(s.offset.Load()))
}

func (s *portAuthorizationSession) authorization(state controlv1.NodeAdministrativeState) *controlv1.GetNodeAuthorizationResponse {
	return &controlv1.GetNodeAuthorizationResponse{NodeId: testNodeID, AdministrativeState: state,
		ConnectionAllowed: true, DeploymentsAllowed: true, AcceptedProtocolVersions: versionRange(1, 0),
		SnapshotExpirationTime: timestamppb.New(s.now().Add(time.Hour)), ArtifactEncryptionKeyId: "artifact-key"}
}

func (s *portAuthorizationSession) heartbeat() {
	s.sequence++
	s.heartbeats++
	request := validHeartbeatRequest(s.epoch, s.heartbeats, s.sequence, uuid.NewString(), uuid.NewString())
	request.Stream.SentTime = timestamppb.New(s.now())
	request.GetHeartbeat().Event.OccurredTime = timestamppb.New(s.now())
	s.receive <- connectReceive{request: request}
}

func (s *portAuthorizationSession) sendStatus(command *agentv1.GatewayPortTransitionCommand) {
	s.sequence++
	value := terminalStatus(command)
	value.State = agentv1.GatewayPortTransitionState_GATEWAY_PORT_TRANSITION_STATE_SWITCHED
	value.Event.OccurredTime = timestamppb.New(s.now())
	s.receive <- connectReceive{request: &agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: s.sequence, SentTime: timestamppb.New(s.now())},
		Payload: &agentv1.ConnectRequest_GatewayPortTransitionStatus{GatewayPortTransitionStatus: value},
	}}
}

func portTestReceive[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("gateway port authorization test did not reach the expected stream event")
		var zero T
		return zero
	}
}
