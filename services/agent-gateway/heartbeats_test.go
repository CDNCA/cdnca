package gateway

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type fakeHeartbeatSink struct {
	mu       sync.Mutex
	err      error
	block    bool
	attempts []*agentv1.Heartbeat
	unique   map[string]struct{}
	order    *[]string
}

func (s *fakeHeartbeatSink) PersistHeartbeat(ctx context.Context, _ string, heartbeat *agentv1.Heartbeat) error {
	if s.block {
		<-ctx.Done()
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, proto.Clone(heartbeat).(*agentv1.Heartbeat))
	if s.order != nil {
		*s.order = append(*s.order, "persist")
	}
	if s.err != nil {
		return s.err
	}
	if s.unique == nil {
		s.unique = make(map[string]struct{})
	}
	s.unique[heartbeat.Event.EventId] = struct{}{}
	return nil
}

type heartbeatTestStream struct {
	ctx    context.Context
	sent   chan *agentv1.ConnectResponse
	onSend func()
}

func (s *heartbeatTestStream) Context() context.Context { return s.ctx }
func (s *heartbeatTestStream) Recv() (*agentv1.ConnectRequest, error) {
	<-s.ctx.Done()
	return nil, s.ctx.Err()
}
func (s *heartbeatTestStream) Send(response *agentv1.ConnectResponse) error {
	if s.onSend != nil {
		s.onSend()
	}
	select {
	case s.sent <- response:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *heartbeatTestStream) SetHeader(metadata.MD) error  { return nil }
func (s *heartbeatTestStream) SendHeader(metadata.MD) error { return nil }
func (s *heartbeatTestStream) SetTrailer(metadata.MD)       {}
func (s *heartbeatTestStream) SendMsg(any) error            { return nil }
func (s *heartbeatTestStream) RecvMsg(any) error            { return io.EOF }

func TestHeartbeatPersistsBeforeAck(t *testing.T) {
	order := make([]string, 0, 2)
	sink := &fakeHeartbeatSink{order: &order}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSession(t, gateway, nil)
	request <- connectReceive{request: validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())}
	request <- connectReceive{err: io.EOF}
	response := <-stream.sent
	if response.GetHeartbeatAck() == nil {
		t.Fatalf("response = %+v, want heartbeat acknowledgement", response)
	}
	if err := <-done; err != nil {
		t.Fatalf("serveSession() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"persist", "ack"}) {
		t.Fatalf("heartbeat order = %v, want persist then ack", order)
	}
}

func TestHeartbeatPersistenceFailureDoesNotAck(t *testing.T) {
	sink := &fakeHeartbeatSink{err: errors.New("heartbeat stream unavailable")}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSession(t, gateway, nil)
	request <- connectReceive{request: validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())}
	if err := <-done; status.Code(err) != codes.Unavailable {
		t.Fatalf("serveSession() code = %v, want Unavailable", status.Code(err))
	}
	select {
	case response := <-stream.sent:
		t.Fatalf("persistence failure sent response %+v", response)
	default:
	}
}

func TestDuplicateHeartbeatReplaysAckAndSinkDeduplicates(t *testing.T) {
	sink := &fakeHeartbeatSink{}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSession(t, gateway, nil)
	heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	request <- connectReceive{request: heartbeat}
	request <- connectReceive{request: proto.Clone(heartbeat).(*agentv1.ConnectRequest)}
	request <- connectReceive{err: io.EOF}
	for index := 0; index < 2; index++ {
		response := <-stream.sent
		if response.GetHeartbeatAck() == nil || response.GetHeartbeatAck().HeartbeatEventId != heartbeat.GetHeartbeat().Event.EventId {
			t.Fatalf("duplicate response %d = %+v", index, response)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("serveSession() error = %v", err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.attempts) != 2 || len(sink.unique) != 1 {
		t.Fatalf("sink attempts=%d unique=%d, want 2 and 1", len(sink.attempts), len(sink.unique))
	}
}

func TestHeartbeatPersistenceTimeoutDoesNotAck(t *testing.T) {
	sink := &fakeHeartbeatSink{block: true}
	gateway := newHeartbeatGateway(t, sink, func(config *Config) {
		config.HeartbeatPersistTimeout = 10 * time.Millisecond
	})
	request, stream, done := startHeartbeatSession(t, gateway, nil)
	request <- connectReceive{request: validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())}
	if err := <-done; status.Code(err) != codes.Unavailable {
		t.Fatalf("serveSession() code = %v, want Unavailable", status.Code(err))
	}
	select {
	case response := <-stream.sent:
		t.Fatalf("timed out persistence sent response %+v", response)
	default:
	}
}

func TestNilHeartbeatIsRejectedWithoutPersistenceOrAck(t *testing.T) {
	sink := &fakeHeartbeatSink{}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSession(t, gateway, nil)
	invalid := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	invalid.Payload = &agentv1.ConnectRequest_Heartbeat{}
	request <- connectReceive{request: invalid}
	if err := <-done; status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil heartbeat code = %v, want InvalidArgument", status.Code(err))
	}
	assertNoHeartbeatAck(t, stream)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.attempts) != 0 {
		t.Fatalf("nil heartbeat persistence attempts = %d", len(sink.attempts))
	}
}

func TestHeartbeatAgentVersionMustMatchHello(t *testing.T) {
	sink := &fakeHeartbeatSink{}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSessionVersion(t, gateway, "1.2.3", nil)
	heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())
	wrongVersion := "1.2.4"
	heartbeat.GetHeartbeat().AgentVersion = &wrongVersion
	request <- connectReceive{request: heartbeat}
	if err := <-done; status.Code(err) != codes.InvalidArgument {
		t.Fatalf("version mismatch code = %v, want InvalidArgument", status.Code(err))
	}
	assertNoHeartbeatAck(t, stream)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.attempts) != 0 {
		t.Fatalf("version mismatch persistence attempts = %d, want 0", len(sink.attempts))
	}
}

func TestHeartbeatWithoutAgentVersionRemainsCompatible(t *testing.T) {
	sink := &fakeHeartbeatSink{}
	gateway := newHeartbeatGateway(t, sink, nil)
	request, stream, done := startHeartbeatSessionVersion(t, gateway, "1.2.3", nil)
	request <- connectReceive{request: validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString())}
	request <- connectReceive{err: io.EOF}
	if response := <-stream.sent; response.GetHeartbeatAck() == nil {
		t.Fatalf("response = %+v, want heartbeat acknowledgement", response)
	}
	if err := <-done; err != nil {
		t.Fatalf("serveSession() error = %v", err)
	}
	if len(sink.attempts) != 1 || sink.attempts[0].AgentVersion != nil {
		t.Fatalf("legacy heartbeat persistence = %+v", sink.attempts)
	}
}

func TestGatewayHeartbeatSinkModesAreExplicit(t *testing.T) {
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-heartbeat-constructor"
	config.GatewayVersion = "test"
	standalone, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil || standalone.heartbeats != nil {
		t.Fatalf("New() = (%+v, %v), want standalone mode", standalone, err)
	}
	commandsOnly, err := NewWithCommandBus(config, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{})
	if err != nil || commandsOnly.heartbeats != nil {
		t.Fatalf("NewWithCommandBus() = (%+v, %v), want no heartbeat sink", commandsOnly, err)
	}
	if _, err := NewWithDurableMessaging(config, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{}, nil); err == nil {
		t.Fatal("NewWithDurableMessaging() accepted a nil heartbeat sink")
	}
}

func TestDefaultNATSHeartbeatConfigAndValidation(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	if config.HeartbeatStream != "AGENT_HEARTBEATS" || config.HeartbeatSubjectPrefix != "cdnca.agent.heartbeats" || config.MaxHeartbeatBytes != defaultMaxMessageBytes {
		t.Fatalf("default heartbeat config = %+v", config)
	}
	invalid := []func(*NATSCommandBusConfig){
		func(config *NATSCommandBusConfig) { config.HeartbeatStream = "bad.stream" },
		func(config *NATSCommandBusConfig) { config.HeartbeatSubjectPrefix = "cdnca.*.heartbeats" },
		func(config *NATSCommandBusConfig) { config.MaxHeartbeatBytes = 0 },
	}
	for index, mutate := range invalid {
		candidate := config
		mutate(&candidate)
		if err := candidate.validate(); err == nil {
			t.Fatalf("invalid heartbeat config %d was accepted", index)
		}
	}
}

func TestNATSHeartbeatInputValidation(t *testing.T) {
	heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
	bus := &NATSCommandBus{config: DefaultNATSCommandBusConfig()}
	nonCanonicalEvent := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	nonCanonicalEvent.Event.EventId = strings.ToUpper(nonCanonicalEvent.Event.EventId)
	missingEvent := proto.Clone(heartbeat).(*agentv1.Heartbeat)
	missingEvent.Event = nil
	tests := []struct {
		name      string
		ctx       context.Context
		nodeID    string
		heartbeat *agentv1.Heartbeat
	}{
		{name: "nil context", nodeID: testNodeID, heartbeat: heartbeat},
		{name: "non-canonical node ID", ctx: context.Background(), nodeID: strings.ToUpper(testNodeID), heartbeat: heartbeat},
		{name: "nil heartbeat", ctx: context.Background(), nodeID: testNodeID},
		{name: "missing event", ctx: context.Background(), nodeID: testNodeID, heartbeat: missingEvent},
		{name: "non-canonical event ID", ctx: context.Background(), nodeID: testNodeID, heartbeat: nonCanonicalEvent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := bus.PersistHeartbeat(test.ctx, test.nodeID, test.heartbeat); err == nil {
				t.Fatal("invalid heartbeat input was accepted")
			}
		})
	}
	limited := &NATSCommandBus{config: DefaultNATSCommandBusConfig()}
	limited.config.MaxHeartbeatBytes = 1
	if err := limited.PersistHeartbeat(context.Background(), testNodeID, heartbeat); err == nil {
		t.Fatal("oversized heartbeat was accepted")
	}
}

func assertNoHeartbeatAck(t *testing.T, stream *heartbeatTestStream) {
	t.Helper()
	select {
	case response := <-stream.sent:
		t.Fatalf("failed heartbeat sent response %+v", response)
	default:
	}
}

func newHeartbeatGateway(t *testing.T, sink HeartbeatSink, configure func(*Config)) *Gateway {
	t.Helper()
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-heartbeat-test"
	config.GatewayVersion = "test"
	if configure != nil {
		configure(&config)
	}
	gateway, err := NewWithDurableMessaging(config, defaultFakeControl(), NewMemorySessionCoordinator(), &fakeCommandBus{}, sink)
	if err != nil {
		t.Fatal(err)
	}
	return gateway
}

func startHeartbeatSession(
	t *testing.T,
	gateway *Gateway,
	configureStream func(*heartbeatTestStream),
) (chan connectReceive, *heartbeatTestStream, chan error) {
	return startHeartbeatSessionVersion(t, gateway, "", configureStream)
}

func startHeartbeatSessionVersion(
	t *testing.T,
	gateway *Gateway,
	agentVersion string,
	configureStream func(*heartbeatTestStream),
) (chan connectReceive, *heartbeatTestStream, chan error) {
	t.Helper()
	lease, err := NewMemorySessionCoordinator().Acquire(context.Background(), testNodeID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		lease.Release()
	})
	stream := &heartbeatTestStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 4)}
	if configureStream != nil {
		configureStream(stream)
	}
	if sink, ok := gateway.heartbeats.(*fakeHeartbeatSink); ok && sink.order != nil {
		stream.onSend = func() {
			sink.mu.Lock()
			defer sink.mu.Unlock()
			*sink.order = append(*sink.order, "ack")
		}
	}
	received := make(chan connectReceive, 4)
	done := make(chan error, 1)
	go func() {
		done <- gateway.serveSession(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: testNodeID, SerialNumber: "10"}, agentVersion, versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", time.Now().Add(time.Hour), false, false,
		)
	}()
	return received, stream, done
}
