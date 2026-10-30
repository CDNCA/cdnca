package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type l4LiveRequestStub struct {
	command *agentv1.L4LiveConnectionsCommand
	replies chan *agentv1.L4LiveConnectionsResult
}

func (request *l4LiveRequestStub) Command() *agentv1.L4LiveConnectionsCommand { return request.command }
func (request *l4LiveRequestStub) Reply(result *agentv1.L4LiveConnectionsResult) error {
	request.replies <- result
	return nil
}

type l4LiveBusStub struct {
	requests   chan L4LiveRequest
	subscribed chan string
	closed     chan string
}

func (bus *l4LiveBusStub) SubscribeL4Live(_ context.Context, nodeID string) (L4LiveSubscription, error) {
	bus.subscribed <- nodeID
	return &l4LiveSubscriptionStub{bus: bus, nodeID: nodeID}, nil
}

type l4LiveSubscriptionStub struct {
	bus    *l4LiveBusStub
	nodeID string
}

func (subscription *l4LiveSubscriptionStub) Requests() <-chan L4LiveRequest {
	return subscription.bus.requests
}
func (subscription *l4LiveSubscriptionStub) Close() error {
	subscription.bus.closed <- subscription.nodeID
	return nil
}

func testL4LiveCommand(nodeID string, keys ...string) *agentv1.L4LiveConnectionsCommand {
	return &agentv1.L4LiveConnectionsCommand{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: nodeID,
		StreamId: uuid.NewString(), Limit: 10, CloseSessionKeys: keys, ExpireTime: timestamppb.New(time.Now().Add(5 * time.Second))}
}

func TestL4LiveCommandAndResultValidation(t *testing.T) {
	now := time.Now()
	if err := validateL4LiveCommand(testL4LiveCommand(testNodeID), testNodeID, 1, now); err != nil {
		t.Fatal(err)
	}
	if validateL4LiveCommand(testL4LiveCommand(testNodeID, "k"), testNodeID, 1, now) == nil {
		t.Fatal("close sent to a list-only (v1) agent")
	}
	if validateL4LiveCommand(testL4LiveCommand(testNodeID, "k"), testNodeID, 2, now) != nil {
		t.Fatal("close refused for a v2 agent")
	}
	far := testL4LiveCommand(testNodeID)
	far.ExpireTime = timestamppb.New(now.Add(time.Minute))
	if validateL4LiveCommand(far, testNodeID, 2, now) == nil {
		t.Fatal("command expiring beyond 15 s accepted")
	}
	if validateL4LiveCommand(testL4LiveCommand(uuid.NewString()), testNodeID, 2, now) == nil {
		t.Fatal("another node's command accepted")
	}
	command := testL4LiveCommand(testNodeID)
	result := &agentv1.L4LiveConnectionsResult{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: testNodeID,
		CommandEventId: command.Event.EventId}
	if err := validateL4LiveResult(result, command, testNodeID); err != nil {
		t.Fatal(err)
	}
	result.Connections = make([]*agentv1.L4LiveConnection, 11)
	if validateL4LiveResult(result, command, testNodeID) == nil {
		t.Fatal("result over the command's limit accepted")
	}
}

func TestL4LiveSessionNegotiatesRelaysAndAnswers(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 11, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	service, err := New(config, deployingControl{defaultFakeControl()}, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	bus := &l4LiveBusStub{requests: make(chan L4LiveRequest, 4), subscribed: make(chan string, 4), closed: make(chan string, 4)}
	if err := service.ConfigureL4Live(bus); err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(service, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.MTLS.Serve(listener) }()
	t.Cleanup(servers.MTLS.Stop)
	connection := dialGateway(t, listener.Addr().String(), pki.rootPool, clientCertificate)
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities.Features = []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS, ApiVersion: 1}}
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if version, _ := l4LiveCapabilityFromFeatures(first.GetHello().GetEnabledCapabilities()); version != 1 {
		t.Fatalf("L4 live capability enabled at v%d: %v", version, first.GetHello().GetEnabledCapabilities())
	}
	if nodeID := <-bus.subscribed; nodeID != testNodeID {
		t.Fatalf("subscribed for %s", nodeID)
	}
	replies := make(chan *agentv1.L4LiveConnectionsResult, 4)
	bus.requests <- &l4LiveRequestStub{command: testL4LiveCommand(testNodeID, "k"), replies: replies}
	if refused := <-replies; refused != nil {
		t.Fatalf("close relayed to a list-only agent: %v", refused)
	}
	command := testL4LiveCommand(testNodeID)
	bus.requests <- &l4LiveRequestStub{command: command, replies: replies}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if relayed := response.GetL4LiveConnectionsCommand(); relayed == nil || !proto.Equal(relayed, command) {
		t.Fatalf("relayed %v", response.Payload)
	}
	result := &agentv1.L4LiveConnectionsResult{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: testNodeID,
		CommandEventId: command.Event.EventId, Matched: 1, Connections: []*agentv1.L4LiveConnection{{SessionKey: "k"}}}
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_L4LiveConnectionsResult{L4LiveConnectionsResult: result},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-replies:
		if !proto.Equal(got, result) {
			t.Fatalf("answered %v", got)
		}
	case <-ctx.Done():
		t.Fatal("request was not answered")
	}
	cancel()
	select {
	case <-bus.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not closed")
	}
}
