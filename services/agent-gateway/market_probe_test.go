package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// deployingControl is the fake control plane with deployments allowed, which session command relays require.
type deployingControl struct{ *fakeControl }

func (control deployingControl) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	response, err := control.fakeControl.GetNodeAuthorization(ctx, request)
	if response != nil {
		response.DeploymentsAllowed = true
	}
	return response, err
}

type marketProbeRequestStub struct {
	command *agentv1.MarketProbeCommand
	replies chan *agentv1.MarketProbeResult
}

func (request *marketProbeRequestStub) Command() *agentv1.MarketProbeCommand { return request.command }
func (request *marketProbeRequestStub) Reply(result *agentv1.MarketProbeResult) error {
	request.replies <- result
	return nil
}

type marketProbeBusStub struct {
	requests   chan MarketProbeRequest
	subscribed chan string
	closed     chan string
}

func (bus *marketProbeBusStub) SubscribeMarketProbes(_ context.Context, nodeID string) (MarketProbeSubscription, error) {
	bus.subscribed <- nodeID
	return &marketProbeSubscriptionStub{bus: bus, nodeID: nodeID}, nil
}

type marketProbeSubscriptionStub struct {
	bus    *marketProbeBusStub
	nodeID string
}

func (subscription *marketProbeSubscriptionStub) Requests() <-chan MarketProbeRequest {
	return subscription.bus.requests
}
func (subscription *marketProbeSubscriptionStub) Close() error {
	subscription.bus.closed <- subscription.nodeID
	return nil
}

func testMarketProbeCommand(nodeID string) *agentv1.MarketProbeCommand {
	return &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, TimeoutMillis: 3000, ExpireTime: timestamppb.New(time.Now().Add(time.Minute)),
		Targets: []*agentv1.MarketProbeTarget{{TaskId: "a", Ip: "8.8.8.8", Port: 80}, {TaskId: "b", Ip: "1.1.1.1", Port: 443}},
	}
}

func testMarketProbeResult(command *agentv1.MarketProbeCommand) *agentv1.MarketProbeResult {
	results := make([]*agentv1.MarketProbeTargetResult, len(command.Targets))
	for i, target := range command.Targets {
		results[i] = &agentv1.MarketProbeTargetResult{TaskId: target.TaskId,
			Outcome: agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, LatencyMillis: 20}
	}
	return &agentv1.MarketProbeResult{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Results: results,
	}
}

func TestMarketProbeCapabilityVersions(t *testing.T) {
	for version, want := range map[uint32]bool{1: false, 2: true, 3: true, 4: false} {
		got, err := marketProbeCapabilityFromFeatures([]*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: version}})
		if want && (err != nil || got != version) || !want && err == nil {
			t.Fatalf("v%d = %d, %v", version, got, err)
		}
	}
	if got, err := marketProbeCapabilityFromFeatures(nil); got != 0 || err != nil {
		t.Fatalf("absent = %d, %v", got, err)
	}
}

func TestValidateMarketProbeCommandAndResult(t *testing.T) {
	now := time.Now()
	command := testMarketProbeCommand(testNodeID)
	if err := validateMarketProbeCommand(command, testNodeID, now); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	many := make([]*agentv1.MarketProbeTarget, 65)
	for i := range many {
		many[i] = &agentv1.MarketProbeTarget{TaskId: "t", Ip: "8.8.8.8", Port: 80}
	}
	for name, mutate := range map[string]func(*agentv1.MarketProbeCommand){
		"other node":   func(value *agentv1.MarketProbeCommand) { value.NodeId = uuid.NewString() },
		"event":        func(value *agentv1.MarketProbeCommand) { value.Event.EventId = "x" },
		"no targets":   func(value *agentv1.MarketProbeCommand) { value.Targets = nil },
		"many targets": func(value *agentv1.MarketProbeCommand) { value.Targets = many },
		"timeout":      func(value *agentv1.MarketProbeCommand) { value.TimeoutMillis = 10_001 },
		"expired":      func(value *agentv1.MarketProbeCommand) { value.ExpireTime = timestamppb.New(now.Add(-time.Second)) },
	} {
		changed := proto.Clone(command).(*agentv1.MarketProbeCommand)
		mutate(changed)
		if err := validateMarketProbeCommand(changed, testNodeID, now); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	result := testMarketProbeResult(command)
	if err := validateMarketProbeResult(result, command, testNodeID); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.MarketProbeResult){
		"node":      func(value *agentv1.MarketProbeResult) { value.NodeId = uuid.NewString() },
		"command":   func(value *agentv1.MarketProbeResult) { value.CommandEventId = uuid.NewString() },
		"count":     func(value *agentv1.MarketProbeResult) { value.Results = value.Results[:1] },
		"task":      func(value *agentv1.MarketProbeResult) { value.Results[1].TaskId = "z" },
		"outcome":   func(value *agentv1.MarketProbeResult) { value.Results[0].Outcome = 0 },
		"latency":   func(value *agentv1.MarketProbeResult) { value.Results[0].LatencyMillis = 10_001 },
		"no event":  func(value *agentv1.MarketProbeResult) { value.Event = nil },
		"long code": func(value *agentv1.MarketProbeResult) { value.Results[0].ErrorCode = string(make([]byte, 65)) },
	} {
		changed := proto.Clone(result).(*agentv1.MarketProbeResult)
		mutate(changed)
		if err := validateMarketProbeResult(changed, command, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
}

func TestSessionMarketProbesAdmitBoundAndExpire(t *testing.T) {
	session := &sessionMarketProbes{pending: map[string]pendingMarketProbe{}}
	now := time.Now()
	replies := make(chan *agentv1.MarketProbeResult, 8)
	request := func(command *agentv1.MarketProbeCommand) *marketProbeRequestStub {
		return &marketProbeRequestStub{command: command, replies: replies}
	}
	first := testMarketProbeCommand(testNodeID)
	if _, ok := session.admit(request(first), testNodeID, now); !ok {
		t.Fatal("first command refused")
	}
	if _, ok := session.admit(request(first), testNodeID, now); ok || <-replies != nil {
		t.Fatal("duplicate command admitted")
	}
	if _, ok := session.admit(request(testMarketProbeCommand(uuid.NewString())), testNodeID, now); ok || <-replies != nil {
		t.Fatal("command for another node admitted")
	}
	if _, ok := session.admit(request(testMarketProbeCommand(testNodeID)), testNodeID, now); !ok {
		t.Fatal("second command refused")
	}
	if _, ok := session.admit(request(testMarketProbeCommand(testNodeID)), testNodeID, now); ok || <-replies != nil {
		t.Fatal("pending budget not enforced")
	}
	// A result for an unknown command is ignored; a valid one settles its request.
	if err := session.settle(testMarketProbeResult(testMarketProbeCommand(testNodeID)), testNodeID); err != nil {
		t.Fatalf("stray result: %v", err)
	}
	result := testMarketProbeResult(first)
	if err := session.settle(result, testNodeID); err != nil {
		t.Fatal(err)
	}
	if got := <-replies; !proto.Equal(got, result) {
		t.Fatalf("replied %v", got)
	}
	session.expire(now.Add(2 * time.Minute))
	if len(session.pending) != 0 {
		t.Fatalf("expired commands kept: %d", len(session.pending))
	}
}

// TestMarketProbeSessionRelaysCommandAndAnswersWithResult drives a real mTLS
// Connect session: the capability is negotiated, the gateway subscribes for
// the authenticated node, relays a valid command, refuses an invalid one and
// answers the request with the Agent's result.
func TestMarketProbeSessionRelaysCommandAndAnswersWithResult(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 11, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	service, err := New(config, deployingControl{defaultFakeControl()}, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	bus := &marketProbeBusStub{requests: make(chan MarketProbeRequest, 4), subscribed: make(chan string, 4),
		closed: make(chan string, 4)}
	if err := service.ConfigureMarketProbes(bus); err != nil {
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
	hello.GetHello().Capabilities.Features = []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 2}}
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if negotiated, _ := marketProbeCapabilityFromFeatures(first.GetHello().GetEnabledCapabilities()); negotiated != 2 {
		t.Fatalf("market probe capability not enabled: %v", first.GetHello().GetEnabledCapabilities())
	}
	select {
	case nodeID := <-bus.subscribed:
		if nodeID != testNodeID {
			t.Fatalf("subscribed for %s", nodeID)
		}
	case <-ctx.Done():
		t.Fatal("gateway did not subscribe for the authenticated node")
	}
	replies := make(chan *agentv1.MarketProbeResult, 4)
	bus.requests <- &marketProbeRequestStub{command: testMarketProbeCommand(uuid.NewString()), replies: replies}
	command := testMarketProbeCommand(testNodeID)
	bus.requests <- &marketProbeRequestStub{command: command, replies: replies}
	if refused := <-replies; refused != nil {
		t.Fatalf("command for another node answered %v", refused)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if relayed := response.GetMarketProbeCommand(); relayed == nil || !proto.Equal(relayed, command) {
		t.Fatalf("relayed %v", response.Payload)
	}
	result := testMarketProbeResult(command)
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_MarketProbeResult{MarketProbeResult: result},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-replies:
		if !proto.Equal(got, result) {
			t.Fatalf("answered %v", got)
		}
	case <-ctx.Done():
		t.Fatal("request was not answered with the result")
	}
	cancel()
	select {
	case <-bus.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not closed when the session ended")
	}
}
