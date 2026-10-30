package gatewayclient

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// l4LiveGateway knows L4_LIVE_CONNECTIONS, enables it once the Agent
// advertises it, sends the commands and records the results.
type l4LiveGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	commands []*agentv1.L4LiveConnectionsCommand
	hellos   chan *agentv1.AgentHello
	results  chan *agentv1.L4LiveConnectionsResult
}

func (g *l4LiveGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	g.hellos <- hello
	enabled := []*agentv1.Capability{}
	for _, capability := range hello.GetCapabilities().GetFeatures() {
		if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS {
			enabled = append(enabled, capability)
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
			KnownCapabilities: []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS}}}}); err != nil {
		return err
	}
	if len(enabled) != 0 {
		for i, command := range g.commands {
			if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(uint64(i + 2)),
				Payload: &agentv1.ConnectResponse_L4LiveConnectionsCommand{L4LiveConnectionsCommand: command}}); err != nil {
				return err
			}
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if result := request.GetL4LiveConnectionsResult(); result != nil {
			g.results <- result
		}
	}
}

type liveExecutorStub struct{ release chan struct{} }

func (liveExecutorStub) Validate(command *agentv1.L4LiveConnectionsCommand) error { return nil }
func (liveExecutorStub) APIVersion() uint32                                       { return 2 }
func (stub liveExecutorStub) Execute(ctx context.Context, _ *agentv1.L4LiveConnectionsCommand) *agentv1.L4LiveConnectionsResult {
	<-stub.release
	return &agentv1.L4LiveConnectionsResult{Matched: 1, Connections: []*agentv1.L4LiveConnection{{SessionKey: "k"}}}
}

func liveCommand(nodeID string) *agentv1.L4LiveConnectionsCommand {
	return &agentv1.L4LiveConnectionsCommand{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: nodeID,
		StreamId: uuid.NewString(), Limit: 10, ExpireTime: timestamppb.New(time.Now().Add(time.Minute))}
}

// The capability is advertised (v2) once the Gateway knows it; commands run
// one at a time, a second is answered busy, another node's is dropped.
func TestClientRunsL4LiveConnectionCommands(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	executor := liveExecutorStub{release: make(chan struct{})}
	first, busy := liveCommand(config.NodeID), liveCommand(config.NodeID)
	gateway := &l4LiveGateway{hellos: make(chan *agentv1.AgentHello, 4), results: make(chan *agentv1.L4LiveConnectionsResult, 4),
		commands: []*agentv1.L4LiveConnectionsCommand{first, busy, liveCommand("8f3c2d1e-0000-4000-8000-0000000000ff")}}
	client := startBufconnClient(t, gateway, config, testTrust(t), WithL4LiveExecutor(executor))
	defer client.cancel()
	if hello := <-gateway.hellos; hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS) {
		t.Fatal("advertised before the Gateway listed the capability")
	}
	select {
	case hello := <-gateway.hellos:
		found := false
		for _, capability := range hello.GetCapabilities().GetFeatures() {
			found = found || capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_L4_LIVE_CONNECTIONS && capability.ApiVersion == 2
		}
		if !found {
			t.Fatalf("second hello lacks L4_LIVE_CONNECTIONS v2: %v", hello.GetCapabilities().GetFeatures())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no second hello")
	}
	select {
	case result := <-gateway.results:
		if result.CommandEventId != busy.Event.EventId || result.ErrorCode != "busy" || result.NodeId != config.NodeID {
			t.Fatalf("busy result %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no busy result")
	}
	close(executor.release)
	select {
	case result := <-gateway.results:
		if result.CommandEventId != first.Event.EventId || result.Matched != 1 || result.Event.GetEventId() == "" {
			t.Fatalf("first result %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no result")
	}
	select {
	case result := <-gateway.results:
		t.Fatalf("another node's command was answered: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}
}
