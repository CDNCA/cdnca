package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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

// marketProbeGateway enables market probes, sends the given commands and
// records the Agent's results.
type marketProbeGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	enable   bool
	known    []agentv1.CapabilityName // GatewayHello.known_capabilities
	commands []*agentv1.MarketProbeCommand
	hellos   chan *agentv1.AgentHello
	results  chan *agentv1.MarketProbeResult
	ended    chan error
}

func (g *marketProbeGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	g.hellos <- first.GetHello()
	enabled := []*agentv1.Capability{}
	if g.enable {
		enabled = append(enabled, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 3})
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled, KnownCapabilities: g.known}}}); err != nil {
		return err
	}
	for i, command := range g.commands {
		if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(uint64(i + 2)),
			Payload: &agentv1.ConnectResponse_MarketProbeCommand{MarketProbeCommand: command}}); err != nil {
			return err
		}
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			if g.ended != nil {
				g.ended <- err
			}
			return err
		}
		if result := request.GetMarketProbeResult(); result != nil {
			g.results <- result
		}
	}
}

// blockingExecutor accepts commands for nodeID and holds Execute until release.
type blockingExecutor struct {
	nodeID  string
	release chan struct{}
}

func (e blockingExecutor) Validate(command *agentv1.MarketProbeCommand) error {
	if command.GetNodeId() != e.nodeID || command.GetEvent().GetEventId() == "" {
		return errors.New("invalid")
	}
	return nil
}

func (e blockingExecutor) Execute(ctx context.Context, command *agentv1.MarketProbeCommand) ([]*agentv1.MarketProbeTargetResult, error) {
	select {
	case <-e.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	out := make([]*agentv1.MarketProbeTargetResult, len(command.Targets))
	for i, target := range command.Targets {
		out[i] = &agentv1.MarketProbeTargetResult{TaskId: target.TaskId, Outcome: agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK,
			LatencyMillis: 12}
	}
	return out, nil
}

func probeCommand(nodeID, eventID string) *agentv1.MarketProbeCommand {
	return &agentv1.MarketProbeCommand{Event: &commonv1.EventMetadata{EventId: eventID, RequestId: uuid.NewString(),
		OccurredTime: timestamppb.Now()}, NodeId: nodeID, TimeoutMillis: 1000,
		ExpireTime: timestamppb.New(time.Now().Add(time.Minute)),
		Targets:    []*agentv1.MarketProbeTarget{{TaskId: "t1", Ip: "8.8.8.8", Port: 80}}}
}

func testTrust(t *testing.T) *TrustStore {
	t.Helper()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"edge-key": public})
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestClientRunsMarketProbesInBackgroundOneAtATime(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	executor := blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}
	first, busy := uuid.NewString(), uuid.NewString()
	gateway := &marketProbeGateway{enable: true, hellos: make(chan *agentv1.AgentHello, 4),
		results: make(chan *agentv1.MarketProbeResult, 4), commands: []*agentv1.MarketProbeCommand{
			probeCommand(config.NodeID, first),
			probeCommand(config.NodeID, busy),
			probeCommand("8f3c2d1e-0000-4000-8000-0000000000ff", uuid.NewString()), // another node: dropped
		}}
	client := startBufconnClient(t, gateway, config, testTrust(t), WithMarketProbeExecutor(executor))
	defer client.cancel()
	if hello := <-gateway.hellos; !hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE) {
		t.Fatalf("hello does not advertise market probes: %v", hello.GetCapabilities().GetFeatures())
	}
	// While the first command is still running, the second is answered busy.
	select {
	case result := <-gateway.results:
		if result.CommandEventId != busy || len(result.Results) != 1 || result.NodeId != config.NodeID ||
			result.Results[0].Outcome != agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED ||
			result.Results[0].ErrorCode != "busy" {
			t.Fatalf("busy result %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no busy result")
	}
	close(executor.release)
	select {
	case result := <-gateway.results:
		if result.CommandEventId != first || result.Results[0].Outcome != agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK ||
			result.Results[0].TaskId != "t1" {
			t.Fatalf("first result %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no probe result")
	}
	select {
	case result := <-gateway.results:
		t.Fatalf("command for another node was answered: %+v", result)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestClientRejectsUnnegotiatedMarketProbeCommand(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	// The Agent advertises the capability but this gateway does not enable it.
	gateway := &marketProbeGateway{hellos: make(chan *agentv1.AgentHello, 4), results: make(chan *agentv1.MarketProbeResult, 4),
		ended: make(chan error, 4), commands: []*agentv1.MarketProbeCommand{probeCommand(config.NodeID, uuid.NewString())}}
	client := startBufconnClient(t, gateway, config, testTrust(t),
		WithMarketProbeExecutor(blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}))
	defer client.cancel()
	<-gateway.hellos
	select {
	case <-gateway.ended:
	case result := <-gateway.results:
		t.Fatalf("unnegotiated command was executed: %+v", result)
	case <-time.After(5 * time.Second):
		t.Fatal("session survived an unnegotiated market probe command")
	}
}

func TestMarketProbeNegotiation(t *testing.T) {
	enable := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 3}}}
	if _, err := negotiateMarketProbe(enable, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unrequested enablement err=%v", err)
	}
	executor := blockingExecutor{}
	if enabled, err := negotiateMarketProbe(&agentv1.GatewayHello{}, executor); err != nil || enabled {
		t.Fatalf("older gateway = %v, %v", enabled, err)
	}
	if enabled, err := negotiateMarketProbe(enable, executor); err != nil || !enabled {
		t.Fatalf("enabled = %v, %v", enabled, err)
	}
	twice := &agentv1.GatewayHello{EnabledCapabilities: append(enable.EnabledCapabilities, enable.EnabledCapabilities[0])}
	if _, err := negotiateMarketProbe(twice, executor); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("duplicate err=%v", err)
	}
	// The Agent advertises v3 only; the gateway echoes it, so v1/v2 or a
	// future v4 is not what was advertised.
	for _, version := range []uint32{1, 2, 4} {
		other := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: version}}}
		if _, err := negotiateMarketProbe(other, executor); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("v%d err=%v", version, err)
		}
	}
	// Without an executor the Agent does not advertise the capability.
	gateway := &marketProbeGateway{hellos: make(chan *agentv1.AgentHello, 4)}
	client := startBufconnClient(t, gateway, testClientConfig(filepath.Join(secureTempDir(t), "journal")), testTrust(t))
	defer client.cancel()
	if hello := <-gateway.hellos; hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE) {
		t.Fatal("agent without an executor advertised market probes")
	}
}

type benchmarkExecutor struct{ blockingExecutor }

func (benchmarkExecutor) BenchmarkEnabled() bool { return true }

// MARKET_BENCHMARK (34) is declared in the first hello whenever benchmarking
// is configured, whatever the Gateway lists in known_capabilities: every
// 1.0.35 Gateway knows it, so there is no probe and no reconnect.
func TestClientAdvertisesMarketBenchmarkWhenConfigured(t *testing.T) {
	for _, c := range []struct {
		name      string
		benchmark bool
		known     []agentv1.CapabilityName
		want      bool // capability 34 in the first hello
	}{
		{"benchmark off", false, []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK}, false},
		{"benchmark on, gateway lists nothing", true, nil, true},
		{"benchmark on, gateway lists it", true, []agentv1.CapabilityName{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE,
			agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
			var executor MarketProbeExecutor = blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}
			if c.benchmark {
				executor = benchmarkExecutor{blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}}
			}
			gateway := &marketProbeGateway{enable: true, known: c.known, hellos: make(chan *agentv1.AgentHello, 8),
				results: make(chan *agentv1.MarketProbeResult, 4)}
			client := startBufconnClient(t, gateway, config, testTrust(t), WithMarketProbeExecutor(executor))
			defer client.cancel()
			var hello *agentv1.AgentHello
			select {
			case hello = <-gateway.hellos:
			case <-time.After(10 * time.Second):
				t.Fatal("hello not received")
			}
			if got := hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK); got != c.want {
				t.Fatalf("benchmark advertised %v, want %v", got, c.want)
			}
			if !hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE) {
				t.Fatal("hello lost MARKET_PROBE")
			}
			// Nothing is held back, so the session is not restarted.
			select {
			case again := <-gateway.hellos:
				t.Fatalf("unexpected reconnect hello: %v", again.GetCapabilities())
			case <-time.After(500 * time.Millisecond):
			}
		})
	}
}
