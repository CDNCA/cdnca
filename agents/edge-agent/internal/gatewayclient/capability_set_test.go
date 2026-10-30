package gatewayclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type legacyTestUpgradeRuntime struct{}

func (legacyTestUpgradeRuntime) Ready() bool                                 { return true }
func (legacyTestUpgradeRuntime) Recover(context.Context) error               { return nil }
func (legacyTestUpgradeRuntime) AcceptCommand(context.Context, []byte) error { return nil }
func (legacyTestUpgradeRuntime) PendingStatuses(context.Context) ([]updater.QueuedUpgradeStatus, error) {
	return nil, nil
}
func (legacyTestUpgradeRuntime) AcknowledgeStatus(context.Context, string, string, string) (bool, error) {
	return false, nil
}

// skewGateway answers like a Gateway that builds session facts only when every offered capability name is in its
// table (<= GATEWAY_PORT_TRANSITION, released=true) and without facts never enables EDGE_UPGRADE.
// authorized=false models a Gateway that does not authorize upgrades for this node at all.
type skewGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	released   bool
	authorized bool
	closeAfter time.Duration
	mu         sync.Mutex
	hellos     []*agentv1.AgentHello
	connected  chan struct{}
}

func (g *skewGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	g.mu.Lock()
	g.hellos = append(g.hellos, hello)
	g.mu.Unlock()
	factsRecorded := true
	for _, feature := range hello.GetCapabilities().GetFeatures() {
		if g.released && feature.GetName() > agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION {
			factsRecorded = false
		}
	}
	enabled := []*agentv1.Capability{}
	if g.authorized && factsRecorded && hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) {
		enabled = append(enabled, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1})
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "skew",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled}}}); err != nil {
		return err
	}
	select {
	case g.connected <- struct{}{}:
	default:
	}
	if g.closeAfter > 0 {
		select {
		case <-time.After(g.closeAfter):
			return nil
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func (g *skewGateway) offered() [][]agentv1.CapabilityName {
	g.mu.Lock()
	defer g.mu.Unlock()
	result := make([][]agentv1.CapabilityName, len(g.hellos))
	for index, hello := range g.hellos {
		for _, feature := range hello.GetCapabilities().GetFeatures() {
			result[index] = append(result[index], feature.GetName())
		}
	}
	return result
}

func offersCapability(names []agentv1.CapabilityName, name agentv1.CapabilityName) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}

func legacySkewClient(t *testing.T, gateway *skewGateway) runningClient {
	t.Helper()
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"edge-key": public})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	config.Capabilities.Features = append(config.Capabilities.Features,
		&agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE, ApiVersion: 1})
	return startBufconnClient(t, gateway, config, trust, WithUpgradeRuntime(legacyTestUpgradeRuntime{}))
}

func waitConnects(t *testing.T, gateway *skewGateway, count int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if len(gateway.offered()) >= count {
			return
		}
		select {
		case <-gateway.connected:
		case <-time.After(10 * time.Millisecond):
		case <-deadline:
			t.Fatalf("connects = %d, want %d", len(gateway.offered()), count)
		}
	}
}

// The agent offers its full capability set and keeps the session when a Gateway does not enable EDGE_UPGRADE:
// there is no reduced set for Gateways that predate the 1.0.35 baseline.
func TestAgentDoesNotFallBackToReducedCapabilities(t *testing.T) {
	for _, gateway := range []*skewGateway{
		{released: true, authorized: true, connected: make(chan struct{}, 8)},
		{authorized: false, connected: make(chan struct{}, 8)},
		{authorized: true, connected: make(chan struct{}, 8)},
	} {
		client := legacySkewClient(t, gateway)
		waitConnects(t, gateway, 1)
		time.Sleep(150 * time.Millisecond)
		client.cancel()
		offered := gateway.offered()
		if len(offered) != 1 || !offersCapability(offered[0], agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE) {
			t.Fatalf("released=%v authorized=%v: sessions = %v, want one session with the full set", gateway.released, gateway.authorized, offered)
		}
	}
}
