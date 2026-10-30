package gatewayclient

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// helloGateway accepts every session (hour-long heartbeats) and records the
// hellos.
type helloGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	hellos chan *agentv1.AgentHello
}

func (g *helloGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	g.hellos <- first.GetHello()
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128}}}); err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
	}
}

// XDP_FILTER is withdrawn as soon as the filter falls back
// (a new hello without it, not at the next unrelated reconnect) and declared
// again once it reattaches; a signal that changes nothing keeps the session.
func TestLiveCapabilityChangeRedeclaresAtOnce(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	changed := make(chan struct{}, 1)
	gateway := &helloGateway{hellos: make(chan *agentv1.AgentHello, 8)}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	client := startBufconnClient(t, gateway, config, testTrust(t), WithLiveCapability(LiveCapability{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1, Ready: ready.Load, Changed: changed}))
	defer client.cancel()
	next := func(step string) *agentv1.AgentHello {
		t.Helper()
		select {
		case hello := <-gateway.hellos:
			return hello
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: no hello", step)
			return nil
		}
	}
	declared := func(hello *agentv1.AgentHello) bool {
		for _, capability := range hello.GetCapabilities().GetFeatures() {
			if capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER {
				return capability.ApiVersion == 1
			}
		}
		return false
	}
	if hello := next("start"); !declared(hello) {
		t.Fatalf("attached filter not declared: %v", hello.GetCapabilities().GetFeatures())
	}
	changed <- struct{}{} // nothing changed: the session stays
	select {
	case hello := <-gateway.hellos:
		t.Fatalf("reconnected without a change: %v", hello.GetCapabilities().GetFeatures())
	case <-time.After(300 * time.Millisecond):
	}
	ready.Store(false)
	changed <- struct{}{}
	if hello := next("fallback"); declared(hello) {
		t.Fatalf("fallen back filter still declared: %v", hello.GetCapabilities().GetFeatures())
	}
	ready.Store(true)
	changed <- struct{}{}
	if hello := next("reattach"); !declared(hello) {
		t.Fatalf("reattached filter not declared: %v", hello.GetCapabilities().GetFeatures())
	}
}

func TestLiveCapabilityOptionValidates(t *testing.T) {
	for name, capability := range map[string]LiveCapability{
		"no ready":   {Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1},
		"no version": {Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, Ready: func() bool { return true }},
		"no name":    {APIVersion: 1, Ready: func() bool { return true }},
	} {
		config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
		client, err := New(config, &bufDialer{}, noOpManager{}, testTrust(t), WithLiveCapability(capability))
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
		if client != nil {
			_ = client.Close()
		}
	}
}
