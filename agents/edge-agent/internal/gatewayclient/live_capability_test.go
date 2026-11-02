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

// on a new node the dynamic routing skeleton (overlay
// root) is written after the first hello. ACME_HTTP01_OVERLAY must be declared
// once it is there, without an agent restart, and withdrawn when it goes; a
// poll that finds nothing changed keeps the session.
func TestACMEHTTP01OverlayDeclaredOnceSkeletonReady(t *testing.T) {
	consumer := &fakeACMEHTTP01Consumer{}
	gateway := &helloGateway{hellos: make(chan *agentv1.AgentHello, 8)}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	fastPoll := func(client *Client) error { client.acmeHTTP01Poll = 20 * time.Millisecond; return nil }
	client := startBufconnClient(t, gateway, config, testTrust(t), fastPoll, WithACMEHTTP01OverlayConsumer(consumer))
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
	setReady := func(ready bool) {
		consumer.mu.Lock()
		consumer.ready = ready
		consumer.mu.Unlock()
	}
	overlay := agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY
	if hello := next("start"); hasCapability(hello.Capabilities, overlay) {
		t.Fatalf("overlay declared before the skeleton: %v", hello.GetCapabilities().GetFeatures())
	}
	select {
	case hello := <-gateway.hellos:
		t.Fatalf("reconnected without a change: %v", hello.GetCapabilities().GetFeatures())
	case <-time.After(300 * time.Millisecond):
	}
	setReady(true)
	hello := next("skeleton written")
	if !hasCapability(hello.Capabilities, overlay) {
		t.Fatalf("ready overlay not declared: %v", hello.GetCapabilities().GetFeatures())
	}
	for _, capability := range hello.GetCapabilities().GetFeatures() {
		if capability.Name == overlay && capability.ApiVersion != 1 {
			t.Fatalf("overlay api version = %d", capability.ApiVersion)
		}
	}
	setReady(false)
	if hello := next("skeleton removed"); hasCapability(hello.Capabilities, overlay) {
		t.Fatalf("removed overlay still declared: %v", hello.GetCapabilities().GetFeatures())
	}
}

func TestLiveCapabilityOptionRejectsDuplicates(t *testing.T) {
	ready := func() bool { return true }
	signal := make(chan struct{})
	for name, options := range map[string][]ClientOption{
		"same name": {
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1, Ready: ready}),
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1, Ready: ready}),
		},
		"overlay twice": {
			WithACMEHTTP01OverlayConsumer(&fakeACMEHTTP01Consumer{}),
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_ACME_HTTP01_OVERLAY, APIVersion: 1, Ready: ready}),
		},
		"two signals": {
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1, Ready: ready, Changed: signal}),
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, APIVersion: 1, Ready: ready, Changed: signal}),
		},
		"negative poll": {
			WithLiveCapability(LiveCapability{Name: agentv1.CapabilityName_CAPABILITY_NAME_XDP_FILTER, APIVersion: 1, Ready: ready, Poll: -time.Second}),
		},
	} {
		config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
		client, err := New(config, &bufDialer{}, noOpManager{}, testTrust(t), options...)
		if !errors.Is(err, ErrInvalidConfiguration) {
			t.Errorf("%s: %v", name, err)
		}
		if client != nil {
			_ = client.Close()
		}
	}
}
