package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type securityBanDeliveryStub struct {
	command          *agentv1.SecurityBanCommand
	acks, naks, term chan string
}

func (delivery *securityBanDeliveryStub) Command() *agentv1.SecurityBanCommand {
	return proto.Clone(delivery.command).(*agentv1.SecurityBanCommand)
}
func (delivery *securityBanDeliveryStub) Ack(context.Context) error {
	delivery.acks <- delivery.command.Event.EventId
	return nil
}
func (delivery *securityBanDeliveryStub) Nak(context.Context) error {
	delivery.naks <- delivery.command.Event.EventId
	return nil
}
func (delivery *securityBanDeliveryStub) Term() error {
	delivery.term <- delivery.command.Event.EventId
	return nil
}

type securityBanBusStub struct {
	deliveries chan SecurityBanDelivery
	subscribed chan string
	mu         sync.Mutex
	published  []*agentv1.SecurityBanStatus
}

func (bus *securityBanBusStub) SubscribeSecurityBans(_ context.Context, nodeID string) (SecurityBanSubscription, error) {
	bus.subscribed <- nodeID
	return bus, nil
}
func (bus *securityBanBusStub) Next(ctx context.Context) (SecurityBanDelivery, error) {
	select {
	case delivery := <-bus.deliveries:
		return delivery, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*securityBanBusStub) Close() error { return nil }
func (bus *securityBanBusStub) PublishSecurityBanStatus(_ context.Context, _ string, report *agentv1.SecurityBanStatus) (SecurityBanPublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.published = append(bus.published, report)
	return SecurityBanPublication{Stream: securityban.StatusStream, Sequence: uint64(len(bus.published))}, nil
}

func testSecurityBanCommand(t *testing.T, nodeID string, revision uint64) *agentv1.SecurityBanCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	list := securityban.List{Schema: securityban.Schema, NodeID: nodeID, Revision: revision, IssuedAt: time.Now().Unix(),
		Bans:     []securityban.Ban{{SiteID: "22222222-2222-4222-8222-222222222222", Client: "198.51.100.7", Until: time.Now().Unix() + 60, Source: "manual"}},
		Releases: []securityban.Release{}, Algorithm: securityban.Algorithm, KeyID: "edge-publish"}
	payload, err := securityban.SigningPayload(list)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := securityban.Seal(list, ed25519.Sign(private, payload))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.SecurityBanCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, ListJson: encoded, ListSha256: digest[:],
	}
}

func testSecurityBanStatus(command *agentv1.SecurityBanCommand) *agentv1.SecurityBanStatus {
	return &agentv1.SecurityBanStatus{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		ListSha256: command.ListSha256, Applied: true, Bans: 1,
	}
}

func TestValidateSecurityBanCommandAndStatusBindings(t *testing.T) {
	command := testSecurityBanCommand(t, testNodeID, 4)
	if err := validateSecurityBanCommand(command, testNodeID); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.SecurityBanCommand){
		"node":     func(value *agentv1.SecurityBanCommand) { value.NodeId = uuid.NewString() },
		"revision": func(value *agentv1.SecurityBanCommand) { value.Revision = 5 },
		"digest":   func(value *agentv1.SecurityBanCommand) { value.ListSha256 = make([]byte, sha256.Size) },
		"body":     func(value *agentv1.SecurityBanCommand) { value.ListJson = []byte(`{}`) },
		"event":    func(value *agentv1.SecurityBanCommand) { value.Event.EventId = "x" },
	} {
		changed := proto.Clone(command).(*agentv1.SecurityBanCommand)
		mutate(changed)
		if err := validateSecurityBanCommand(changed, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	report := testSecurityBanStatus(command)
	if err := validateSecurityBanStatus(report, command, testNodeID); err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.SecurityBanStatus){
		"command event":    func(value *agentv1.SecurityBanStatus) { value.CommandEventId = uuid.NewString() },
		"digest":           func(value *agentv1.SecurityBanStatus) { value.ListSha256 = make([]byte, sha256.Size) },
		"revision":         func(value *agentv1.SecurityBanStatus) { value.Revision = 3 },
		"applied + error":  func(value *agentv1.SecurityBanStatus) { value.ErrorCode = "stale_revision" },
		"refused no error": func(value *agentv1.SecurityBanStatus) { value.Applied = false },
	} {
		changed := proto.Clone(report).(*agentv1.SecurityBanStatus)
		mutate(changed)
		if err := validateSecurityBanStatus(changed, command, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
}

func connectSecurityBanSession(t *testing.T, bus SecurityBanBus, features []*agentv1.Capability) (agentv1.AgentGatewayService_ConnectClient, context.Context) {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	// defaultFakeControl does not allow deployments: ban lists are delivered regardless.
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureSecurityBans(bus); err != nil {
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
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities.Features = features
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	return stream, ctx
}

// A WAF v1 Agent gets no ban list subscription and may not send a status.
func TestSecurityBansNotNegotiatedBelowWAFv2(t *testing.T) {
	bus := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 1), subscribed: make(chan string, 1)}
	stream, _ := connectSecurityBanSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1}})
	command := testSecurityBanCommand(t, testNodeID, 1)
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_SecurityBanStatus{SecurityBanStatus: testSecurityBanStatus(command)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "not negotiated") {
		t.Fatalf("unnegotiated status: %v", err)
	}
	select {
	case nodeID := <-bus.subscribed:
		t.Fatalf("subscribed for %s without WAF v2", nodeID)
	default:
	}
}

// A WAF v2 Agent receives the snapshot (deployments paused or not); the
// delivery is acknowledged only after its status is published; a snapshot
// with a broken binding is dropped without closing the session.
func TestSecurityBanSessionDeliversAndAcksAfterStatus(t *testing.T) {
	bus := &securityBanBusStub{deliveries: make(chan SecurityBanDelivery, 4), subscribed: make(chan string, 4)}
	stream, ctx := connectSecurityBanSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 2}})
	select {
	case nodeID := <-bus.subscribed:
		if nodeID != testNodeID {
			t.Fatalf("subscribed for %s", nodeID)
		}
	case <-ctx.Done():
		t.Fatal("gateway did not subscribe for the authenticated node")
	}
	acks, naks, terms := make(chan string, 4), make(chan string, 4), make(chan string, 4)
	broken := testSecurityBanCommand(t, testNodeID, 3)
	broken.Revision = 9
	bus.deliveries <- &securityBanDeliveryStub{command: broken, acks: acks, naks: naks, term: terms}
	command := testSecurityBanCommand(t, testNodeID, 5)
	bus.deliveries <- &securityBanDeliveryStub{command: command, acks: acks, naks: naks, term: terms}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetSecurityBanCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v, want the valid snapshot", response.Payload)
	}
	if dropped := <-terms; dropped != broken.Event.EventId {
		t.Fatalf("terminated %s, want the broken snapshot", dropped)
	}
	select {
	case id := <-acks:
		t.Fatalf("snapshot %s acknowledged before its status", id)
	case <-time.After(100 * time.Millisecond):
	}
	report := testSecurityBanStatus(command)
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_SecurityBanStatus{SecurityBanStatus: report},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-acks:
		if id != command.Event.EventId {
			t.Fatalf("acknowledged %s", id)
		}
	case <-ctx.Done():
		t.Fatal("snapshot was not acknowledged after its status")
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 1 || !proto.Equal(bus.published[0], report) {
		t.Fatalf("published statuses = %v", bus.published)
	}
	select {
	case id := <-naks:
		t.Fatalf("unexpected nak %s", id)
	default:
	}
}
