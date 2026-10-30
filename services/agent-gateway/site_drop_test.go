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

	"github.com/cdnca/cdnca/libs/edgeconfig/sitedrop"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// siteDropBusStub replays current (the node's newest snapshot) to every new
// subscription, like the LimitsPolicy stream; later pushes go to the live one.
type siteDropBusStub struct {
	mu         sync.Mutex
	current    *agentv1.SiteDropCommand
	live       chan *agentv1.SiteDropCommand
	subscribed chan string
	published  chan *agentv1.SiteDropReceipt
}

func newSiteDropBusStub(current *agentv1.SiteDropCommand) *siteDropBusStub {
	return &siteDropBusStub{current: current, subscribed: make(chan string, 4), published: make(chan *agentv1.SiteDropReceipt, 4)}
}

type siteDropSubscriptionStub struct {
	replay chan *agentv1.SiteDropCommand
	live   chan *agentv1.SiteDropCommand
}

func (bus *siteDropBusStub) SubscribeSiteDrops(_ context.Context, nodeID string) (SiteDropSubscription, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	replay := make(chan *agentv1.SiteDropCommand, 1)
	if bus.current != nil {
		replay <- bus.current
	}
	bus.live = make(chan *agentv1.SiteDropCommand, 4)
	bus.subscribed <- nodeID
	return &siteDropSubscriptionStub{replay: replay, live: bus.live}, nil
}

func (bus *siteDropBusStub) push(command *agentv1.SiteDropCommand) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.current = command
	bus.live <- command
}

func (subscription *siteDropSubscriptionStub) Next(ctx context.Context) (*agentv1.SiteDropCommand, error) {
	select {
	case command := <-subscription.replay:
		return proto.Clone(command).(*agentv1.SiteDropCommand), nil
	default:
	}
	select {
	case command := <-subscription.live:
		return proto.Clone(command).(*agentv1.SiteDropCommand), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*siteDropSubscriptionStub) Close() error { return nil }

func (bus *siteDropBusStub) PublishSiteDropReceipt(_ context.Context, _ string, receipt *agentv1.SiteDropReceipt) (SiteDropPublication, error) {
	bus.published <- receipt
	return SiteDropPublication{Stream: sitedrop.ReceiptStream, Sequence: 1}, nil
}

func testSiteDropCommand(t *testing.T, nodeID string, revision uint64) *agentv1.SiteDropCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	now := time.Now().Unix()
	encoded, err := sitedrop.Sign(sitedrop.List{NodeID: nodeID, Revision: revision, IssuedAt: now,
		Sites: []sitedrop.Site{{SiteID: "22222222-2222-4222-8222-222222222222", TenantID: "33333333-3333-4333-8333-333333333333",
			Since: now - 60, Until: now + 3600}}}, "edge-publish", private)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.SiteDropCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, ListJson: encoded, ListSha256: digest[:],
	}
}

func testSiteDropReceipt(command *agentv1.SiteDropCommand) *agentv1.SiteDropReceipt {
	return &agentv1.SiteDropReceipt{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		ListSha256: command.ListSha256, Applied: true, Mode: "nftables", Sites: 1, Ports: 1,
	}
}

func TestValidateSiteDropCommandAndReceiptBindings(t *testing.T) {
	command := testSiteDropCommand(t, testNodeID, 4)
	if err := validateSiteDropCommand(command, testNodeID); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.SiteDropCommand){
		"node":     func(value *agentv1.SiteDropCommand) { value.NodeId = uuid.NewString() },
		"revision": func(value *agentv1.SiteDropCommand) { value.Revision = 5 },
		"digest":   func(value *agentv1.SiteDropCommand) { value.ListSha256 = make([]byte, sha256.Size) },
		"body":     func(value *agentv1.SiteDropCommand) { value.ListJson = []byte(`{}`) },
		"event":    func(value *agentv1.SiteDropCommand) { value.Event.EventId = "x" },
	} {
		changed := proto.Clone(command).(*agentv1.SiteDropCommand)
		mutate(changed)
		if err := validateSiteDropCommand(changed, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	if err := validateSiteDropCommand(command, uuid.NewString()); err == nil {
		t.Fatal("snapshot for another node accepted")
	}
	receipt := testSiteDropReceipt(command)
	if err := validateSiteDropReceipt(receipt, command, testNodeID); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.SiteDropReceipt){
		"command event":    func(value *agentv1.SiteDropReceipt) { value.CommandEventId = uuid.NewString() },
		"digest":           func(value *agentv1.SiteDropReceipt) { value.ListSha256 = make([]byte, sha256.Size) },
		"revision":         func(value *agentv1.SiteDropReceipt) { value.Revision = 3 },
		"node":             func(value *agentv1.SiteDropReceipt) { value.NodeId = uuid.NewString() },
		"applied + error":  func(value *agentv1.SiteDropReceipt) { value.ErrorCode = sitedrop.ErrorStale },
		"refused no error": func(value *agentv1.SiteDropReceipt) { value.Applied = false },
	} {
		changed := proto.Clone(receipt).(*agentv1.SiteDropReceipt)
		mutate(changed)
		if err := validateSiteDropReceipt(changed, command, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	unsupported := notSupportedSiteDropReceipt(command, time.Now())
	if err := validateSiteDropReceipt(unsupported, command, testNodeID); err != nil || unsupported.Applied ||
		unsupported.ErrorCode != sitedrop.ErrorNotSupported {
		t.Fatalf("not_supported receipt = %v, %v", unsupported, err)
	}
	if again := notSupportedSiteDropReceipt(command, time.Now()); again.Event.EventId != unsupported.Event.EventId {
		t.Fatal("not_supported receipt identity does not follow the command")
	}
}

func TestSiteDropCapabilityRejectsDuplicateOrOtherVersion(t *testing.T) {
	capability := &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1}
	if ok, err := siteDropCapabilityFromFeatures([]*agentv1.Capability{capability}); !ok || err != nil {
		t.Fatalf("v1 = %v, %v", ok, err)
	}
	if _, err := siteDropCapabilityFromFeatures([]*agentv1.Capability{capability, capability}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := siteDropCapabilityFromFeatures([]*agentv1.Capability{{Name: capability.Name, ApiVersion: 2}}); err == nil {
		t.Fatal("v2 accepted")
	}
}

func connectSiteDropSession(t *testing.T, bus SiteDropBus, features []*agentv1.Capability) (agentv1.AgentGatewayService_ConnectClient, context.Context, *agentv1.GatewayHello) {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	// defaultFakeControl does not allow deployments: site drop lists are delivered regardless.
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureSiteDrops(bus); err != nil {
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
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return stream, ctx, response.GetHello()
}

func siteDropCapabilityEnabled(hello *agentv1.GatewayHello) bool {
	for _, capability := range hello.GetEnabledCapabilities() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP && capability.GetApiVersion() == siteDropAPIVersion {
			return true
		}
	}
	return false
}

func sendSiteDropReceiptRequest(t *testing.T, stream agentv1.AgentGatewayService_ConnectClient, sequence uint64, receipt *agentv1.SiteDropReceipt) {
	t.Helper()
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_SiteDropReceipt{SiteDropReceipt: receipt},
	}); err != nil {
		t.Fatal(err)
	}
}

func awaitSiteDropReceipt(t *testing.T, bus *siteDropBusStub, ctx context.Context) *agentv1.SiteDropReceipt {
	t.Helper()
	select {
	case receipt := <-bus.published:
		return receipt
	case <-ctx.Done():
		t.Fatal("no site drop receipt published")
		return nil
	}
}

// A SITE_DROP v1 Agent gets the current snapshot on connect (deployments
// paused), its receipt is relayed to control-api, a broken snapshot is
// skipped without closing the session and the next snapshot waits for the
// receipt of the one in flight.
func TestSiteDropSessionDeliversCurrentSnapshotAndRelaysReceipt(t *testing.T) {
	first := testSiteDropCommand(t, testNodeID, 3)
	bus := newSiteDropBusStub(first)
	stream, ctx, hello := connectSiteDropSession(t, bus,
		[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1}})
	if !siteDropCapabilityEnabled(hello) {
		t.Fatal("gateway did not enable SITE_DROP v1")
	}
	if nodeID := <-bus.subscribed; nodeID != testNodeID {
		t.Fatalf("subscribed for %s", nodeID)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetSiteDropCommand(); delivered == nil || !proto.Equal(delivered, first) {
		t.Fatalf("delivered %v, want the current snapshot", response.Payload)
	}
	broken := testSiteDropCommand(t, testNodeID, 4)
	broken.Revision = 9
	bus.push(broken)
	second := testSiteDropCommand(t, testNodeID, 5)
	bus.push(second)
	receipt := testSiteDropReceipt(first)
	sendSiteDropReceiptRequest(t, stream, 2, receipt)
	if published := awaitSiteDropReceipt(t, bus, ctx); !proto.Equal(published, receipt) {
		t.Fatalf("published %v", published)
	}
	response, err = stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetSiteDropCommand(); delivered == nil || !proto.Equal(delivered, second) {
		t.Fatalf("delivered %v, want revision 5 (broken one skipped)", response.Payload)
	}
	// A receipt that does not answer the snapshot in flight closes the session.
	sendSiteDropReceiptRequest(t, stream, 3, testSiteDropReceipt(first))
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "site drop receipt is invalid") {
		t.Fatalf("mismatched receipt: %v", err)
	}
}

// A node without SITE_DROP v1 is sent nothing; the gateway answers
// not_supported so control-api marks it, and may not send a receipt itself.
func TestSiteDropUnsupportedNodeIsAnsweredNotSupported(t *testing.T) {
	command := testSiteDropCommand(t, testNodeID, 2)
	bus := newSiteDropBusStub(command)
	stream, ctx, hello := connectSiteDropSession(t, bus, nil)
	if siteDropCapabilityEnabled(hello) {
		t.Fatal("SITE_DROP enabled for a node that did not declare it")
	}
	receipt := awaitSiteDropReceipt(t, bus, ctx)
	if receipt.NodeId != testNodeID || receipt.Revision != 2 || receipt.Applied || receipt.ErrorCode != sitedrop.ErrorNotSupported ||
		receipt.CommandEventId != command.Event.EventId || validateSiteDropReceipt(receipt, command, testNodeID) != nil {
		t.Fatalf("not_supported receipt = %v", receipt)
	}
	sendSiteDropReceiptRequest(t, stream, 2, testSiteDropReceipt(command))
	response, err := stream.Recv()
	if err == nil {
		if response.GetSiteDropCommand() != nil {
			t.Fatal("site drop command sent to a node without SITE_DROP")
		}
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), "not negotiated") {
		t.Fatalf("unnegotiated receipt: %v", err)
	}
}

// Reconnect (and a gateway restart, which is a new session too) resends the
// current snapshot, even one already answered.
func TestSiteDropReconnectResendsCurrentSnapshot(t *testing.T) {
	command := testSiteDropCommand(t, testNodeID, 7)
	bus := newSiteDropBusStub(command)
	features := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_DROP, ApiVersion: 1}}
	for attempt := range 2 {
		stream, ctx, _ := connectSiteDropSession(t, bus, features)
		response, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if delivered := response.GetSiteDropCommand(); delivered == nil || !proto.Equal(delivered, command) {
			t.Fatalf("attempt %d delivered %v", attempt, response.Payload)
		}
		sendSiteDropReceiptRequest(t, stream, 2, testSiteDropReceipt(command))
		awaitSiteDropReceipt(t, bus, ctx)
		_ = stream.CloseSend()
	}
}
