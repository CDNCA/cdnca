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

	"github.com/cdnca/cdnca/libs/edgeconfig/gatewayaddr"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type gatewayAddressBusStub struct {
	mu         sync.Mutex
	current    *agentv1.GatewayAddressChangeCommand
	subscribed chan string
	published  chan *agentv1.GatewayAddressChangeReceipt
}

func newGatewayAddressBusStub(current *agentv1.GatewayAddressChangeCommand) *gatewayAddressBusStub {
	return &gatewayAddressBusStub{current: current, subscribed: make(chan string, 4), published: make(chan *agentv1.GatewayAddressChangeReceipt, 4)}
}

type gatewayAddressSubscriptionStub struct {
	replay chan *agentv1.GatewayAddressChangeCommand
}

func (bus *gatewayAddressBusStub) SubscribeGatewayAddressChanges(_ context.Context, nodeID string) (GatewayAddressSubscription, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	replay := make(chan *agentv1.GatewayAddressChangeCommand, 1)
	if bus.current != nil {
		replay <- bus.current
	}
	bus.subscribed <- nodeID
	return &gatewayAddressSubscriptionStub{replay: replay}, nil
}

func (subscription *gatewayAddressSubscriptionStub) Next(ctx context.Context) (*agentv1.GatewayAddressChangeCommand, error) {
	select {
	case command := <-subscription.replay:
		return proto.Clone(command).(*agentv1.GatewayAddressChangeCommand), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*gatewayAddressSubscriptionStub) Close() error { return nil }

func (bus *gatewayAddressBusStub) PublishGatewayAddressReceipt(_ context.Context, _ string, receipt *agentv1.GatewayAddressChangeReceipt) (GatewayAddressPublication, error) {
	bus.published <- receipt
	return GatewayAddressPublication{Stream: gatewayaddr.ReceiptStream, Sequence: 1}, nil
}

func testGatewayAddressCommand(t *testing.T, nodeID string, revision uint64) *agentv1.GatewayAddressChangeCommand {
	t.Helper()
	_, private, _ := ed25519.GenerateKey(nil)
	now := time.Now()
	encoded, err := gatewayaddr.Sign(gatewayaddr.Change{NodeID: nodeID, ChangeID: uuid.NewString(), Revision: revision,
		Address: "gateway.cdnca.com:9443", ServerName: "gateway.cdnca.com", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()},
		"edge-publish", private)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return &agentv1.GatewayAddressChangeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, DocumentJson: encoded, DocumentSha256: digest[:],
	}
}

func testGatewayAddressReceipt(command *agentv1.GatewayAddressChangeCommand, state, code string) *agentv1.GatewayAddressChangeReceipt {
	return &agentv1.GatewayAddressChangeReceipt{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision,
		DocumentSha256: command.DocumentSha256, State: state, ErrorCode: code,
		ActiveAddress: "old.cdnca.com:443", ActiveServerName: "old.cdnca.com",
	}
}

func TestValidateGatewayAddressCommandAndReceiptBindings(t *testing.T) {
	command := testGatewayAddressCommand(t, testNodeID, 4)
	if err := validateGatewayAddressCommand(command, testNodeID); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.GatewayAddressChangeCommand){
		"node":     func(value *agentv1.GatewayAddressChangeCommand) { value.NodeId = uuid.NewString() },
		"revision": func(value *agentv1.GatewayAddressChangeCommand) { value.Revision = 5 },
		"digest":   func(value *agentv1.GatewayAddressChangeCommand) { value.DocumentSha256 = make([]byte, sha256.Size) },
		"body":     func(value *agentv1.GatewayAddressChangeCommand) { value.DocumentJson = []byte(`{}`) },
	} {
		changed := proto.Clone(command).(*agentv1.GatewayAddressChangeCommand)
		mutate(changed)
		if err := validateGatewayAddressCommand(changed, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	for _, valid := range []*agentv1.GatewayAddressChangeReceipt{
		testGatewayAddressReceipt(command, gatewayaddr.StateProbing, ""),
		testGatewayAddressReceipt(command, gatewayaddr.StateSwitched, ""),
		testGatewayAddressReceipt(command, gatewayaddr.StateFailed, gatewayaddr.ErrorDial),
	} {
		if err := validateGatewayAddressReceipt(valid, command, testNodeID); err != nil {
			t.Fatalf("valid %s rejected: %v", valid.State, err)
		}
	}
	for name, receipt := range map[string]*agentv1.GatewayAddressChangeReceipt{
		"failed no code":  testGatewayAddressReceipt(command, gatewayaddr.StateFailed, ""),
		"switched + code": testGatewayAddressReceipt(command, gatewayaddr.StateSwitched, gatewayaddr.ErrorDial),
		"unknown state":   testGatewayAddressReceipt(command, "done", ""),
		"other revision": func() *agentv1.GatewayAddressChangeReceipt {
			r := testGatewayAddressReceipt(command, gatewayaddr.StateProbing, "")
			r.Revision = 3
			return r
		}(),
		"other command id": func() *agentv1.GatewayAddressChangeReceipt {
			r := testGatewayAddressReceipt(command, gatewayaddr.StateProbing, "")
			r.CommandEventId = uuid.NewString()
			return r
		}(),
	} {
		if err := validateGatewayAddressReceipt(receipt, command, testNodeID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	unsupported := notSupportedGatewayAddressReceipt(command, time.Now())
	if err := validateGatewayAddressReceipt(unsupported, command, testNodeID); err != nil || unsupported.ErrorCode != gatewayaddr.ErrorNotSupported {
		t.Fatalf("not_supported receipt = %v, %v", unsupported, err)
	}
}

func connectGatewayAddressSession(t *testing.T, bus GatewayAddressBus, features []*agentv1.Capability) (agentv1.AgentGatewayService_ConnectClient, context.Context, *agentv1.GatewayHello) {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureGatewayAddressChanges(bus); err != nil {
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

func sendGatewayAddressReceiptRequest(t *testing.T, stream agentv1.AgentGatewayService_ConnectClient, sequence uint64, receipt *agentv1.GatewayAddressChangeReceipt) {
	t.Helper()
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_GatewayAddressChangeReceipt{GatewayAddressChangeReceipt: receipt},
	}); err != nil {
		t.Fatal(err)
	}
}

func awaitGatewayAddressReceipt(t *testing.T, bus *gatewayAddressBusStub, ctx context.Context) *agentv1.GatewayAddressChangeReceipt {
	t.Helper()
	select {
	case receipt := <-bus.published:
		return receipt
	case <-ctx.Done():
		t.Fatal("no gateway address receipt published")
		return nil
	}
}

// The current document is delivered on connect (deployments paused); probing
// and the final receipt are both relayed; a receipt after the final one is
// refused (nothing pending).
func TestGatewayAddressSessionDeliversDocumentAndRelaysProbingThenFinal(t *testing.T) {
	command := testGatewayAddressCommand(t, testNodeID, 3)
	bus := newGatewayAddressBusStub(command)
	stream, ctx, hello := connectGatewayAddressSession(t, bus,
		[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE, ApiVersion: 1}})
	enabled := false
	for _, capability := range hello.GetEnabledCapabilities() {
		enabled = enabled || capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_ADDRESS_CHANGE
	}
	if !enabled {
		t.Fatal("gateway did not enable GATEWAY_ADDRESS_CHANGE v1")
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetGatewayAddressChangeCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v", response.Payload)
	}
	probing := testGatewayAddressReceipt(command, gatewayaddr.StateProbing, "")
	sendGatewayAddressReceiptRequest(t, stream, 2, probing)
	if published := awaitGatewayAddressReceipt(t, bus, ctx); !proto.Equal(published, probing) {
		t.Fatalf("published %v", published)
	}
	failed := testGatewayAddressReceipt(command, gatewayaddr.StateFailed, gatewayaddr.ErrorDial)
	sendGatewayAddressReceiptRequest(t, stream, 3, failed)
	if published := awaitGatewayAddressReceipt(t, bus, ctx); !proto.Equal(published, failed) {
		t.Fatalf("published %v", published)
	}
	sendGatewayAddressReceiptRequest(t, stream, 4, testGatewayAddressReceipt(command, gatewayaddr.StateSwitched, ""))
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "without a pending document") {
		t.Fatalf("receipt after final: %v", err)
	}
}

func TestGatewayAddressUnsupportedNodeIsAnsweredNotSupported(t *testing.T) {
	command := testGatewayAddressCommand(t, testNodeID, 2)
	bus := newGatewayAddressBusStub(command)
	_, ctx, _ := connectGatewayAddressSession(t, bus, nil)
	receipt := awaitGatewayAddressReceipt(t, bus, ctx)
	if receipt.State != gatewayaddr.StateFailed || receipt.ErrorCode != gatewayaddr.ErrorNotSupported || receipt.Revision != 2 {
		t.Fatalf("receipt = %v", receipt)
	}
}
