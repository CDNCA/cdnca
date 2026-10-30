package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/signertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type signerTrustDeliveryStub struct {
	bundle *agentv1.EdgeSignerTrustBundle
	acks   chan string
	naks   chan string
	terms  chan string
}

func (delivery *signerTrustDeliveryStub) Bundle() *agentv1.EdgeSignerTrustBundle {
	return proto.Clone(delivery.bundle).(*agentv1.EdgeSignerTrustBundle)
}
func (delivery *signerTrustDeliveryStub) Ack(context.Context) error {
	delivery.acks <- delivery.bundle.Event.EventId
	return nil
}
func (delivery *signerTrustDeliveryStub) Nak(context.Context) error {
	delivery.naks <- delivery.bundle.Event.EventId
	return nil
}
func (delivery *signerTrustDeliveryStub) Term() error {
	delivery.terms <- delivery.bundle.Event.EventId
	return nil
}

type signerTrustBusStub struct {
	deliveries chan SignerTrustDelivery
	mu         sync.Mutex
	published  []*agentv1.EdgeSignerTrustReceipt
	subscribed chan string
}

func (bus *signerTrustBusStub) SubscribeSignerTrust(_ context.Context, nodeID string) (SignerTrustSubscription, error) {
	bus.subscribed <- nodeID
	return bus, nil
}

func (bus *signerTrustBusStub) Next(ctx context.Context) (SignerTrustDelivery, error) {
	select {
	case delivery := <-bus.deliveries:
		return delivery, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (*signerTrustBusStub) Close() error { return nil }

func (bus *signerTrustBusStub) PublishSignerTrustReceipt(_ context.Context, _ string, receipt *agentv1.EdgeSignerTrustReceipt) (SignerTrustPublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.published = append(bus.published, receipt)
	return SignerTrustPublication{Stream: signertrust.StatusStream, Sequence: uint64(len(bus.published))}, nil
}

// testSignerTrustBundle builds a carrier around bundle wire bytes with the
// routing fields the gateway binds (the signature is the Agent's concern).
func testSignerTrustBundle(t *testing.T, nodeID string, revision uint64) *agentv1.EdgeSignerTrustBundle {
	t.Helper()
	encoded := []byte(fmt.Sprintf(`{"schema":"cdnca.edge-signer-trust-bundle/v1","node_id":%q,"revision":%d,"document":"e30","issued_at":"2026-10-17T00:00:00Z","algorithm":"Ed25519","key_id":"control-edge","signature":"00"}`, nodeID, revision))
	digest := sha256.Sum256(encoded)
	return &agentv1.EdgeSignerTrustBundle{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		Schema: agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1, NodeId: nodeID, Revision: revision,
		BundleJson: encoded, BundleSha256: digest[:],
	}
}

func testSignerTrustReceipt(t *testing.T, bundle *agentv1.EdgeSignerTrustBundle, enforced uint64) *agentv1.EdgeSignerTrustReceipt {
	t.Helper()
	body, err := json.Marshal(map[string]any{"schema": "cdnca.edge-signer-trust-receipt/v1", "node_id": bundle.NodeId,
		"bundle_sha256": hex.EncodeToString(bundle.BundleSha256), "revision": enforced, "result": "applied",
		"reported_at": "2026-10-17T00:00:01Z"})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.EdgeSignerTrustReceipt{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		Schema: agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1, NodeId: bundle.NodeId, BundleEventId: bundle.Event.EventId,
		Revision: bundle.Revision, BundleSha256: bundle.BundleSha256, ReceiptJson: body,
	}
}

func TestValidateSignerTrustBundleAndReceiptBindings(t *testing.T) {
	bundle := testSignerTrustBundle(t, testNodeID, 7)
	if err := validateSignerTrustBundle(bundle, testNodeID); err != nil {
		t.Fatalf("valid bundle rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.EdgeSignerTrustBundle){
		"other node":      func(value *agentv1.EdgeSignerTrustBundle) { value.NodeId = uuid.NewString() },
		"routed revision": func(value *agentv1.EdgeSignerTrustBundle) { value.Revision = 8 },
		"digest":          func(value *agentv1.EdgeSignerTrustBundle) { value.BundleSha256[0] ^= 0xff },
		"body node": func(value *agentv1.EdgeSignerTrustBundle) {
			*value = *testSignerTrustBundle(t, uuid.NewString(), 7)
			value.NodeId = testNodeID
		},
		"schema": func(value *agentv1.EdgeSignerTrustBundle) {
			value.Schema = agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_UNSPECIFIED
		},
	} {
		changed := proto.Clone(bundle).(*agentv1.EdgeSignerTrustBundle)
		mutate(changed)
		if err := validateSignerTrustBundle(changed, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
	// A rejected bundle reports the lower revision the node still enforces.
	for _, enforced := range []uint64{7, 3} {
		if err := validateSignerTrustReceipt(testSignerTrustReceipt(t, bundle, enforced), bundle, testNodeID); err != nil {
			t.Fatalf("valid receipt (enforced %d) rejected: %v", enforced, err)
		}
	}
	receipt := testSignerTrustReceipt(t, bundle, 7)
	for name, mutate := range map[string]func(*agentv1.EdgeSignerTrustReceipt){
		"bundle event": func(value *agentv1.EdgeSignerTrustReceipt) { value.BundleEventId = uuid.NewString() },
		"digest":       func(value *agentv1.EdgeSignerTrustReceipt) { value.BundleSha256 = make([]byte, sha256.Size) },
		"body":         func(value *agentv1.EdgeSignerTrustReceipt) { value.ReceiptJson = []byte(`{}`) },
		"node":         func(value *agentv1.EdgeSignerTrustReceipt) { value.NodeId = uuid.NewString() },
		"revision":     func(value *agentv1.EdgeSignerTrustReceipt) { value.Revision = 6 },
	} {
		changed := proto.Clone(receipt).(*agentv1.EdgeSignerTrustReceipt)
		mutate(changed)
		if err := validateSignerTrustReceipt(changed, bundle, testNodeID); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
}

type signerTrustSession struct {
	stream agentv1.AgentGatewayService_ConnectClient
	hello  *agentv1.GatewayHello
	ctx    context.Context
}

func connectSignerTrustSession(t *testing.T, bus SignerTrustBus, features []*agentv1.Capability) signerTrustSession {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	// defaultFakeControl does not allow deployments: signer trust is delivered regardless.
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureSignerTrust(bus); err != nil {
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
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	return signerTrustSession{stream: stream, hello: first.GetHello(), ctx: ctx}
}

// TestSignerTrustNotNegotiatedWithoutCapability: an Agent without
// EDGE_SIGNER_TRUST gets no subscription and may not send receipts.
func TestSignerTrustNotNegotiatedWithoutCapability(t *testing.T) {
	bus := &signerTrustBusStub{deliveries: make(chan SignerTrustDelivery, 1), subscribed: make(chan string, 1)}
	session := connectSignerTrustSession(t, bus, nil)
	if negotiated, _ := signerTrustCapabilityFromFeatures(session.hello.GetEnabledCapabilities()); negotiated {
		t.Fatal("edge signer trust enabled for an Agent that did not advertise it")
	}
	bundle := testSignerTrustBundle(t, testNodeID, 1)
	if err := session.stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_EdgeSignerTrustReceipt{EdgeSignerTrustReceipt: testSignerTrustReceipt(t, bundle, 1)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := session.stream.Recv(); err == nil || !strings.Contains(err.Error(), "not negotiated") {
		t.Fatalf("unnegotiated receipt: %v", err)
	}
	select {
	case nodeID := <-bus.subscribed:
		t.Fatalf("subscribed for %s without the capability", nodeID)
	default:
	}
}

// TestSignerTrustSessionDeliversBundleAndAcksAfterReceipt drives a real mTLS
// Connect session whose deployments are paused: the capability is negotiated,
// the bundle reaches the Agent, the delivery is acknowledged only after the
// receipt is published, and a broken binding is dropped without closing the session.
func TestSignerTrustSessionDeliversBundleAndAcksAfterReceipt(t *testing.T) {
	bus := &signerTrustBusStub{deliveries: make(chan SignerTrustDelivery, 4), subscribed: make(chan string, 4)}
	session := connectSignerTrustSession(t, bus, []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1}})
	if negotiated, _ := signerTrustCapabilityFromFeatures(session.hello.GetEnabledCapabilities()); !negotiated {
		t.Fatalf("edge signer trust capability not enabled: %v", session.hello.GetEnabledCapabilities())
	}
	select {
	case nodeID := <-bus.subscribed:
		if nodeID != testNodeID {
			t.Fatalf("subscribed for %s", nodeID)
		}
	case <-session.ctx.Done():
		t.Fatal("gateway did not subscribe for the authenticated node")
	}
	acks, naks, terms := make(chan string, 4), make(chan string, 4), make(chan string, 4)
	broken := testSignerTrustBundle(t, testNodeID, 3)
	broken.Revision = 4
	bus.deliveries <- &signerTrustDeliveryStub{bundle: broken, acks: acks, naks: naks, terms: terms}
	bundle := testSignerTrustBundle(t, testNodeID, 5)
	bus.deliveries <- &signerTrustDeliveryStub{bundle: bundle, acks: acks, naks: naks, terms: terms}
	response, err := session.stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetEdgeSignerTrustBundle(); delivered == nil || !proto.Equal(delivered, bundle) {
		t.Fatalf("delivered %v, want the valid bundle", response.Payload)
	}
	if dropped := <-terms; dropped != broken.Event.EventId {
		t.Fatalf("terminated %s, want the broken bundle", dropped)
	}
	select {
	case id := <-acks:
		t.Fatalf("bundle %s acknowledged before its receipt", id)
	case <-time.After(100 * time.Millisecond):
	}
	receipt := testSignerTrustReceipt(t, bundle, 5)
	if err := session.stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_EdgeSignerTrustReceipt{EdgeSignerTrustReceipt: receipt},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-acks:
		if id != bundle.Event.EventId {
			t.Fatalf("acknowledged %s", id)
		}
	case <-session.ctx.Done():
		t.Fatal("bundle was not acknowledged after its receipt")
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 1 || !proto.Equal(bus.published[0], receipt) {
		t.Fatalf("published receipts = %v", bus.published)
	}
	select {
	case id := <-naks:
		t.Fatalf("unexpected nak %s", id)
	default:
	}
}
