package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/installationban"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type installationBanDeliveryStub struct {
	command           *agentv1.InstallationBanCommand
	acks, naks, terms chan string
}

func (delivery *installationBanDeliveryStub) Command() *agentv1.InstallationBanCommand {
	return proto.Clone(delivery.command).(*agentv1.InstallationBanCommand)
}
func (delivery *installationBanDeliveryStub) Ack(context.Context) error {
	delivery.acks <- delivery.command.Event.EventId
	return nil
}
func (delivery *installationBanDeliveryStub) Nak(context.Context) error {
	delivery.naks <- delivery.command.Event.EventId
	return nil
}
func (delivery *installationBanDeliveryStub) Term() error {
	delivery.terms <- delivery.command.Event.EventId
	return nil
}

type installationBanBusStub struct {
	deliveries chan InstallationBanDelivery
	subscribed chan string
	mu         sync.Mutex
	published  []*agentv1.InstallationBanReceipt
}

func (bus *installationBanBusStub) SubscribeInstallationBan(_ context.Context, nodeID string) (InstallationBanSubscription, error) {
	bus.subscribed <- nodeID
	return bus, nil
}
func (bus *installationBanBusStub) Next(ctx context.Context) (InstallationBanDelivery, error) {
	select {
	case delivery := <-bus.deliveries:
		return delivery, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*installationBanBusStub) Close() error { return nil }
func (bus *installationBanBusStub) PublishInstallationBanReceipt(_ context.Context, _ string,
	receipt *agentv1.InstallationBanReceipt,
) (InstallationBanPublication, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.published = append(bus.published, receipt)
	return InstallationBanPublication{Stream: contract.StatusStream, Sequence: uint64(len(bus.published))}, nil
}

func testInstallationBanCommand(nodeID string, revision uint64) *agentv1.InstallationBanCommand {
	notice := []byte(`{"opaque":"the node verifies the signature"}`)
	digest := sha256.Sum256(notice)
	return &agentv1.InstallationBanCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, NoticeJson: notice, NoticeSha256: digest[:],
	}
}

func testInstallationBanReceipt(command *agentv1.InstallationBanCommand) *agentv1.InstallationBanReceipt {
	return &agentv1.InstallationBanReceipt{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, Revision: command.Revision, Applied: true,
		Status: "banned",
	}
}

func TestValidateInstallationBanBindings(t *testing.T) {
	command := testInstallationBanCommand(testNodeID, 3)
	if err := validateInstallationBanCommand(command, testNodeID); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*agentv1.InstallationBanCommand){
		"other node":    func(c *agentv1.InstallationBanCommand) { c.NodeId = uuid.NewString() },
		"zero revision": func(c *agentv1.InstallationBanCommand) { c.Revision = 0 },
		"digest":        func(c *agentv1.InstallationBanCommand) { c.NoticeSha256[0] ^= 1 },
		"empty":         func(c *agentv1.InstallationBanCommand) { c.NoticeJson, c.NoticeSha256 = nil, nil },
		"orphan digest": func(c *agentv1.InstallationBanCommand) { c.TicketSha256 = make([]byte, 32) },
		"missing event": func(c *agentv1.InstallationBanCommand) { c.Event = nil },
	} {
		broken := proto.Clone(command).(*agentv1.InstallationBanCommand)
		mutate(broken)
		if validateInstallationBanCommand(broken, testNodeID) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	receipt := testInstallationBanReceipt(command)
	if err := validateInstallationBanReceipt(receipt, command, testNodeID); err != nil {
		t.Fatal(err)
	}
	withTicket := proto.Clone(receipt).(*agentv1.InstallationBanReceipt)
	withTicket.TicketIssuedTime, withTicket.TicketNotAfterTime = timestamppb.Now(), timestamppb.New(time.Now().Add(7*24*time.Hour))
	if err := validateInstallationBanReceipt(withTicket, command, testNodeID); err != nil {
		t.Fatalf("receipt with ticket times: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.InstallationBanReceipt){
		"status":   func(r *agentv1.InstallationBanReceipt) { r.Status = "paused" },
		"revision": func(r *agentv1.InstallationBanReceipt) { r.Revision++ },
		"event":    func(r *agentv1.InstallationBanReceipt) { r.CommandEventId = uuid.NewString() },
		// PF09 held ticket times: both or neither, not_after after issued
		"ticket issued only": func(r *agentv1.InstallationBanReceipt) { r.TicketIssuedTime = timestamppb.Now() },
		"ticket not after before issued": func(r *agentv1.InstallationBanReceipt) {
			r.TicketIssuedTime, r.TicketNotAfterTime = timestamppb.Now(), timestamppb.New(time.Now().Add(-time.Hour))
		},
	} {
		broken := proto.Clone(receipt).(*agentv1.InstallationBanReceipt)
		mutate(broken)
		if validateInstallationBanReceipt(broken, command, testNodeID) == nil {
			t.Errorf("receipt %s: accepted", name)
		}
	}
}

// TestInstallationBanSessionDeliversCommandAndAcksAfterReceipt: a session
// whose deployments are paused negotiates the capability, receives the
// command, and the delivery is acknowledged only after the receipt is
// published; a broken binding is dropped without closing the session.
func TestInstallationBanSessionDeliversCommandAndAcksAfterReceipt(t *testing.T) {
	bus := &installationBanBusStub{deliveries: make(chan InstallationBanDelivery, 4), subscribed: make(chan string, 4)}
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	service, err := New(config, defaultFakeControl(), NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureInstallationBan(bus); err != nil {
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
	hello.GetHello().Capabilities.Features = []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_INSTALLATION_BAN_TICKET, ApiVersion: 1}}
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	first, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if negotiated, _ := installationBanCapabilityFromFeatures(first.GetHello().GetEnabledCapabilities()); !negotiated {
		t.Fatalf("capability not enabled: %v", first.GetHello().GetEnabledCapabilities())
	}
	if nodeID := <-bus.subscribed; nodeID != testNodeID {
		t.Fatalf("subscribed for %s", nodeID)
	}
	acks, naks, terms := make(chan string, 4), make(chan string, 4), make(chan string, 4)
	broken := testInstallationBanCommand(testNodeID, 2)
	broken.NoticeSha256[0] ^= 1
	bus.deliveries <- &installationBanDeliveryStub{command: broken, acks: acks, naks: naks, terms: terms}
	command := testInstallationBanCommand(testNodeID, 3)
	bus.deliveries <- &installationBanDeliveryStub{command: command, acks: acks, naks: naks, terms: terms}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetInstallationBanCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v", response.Payload)
	}
	if dropped := <-terms; dropped != broken.Event.EventId {
		t.Fatalf("terminated %s", dropped)
	}
	select {
	case id := <-acks:
		t.Fatalf("command %s acknowledged before its receipt", id)
	case <-time.After(100 * time.Millisecond):
	}
	receipt := testInstallationBanReceipt(command)
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: 2, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_InstallationBanReceipt{InstallationBanReceipt: receipt},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-acks:
		if id != command.Event.EventId {
			t.Fatalf("acknowledged %s", id)
		}
	case <-ctx.Done():
		t.Fatal("command was not acknowledged after its receipt")
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	if len(bus.published) != 1 || !proto.Equal(bus.published[0], receipt) {
		t.Fatalf("published = %v", bus.published)
	}
}
