package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sshaccess"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sshAccessBusStub struct {
	mu        sync.Mutex
	current   *agentv1.SSHAccessCommand
	published chan *agentv1.SSHAccessReceipt
}

type sshAccessSubscriptionStub struct {
	replay chan *agentv1.SSHAccessCommand
}

func (bus *sshAccessBusStub) SubscribeSSHAccess(context.Context, string) (SSHAccessSubscription, error) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	replay := make(chan *agentv1.SSHAccessCommand, 1)
	if bus.current != nil {
		replay <- bus.current
	}
	return &sshAccessSubscriptionStub{replay: replay}, nil
}

func (subscription *sshAccessSubscriptionStub) Next(ctx context.Context) (*agentv1.SSHAccessCommand, error) {
	select {
	case command := <-subscription.replay:
		return proto.Clone(command).(*agentv1.SSHAccessCommand), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (*sshAccessSubscriptionStub) Close() error { return nil }

func (bus *sshAccessBusStub) PublishSSHAccessReceipt(_ context.Context, _ string, receipt *agentv1.SSHAccessReceipt) (SSHAccessPublication, error) {
	bus.published <- receipt
	return SSHAccessPublication{Stream: sshaccess.ReceiptStream, Sequence: 1}, nil
}

func testSSHAccessEvent() *commonv1.EventMetadata {
	return &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()}
}

func testSSHAccessApply(revision uint64) *agentv1.SSHAccessCommand {
	return &agentv1.SSHAccessCommand{Event: testSSHAccessEvent(), NodeId: testNodeID, Revision: revision,
		Operation: sshaccess.OperationApply, Enabled: true, SshPort: 22, Cidrs: []string{"192.0.2.10/32", "2001:db8::/48"}}
}

func testSSHAccessReceipt(command *agentv1.SSHAccessCommand, state, code string) *agentv1.SSHAccessReceipt {
	return &agentv1.SSHAccessReceipt{Event: testSSHAccessEvent(), NodeId: command.NodeId, CommandEventId: command.Event.EventId,
		Revision: command.Revision, State: state, FailureCode: code}
}

func TestValidateSSHAccessCommandAndReceipt(t *testing.T) {
	apply := testSSHAccessApply(3)
	confirm := &agentv1.SSHAccessCommand{Event: testSSHAccessEvent(), NodeId: testNodeID, Revision: 3, Operation: sshaccess.OperationConfirm}
	disable := &agentv1.SSHAccessCommand{Event: testSSHAccessEvent(), NodeId: testNodeID, Revision: 4, Operation: sshaccess.OperationApply, SshPort: 22}
	for _, valid := range []*agentv1.SSHAccessCommand{apply, confirm, disable} {
		if err := validateSSHAccessCommand(valid, testNodeID); err != nil {
			t.Fatalf("valid %s rejected: %v", valid.Operation, err)
		}
	}
	for name, mutate := range map[string]func(*agentv1.SSHAccessCommand){
		"node":            func(value *agentv1.SSHAccessCommand) { value.NodeId = uuid.NewString() },
		"revision":        func(value *agentv1.SSHAccessCommand) { value.Revision = 0 },
		"operation":       func(value *agentv1.SSHAccessCommand) { value.Operation = "drop" },
		"port":            func(value *agentv1.SSHAccessCommand) { value.SshPort = 70000 },
		"no networks":     func(value *agentv1.SSHAccessCommand) { value.Cidrs = nil },
		"unmasked":        func(value *agentv1.SSHAccessCommand) { value.Cidrs = []string{"192.0.2.10/24"} },
		"not a network":   func(value *agentv1.SSHAccessCommand) { value.Cidrs = []string{"example.com"} },
		"confirm + rules": func(value *agentv1.SSHAccessCommand) { value.Operation = sshaccess.OperationConfirm },
		"no event":        func(value *agentv1.SSHAccessCommand) { value.Event = nil },
	} {
		changed := proto.Clone(apply).(*agentv1.SSHAccessCommand)
		mutate(changed)
		if err := validateSSHAccessCommand(changed, testNodeID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	for _, valid := range []*agentv1.SSHAccessReceipt{
		testSSHAccessReceipt(apply, sshaccess.StateApplied, ""),
		testSSHAccessReceipt(apply, sshaccess.StateConfirmed, ""),
		testSSHAccessReceipt(apply, sshaccess.StateFailed, "nft_check_failed"),
		// the rollback timer reports without a command
		{Event: testSSHAccessEvent(), NodeId: testNodeID, Revision: 3, State: sshaccess.StateReverted, FailureCode: sshaccess.FailureConfirmationTimeout},
	} {
		if err := validateSSHAccessReceipt(valid, testNodeID); err != nil {
			t.Fatalf("valid %s rejected: %v", valid.State, err)
		}
	}
	for name, receipt := range map[string]*agentv1.SSHAccessReceipt{
		"failed no code":   testSSHAccessReceipt(apply, sshaccess.StateFailed, ""),
		"applied + code":   testSSHAccessReceipt(apply, sshaccess.StateApplied, "x"),
		"unknown state":    testSSHAccessReceipt(apply, "done", ""),
		"bad code":         testSSHAccessReceipt(apply, sshaccess.StateFailed, "Bad Code"),
		"other node":       {Event: testSSHAccessEvent(), NodeId: uuid.NewString(), Revision: 3, State: sshaccess.StateApplied},
		"bad command id":   {Event: testSSHAccessEvent(), NodeId: testNodeID, CommandEventId: "x", Revision: 3, State: sshaccess.StateApplied},
		"revision missing": {Event: testSSHAccessEvent(), NodeId: testNodeID, State: sshaccess.StateApplied},
	} {
		if err := validateSSHAccessReceipt(receipt, testNodeID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	unsupported := notSupportedSSHAccessReceipt(apply, time.Now())
	if err := validateSSHAccessReceipt(unsupported, testNodeID); err != nil || unsupported.FailureCode != sshaccess.FailureNotSupported {
		t.Fatalf("not_supported receipt = %v, %v", unsupported, err)
	}
}

// The wire numbers are fixed:
// ConnectRequest 29, ConnectResponse 32, CapabilityName 78. Changing them
// breaks deployed agents.
func TestSSHAccessWireNumbersAreFixed(t *testing.T) {
	if agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS != 78 {
		t.Fatalf("SSH_ACCESS = %d", agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS)
	}
	for message, want := range map[protoreflect.MessageDescriptor]protoreflect.FieldNumber{
		(&agentv1.ConnectRequest{}).ProtoReflect().Descriptor():  29,
		(&agentv1.ConnectResponse{}).ProtoReflect().Descriptor(): 32,
	} {
		field := message.Fields().ByName(map[bool]protoreflect.Name{true: "ssh_access_receipt", false: "ssh_access_command"}[want == 29])
		if field == nil || field.Number() != want || field.ContainingOneof() == nil {
			t.Fatalf("%s ssh access field = %v", message.FullName(), field)
		}
	}
	// An older peer drops the new oneof member as unknown fields, so a node
	// without SSH_ACCESS never sees a command it cannot parse.
	encoded, err := proto.Marshal(&agentv1.ConnectResponse{Payload: &agentv1.ConnectResponse_SshAccessCommand{SshAccessCommand: testSSHAccessApply(1)}})
	if err != nil {
		t.Fatal(err)
	}
	decoded := &agentv1.ConnectResponse{}
	if err := proto.Unmarshal(encoded, decoded); err != nil || decoded.GetSshAccessCommand().GetRevision() != 1 {
		t.Fatalf("round trip = %v, %v", decoded, err)
	}
}

func connectSSHAccessSession(t *testing.T, bus SSHAccessBus, features []*agentv1.Capability) (agentv1.AgentGatewayService_ConnectClient, context.Context, *agentv1.GatewayHello) {
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
	if err := service.ConfigureSSHAccess(bus); err != nil {
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

func sendSSHAccessReceiptRequest(t *testing.T, stream agentv1.AgentGatewayService_ConnectClient, sequence uint64, receipt *agentv1.SSHAccessReceipt) {
	t.Helper()
	if err := stream.Send(&agentv1.ConnectRequest{
		Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_SshAccessReceipt{SshAccessReceipt: receipt},
	}); err != nil {
		t.Fatal(err)
	}
}

func awaitSSHAccessReceipt(t *testing.T, bus *sshAccessBusStub, ctx context.Context) *agentv1.SSHAccessReceipt {
	t.Helper()
	select {
	case receipt := <-bus.published:
		return receipt
	case <-ctx.Done():
		t.Fatal("no SSH access receipt published")
		return nil
	}
}

// The newest command is delivered on connect; the node's answer and a later
// unprompted rollback report are both relayed; a receipt for another node
// ends the session.
func TestSSHAccessSessionDeliversCommandAndRelaysReceipts(t *testing.T) {
	command := testSSHAccessApply(5)
	bus := &sshAccessBusStub{current: command, published: make(chan *agentv1.SSHAccessReceipt, 4)}
	stream, ctx, hello := connectSSHAccessSession(t, bus,
		[]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS, ApiVersion: 1}})
	enabled := false
	for _, capability := range hello.GetEnabledCapabilities() {
		enabled = enabled || capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_SSH_ACCESS
	}
	if !enabled {
		t.Fatal("gateway did not enable SSH_ACCESS v1")
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if delivered := response.GetSshAccessCommand(); delivered == nil || !proto.Equal(delivered, command) {
		t.Fatalf("delivered %v", response.Payload)
	}
	applied := testSSHAccessReceipt(command, sshaccess.StateApplied, "")
	sendSSHAccessReceiptRequest(t, stream, 2, applied)
	if published := awaitSSHAccessReceipt(t, bus, ctx); !proto.Equal(published, applied) {
		t.Fatalf("published %v", published)
	}
	reverted := &agentv1.SSHAccessReceipt{Event: testSSHAccessEvent(), NodeId: testNodeID, Revision: 5,
		State: sshaccess.StateReverted, FailureCode: sshaccess.FailureConfirmationTimeout}
	sendSSHAccessReceiptRequest(t, stream, 3, reverted)
	if published := awaitSSHAccessReceipt(t, bus, ctx); !proto.Equal(published, reverted) {
		t.Fatalf("published %v", published)
	}
	other := proto.Clone(applied).(*agentv1.SSHAccessReceipt)
	other.NodeId, other.Event = uuid.NewString(), testSSHAccessEvent()
	sendSSHAccessReceiptRequest(t, stream, 4, other)
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "SSH access receipt is invalid") {
		t.Fatalf("foreign receipt: %v", err)
	}
}

func TestSSHAccessUnsupportedNodeIsAnsweredNotSupported(t *testing.T) {
	bus := &sshAccessBusStub{current: testSSHAccessApply(2), published: make(chan *agentv1.SSHAccessReceipt, 4)}
	_, ctx, _ := connectSSHAccessSession(t, bus, nil)
	receipt := awaitSSHAccessReceipt(t, bus, ctx)
	if receipt.State != sshaccess.StateFailed || receipt.FailureCode != sshaccess.FailureNotSupported || receipt.Revision != 2 {
		t.Fatalf("receipt = %v", receipt)
	}
}

func TestSSHAccessReceiptWithoutCapabilityIsRefused(t *testing.T) {
	bus := &sshAccessBusStub{published: make(chan *agentv1.SSHAccessReceipt, 4)}
	stream, _, _ := connectSSHAccessSession(t, bus, nil)
	sendSSHAccessReceiptRequest(t, stream, 2, testSSHAccessReceipt(testSSHAccessApply(1), sshaccess.StateApplied, ""))
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "not negotiated") {
		t.Fatalf("receipt without capability: %v", err)
	}
}
