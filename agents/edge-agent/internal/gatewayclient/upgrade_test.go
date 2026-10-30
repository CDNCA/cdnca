package gatewayclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/updater"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateUpgradeCommandEnvelopeBindsExactDigest(t *testing.T) {
	wire := []byte(`{"command":"exact"}`)
	digest := sha256.Sum256(wire)
	command := &agentv1.UpgradeCommand{Command: wire, CommandSha256: digest[:]}
	if got, err := validateUpgradeCommandEnvelope(command); err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("validateUpgradeCommandEnvelope() = (%q, %v)", got, err)
	}
	command.CommandSha256[0] ^= 0xff
	if _, err := validateUpgradeCommandEnvelope(command); err == nil {
		t.Fatal("tampered command digest was accepted")
	}
}

func TestValidateUpgradeStatusAckBindsOutboxIdentity(t *testing.T) {
	status := upgradeQueuedStatus{
		StatusID: "00000000-0000-4000-8000-000000000021", CommandID: "00000000-0000-4000-8000-000000000011",
		Revision: 3, Digest: sha256.Sum256([]byte("status")),
	}
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId: status.StatusID, CommandId: status.CommandID, StatusRevision: status.Revision,
		StatusSha256: status.Digest[:], PersistedTime: timestamppb.New(time.Unix(100, 0).UTC()),
	}
	if err := validateUpgradeStatusAck(ack, status); err != nil {
		t.Fatal(err)
	}
	ack.CommandId = "00000000-0000-4000-8000-000000000099"
	if err := validateUpgradeStatusAck(ack, status); err == nil {
		t.Fatal("cross-command acknowledgement was accepted")
	}
}

func TestValidateUpgradeStatusAckPubAckNegotiation(t *testing.T) {
	status := upgradeQueuedStatus{
		StatusID: "00000000-0000-4000-8000-000000000021", CommandID: "00000000-0000-4000-8000-000000000011",
		Revision: 3, Digest: sha256.Sum256([]byte("status")),
	}
	ack := func(stream string, sequence uint64) *agentv1.UpgradeStatusAck {
		return &agentv1.UpgradeStatusAck{
			StatusEventId: status.StatusID, CommandId: status.CommandID, StatusRevision: status.Revision,
			StatusSha256: status.Digest[:], PersistedTime: timestamppb.New(time.Unix(100, 0).UTC()),
			PublishedStream: stream, PublishedSequence: sequence,
		}
	}
	for _, test := range []struct {
		name     string
		ack      *agentv1.UpgradeStatusAck
		accepted bool
	}{
		{name: "legacy", ack: ack("", 0), accepted: true},
		{name: "legacy stream only", ack: ack("AGENT_DEPLOYMENT_STATUS", 0)},
		{name: "legacy sequence only", ack: ack("", 41)},
		{name: "legacy populated", ack: ack("AGENT_DEPLOYMENT_STATUS", 41)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateUpgradeStatusAck(test.ack, status, false)
			if test.accepted && err != nil {
				t.Fatalf("unnegotiated legacy acknowledgement rejected: %v", err)
			}
			if !test.accepted && err == nil {
				t.Fatal("unnegotiated publication acknowledgement accepted")
			}
		})
	}
	for _, test := range []struct {
		name     string
		ack      *agentv1.UpgradeStatusAck
		accepted bool
	}{
		{name: "missing", ack: ack("", 0)},
		{name: "wrong stream", ack: ack("OTHER", 41)},
		{name: "zero sequence", ack: ack("AGENT_DEPLOYMENT_STATUS", 0)},
		{name: "exact", ack: ack("AGENT_DEPLOYMENT_STATUS", 41), accepted: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateUpgradeStatusAck(test.ack, status, true)
			if test.accepted && err != nil {
				t.Fatalf("exact negotiated PubAck rejected: %v", err)
			}
			if !test.accepted && err == nil {
				t.Fatal("invalid negotiated PubAck accepted")
			}
		})
	}
}

func TestUpgradeStatusAckReceiptUsesDeterministicExactAckAndRejectsUnknown(t *testing.T) {
	statusWire := []byte("exact status")
	statusDigest := sha256.Sum256(statusWire)
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId: "00000000-0000-4000-8000-000000000021",
		CommandId:     "00000000-0000-4000-8000-000000000011", StatusRevision: 3,
		StatusSha256: statusDigest[:], PersistedTime: timestamppb.New(time.Unix(100, 123).UTC()),
		PublishedStream: edgeUpgradeStatusStream, PublishedSequence: 41,
	}
	acknowledgement, receipt, err := upgradeStatusAcknowledgement(ack)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := (proto.MarshalOptions{Deterministic: true}).Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	exactDigest := sha256.Sum256(exact)
	if !bytes.Equal(acknowledgement.Encoded, exact) || acknowledgement.SHA256 != hex.EncodeToString(exactDigest[:]) ||
		!bytes.Equal(receipt.AckSha256, exactDigest[:]) || receipt.StatusEventId != ack.StatusEventId ||
		receipt.CommandId != ack.CommandId || receipt.StatusRevision != ack.StatusRevision ||
		!bytes.Equal(receipt.StatusSha256, ack.StatusSha256) || receipt.PublishedStream != ack.PublishedStream ||
		receipt.PublishedSequence != ack.PublishedSequence || !receipt.PersistedTime.AsTime().Equal(ack.PersistedTime.AsTime()) {
		t.Fatalf("exact receipt mismatch: acknowledgement=%#v receipt=%#v", acknowledgement, receipt)
	}

	unknown := proto.Clone(ack).(*agentv1.UpgradeStatusAck)
	unknown.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
	if _, _, err := upgradeStatusAcknowledgement(unknown); err == nil {
		t.Fatal("UpgradeStatusAck with unknown fields was hashed and accepted")
	}
}

func TestUpgradeStatusAckReceiptValidationIsExactAndFailClosed(t *testing.T) {
	statusDigest := sha256.Sum256([]byte("status"))
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId: "00000000-0000-4000-8000-000000000021",
		CommandId:     "00000000-0000-4000-8000-000000000011", StatusRevision: 3,
		StatusSha256: statusDigest[:], PersistedTime: timestamppb.New(time.Unix(100, 0).UTC()),
		PublishedStream: edgeUpgradeStatusStream, PublishedSequence: 41,
	}
	acknowledgement, receipt, err := upgradeStatusAcknowledgement(ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateUpgradeStatusAckReceipt(receipt, acknowledgement); err != nil {
		t.Fatalf("exact receipt rejected: %v", err)
	}
	for _, mutate := range []func(*agentv1.UpgradeStatusAckReceipt){
		func(value *agentv1.UpgradeStatusAckReceipt) { value.CommandId = "00000000-0000-4000-8000-000000000099" },
		func(value *agentv1.UpgradeStatusAckReceipt) { value.StatusRevision++ },
		func(value *agentv1.UpgradeStatusAckReceipt) { value.PublishedSequence++ },
		func(value *agentv1.UpgradeStatusAckReceipt) { value.AckSha256[0] ^= 0xff },
	} {
		changed := proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)
		mutate(changed)
		if err := validateUpgradeStatusAckReceipt(changed, acknowledgement); err == nil {
			t.Fatalf("changed receipt accepted: %#v", changed)
		}
	}
	unknown := proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)
	unknown.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
	if err := validateUpgradeStatusAckReceipt(unknown, acknowledgement); err == nil {
		t.Fatal("receipt with unknown fields was accepted")
	}
}

func TestEdgeUpgradePubAckCapabilityRollingCompatibility(t *testing.T) {
	for _, test := range []struct {
		name       string
		newAgent   bool
		newGateway bool
		wantPubAck bool
	}{
		{name: "old agent old gateway"},
		{name: "new agent old gateway", newAgent: true},
		{name: "old agent new gateway", newGateway: true},
		{name: "new agent new gateway", newAgent: true, newGateway: true, wantPubAck: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			offered := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1,
			}}}
			if test.newAgent {
				ensureEdgeUpgradeCapability(offered)
			}
			hello := &agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
				Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1,
			}}}
			if test.newAgent && test.newGateway {
				hello.EnabledCapabilities = offered.Features
			}
			upgrade, pubAck, err := gatewayHelloEdgeUpgradeCapabilities(hello)
			if err != nil || !upgrade || pubAck != test.wantPubAck {
				t.Fatalf("negotiation = (upgrade=%t puback=%t err=%v), want (true,%t,nil)",
					upgrade, pubAck, err, test.wantPubAck)
			}
		})
	}

	for _, features := range [][]*agentv1.Capability{
		{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 1}},
		{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 2},
		},
		{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK, ApiVersion: 1},
		},
	} {
		hello := &agentv1.GatewayHello{EnabledCapabilities: features}
		if _, _, err := gatewayHelloEdgeUpgradeCapabilities(hello); err == nil {
			t.Fatalf("invalid Gateway capability set accepted: %+v", features)
		}
	}
}

type v2CapabilityUpgradeRuntime struct{ *upgradeOrderingRuntime }

func (*v2CapabilityUpgradeRuntime) InstallerProtocolVersion() int { return updater.InstallerProtocolV2 }

type receiptCapabilityUpgradeRuntime struct{ *upgradeOrderingRuntime }

func (*receiptCapabilityUpgradeRuntime) PendingStatusAcknowledgements(context.Context) ([]updater.UpgradeStatusAcknowledgement, error) {
	return nil, nil
}

func (*receiptCapabilityUpgradeRuntime) PersistStatusAcknowledgement(context.Context, updater.UpgradeStatusAcknowledgement) (bool, error) {
	return true, nil
}

func (*receiptCapabilityUpgradeRuntime) ConfirmStatusAcknowledgement(context.Context, updater.UpgradeStatusAcknowledgement) (bool, error) {
	return true, nil
}

type fullCapabilityUpgradeRuntime struct {
	*receiptCapabilityUpgradeRuntime
}

func (*fullCapabilityUpgradeRuntime) InstallerProtocolVersion() int {
	return updater.InstallerProtocolV2
}

type wrappedConcreteUpgradeRuntime struct{ *updater.UpgradeRuntime }

type capabilityInstallerV2 struct{}

func (capabilityInstallerV2) ProtocolVersion() int { return updater.InstallerProtocolV2 }
func (capabilityInstallerV2) MarkInstalling(context.Context, updater.PreparedInstall) (updater.InstallerTransaction, error) {
	return updater.InstallerTransaction{}, nil
}
func (capabilityInstallerV2) Current(context.Context) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, nil
}
func (capabilityInstallerV2) Install(context.Context, updater.InstallRequest) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, nil
}
func (capabilityInstallerV2) Query(context.Context, string) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, nil
}
func (capabilityInstallerV2) Rollback(context.Context, updater.RollbackRequest) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, nil
}
func (capabilityInstallerV2) Prepare(context.Context, updater.InstallRequest) (updater.PreparedInstall, error) {
	return updater.PreparedInstall{}, nil
}
func (capabilityInstallerV2) Inspect(context.Context, string) (updater.InstallerTransaction, error) {
	return updater.InstallerTransaction{}, nil
}
func (capabilityInstallerV2) Activate(context.Context, updater.PreparedInstall) (updater.ActivationReceipt, error) {
	return updater.ActivationReceipt{}, nil
}
func (capabilityInstallerV2) Abort(context.Context, updater.PreparedInstall) (updater.InstallerTransaction, error) {
	return updater.InstallerTransaction{}, nil
}

type capabilityDownloader struct{}

func (capabilityDownloader) Download(context.Context, updater.DownloadRequest, io.Writer) error {
	return nil
}

type capabilityProbe struct{}

func (capabilityProbe) Check(context.Context, updater.ActivationReceipt, []string) error { return nil }

func newConcreteCapabilityUpgradeRuntime(t *testing.T) (*updater.UpgradeRuntime, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	root := secureTempDir(t)
	keys := map[string]ed25519.PublicKey{"capability-key": publicKey}
	managerConfig := updater.DefaultConfig(
		filepath.Join(root, "manager"), "1.0.0", keys, keys,
		capabilityDownloader{}, capabilityInstallerV2{}, capabilityProbe{},
	)
	managerConfig.NodeID = "node-capability-test"
	managerConfig.DiskReserveBytes = 0
	manager, err := updater.NewManager(managerConfig)
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(root, "runtime")
	store, err := updater.NewDurableUpgradeStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := updater.NewUpgradeRuntime(updater.UpgradeRuntimeConfig{
		Store: store, Manager: manager,
		Options: updater.UpgradeExecutionConsumerOptions{
			ExpectedInstallationID: "installation-capability-test", ExpectedNodeID: "node-capability-test",
			ControlKeys: keys, EdgeKeys: keys,
		},
	})
	if err != nil || !runtime.Ready() {
		t.Fatalf("concrete upgrade runtime = (%#v, %v)", runtime, err)
	}
	return runtime, storeRoot
}

func newUpgradeCapabilityClient(t *testing.T, runtime UpgradeRuntime, wire bool) *Client {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"capability-client-key": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	root := secureTempDir(t)
	config := testClientConfig(filepath.Join(root, "journal"))
	options := make([]ClientOption, 0, 1)
	if wire {
		options = append(options, WithUpgradeRuntime(runtime))
	}
	client, err := New(config, &failingDialer{}, noOpManager{}, trust, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func extendedUpgradeCapabilities(capabilities *agentv1.AgentCapabilities) (bool, bool) {
	return hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT),
		hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE)
}

func TestAgentHelloDerivesExtendedUpgradeCapabilitiesFromCurrentConcreteRuntime(t *testing.T) {
	actual, _ := newConcreteCapabilityUpgradeRuntime(t)
	var typedNil *updater.UpgradeRuntime
	client := newUpgradeCapabilityClient(t, nil, false)
	for _, test := range []struct {
		name    string
		runtime UpgradeRuntime
		want    bool
	}{
		{name: "concrete", runtime: actual, want: true},
		{name: "typed nil", runtime: typedNil},
		{name: "wrapped concrete", runtime: &wrappedConcreteUpgradeRuntime{actual}},
		{name: "fake", runtime: &fullCapabilityUpgradeRuntime{&receiptCapabilityUpgradeRuntime{newUpgradeOrderingRuntime()}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client.upgrades = test.runtime
			hello, err := client.agentHello()
			if err != nil {
				t.Fatal(err)
			}
			receipt, prepareActivate := extendedUpgradeCapabilities(hello.Capabilities)
			if receipt != test.want || prepareActivate != test.want {
				t.Fatalf("extended capabilities = (%t,%t), want (%t,%t)", receipt, prepareActivate, test.want, test.want)
			}
		})
	}
}

func TestAgentHelloDoesNotFreezeConcreteUpgradeCapabilitiesAtWiring(t *testing.T) {
	actual, storeRoot := newConcreteCapabilityUpgradeRuntime(t)
	client := newUpgradeCapabilityClient(t, actual, true)
	if receipt, prepareActivate := extendedUpgradeCapabilities(client.config.Capabilities); receipt || prepareActivate {
		t.Fatalf("New permanently mutated configured capabilities: (%t,%t)", receipt, prepareActivate)
	}
	first, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if receipt, prepareActivate := extendedUpgradeCapabilities(first.Capabilities); !receipt || !prepareActivate {
		t.Fatalf("ready concrete offer = (%t,%t), want (true,true)", receipt, prepareActivate)
	}
	if err := os.Rename(storeRoot, storeRoot+".offline"); err != nil {
		t.Fatal(err)
	}
	if actual.Ready() {
		t.Fatal("concrete runtime remained ready after durable store binding loss")
	}
	second, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if receipt, prepareActivate := extendedUpgradeCapabilities(second.Capabilities); receipt || prepareActivate {
		t.Fatalf("not-ready concrete offer = (%t,%t), want (false,false)", receipt, prepareActivate)
	}
}

type upgradeReadyDriftGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	storeRoot string
	offered   chan *agentv1.AgentHello
}

func (gateway *upgradeReadyDriftGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return err
	}
	hello := proto.Clone(first.GetHello()).(*agentv1.AgentHello)
	receipt, prepareActivate := extendedUpgradeCapabilities(hello.Capabilities)
	if !receipt || !prepareActivate {
		return status.Error(codes.FailedPrecondition, "concrete runtime did not offer extended upgrade capabilities")
	}
	gateway.offered <- hello
	if err := os.Rename(gateway.storeRoot, gateway.storeRoot+".offline"); err != nil {
		return err
	}
	enabled := make([]*agentv1.Capability, 0, 4)
	for _, capability := range hello.Capabilities.Features {
		if capability != nil && (capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT ||
			capability.Name == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE) {
			enabled = append(enabled, proto.Clone(capability).(*agentv1.Capability))
		}
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(50 * time.Millisecond), OfflineAfterDuration: durationpb.New(5 * time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled,
		}},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func TestRunSessionBindsNegotiationToSentHelloAcrossReadyLoss(t *testing.T) {
	actual, storeRoot := newConcreteCapabilityUpgradeRuntime(t)
	client := newUpgradeCapabilityClient(t, actual, true)
	gateway := &upgradeReadyDriftGateway{storeRoot: storeRoot, offered: make(chan *agentv1.AgentHello, 1)}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	established, runErr := client.runSession(context.Background(), connection.Client())
	if !established || runErr == nil || errors.Is(runErr, ErrInvalidMessage) {
		t.Fatalf("session after post-Hello Ready loss = (established=%t, err=%v), want established local failure", established, runErr)
	}
	select {
	case sent := <-gateway.offered:
		if receipt, prepareActivate := extendedUpgradeCapabilities(sent.Capabilities); !receipt || !prepareActivate {
			t.Fatalf("sent offer = (%t,%t), want (true,true)", receipt, prepareActivate)
		}
	default:
		t.Fatal("Gateway did not observe the sent Hello snapshot")
	}
	next, err := client.agentHello()
	if err != nil {
		t.Fatal(err)
	}
	if receipt, prepareActivate := extendedUpgradeCapabilities(next.Capabilities); receipt || prepareActivate {
		t.Fatalf("next offer after Ready loss = (%t,%t), want (false,false)", receipt, prepareActivate)
	}
}

var errUpgradeNegotiationProbeRecover = errors.New("upgrade negotiation probe recovered")

type upgradeNegotiationProbeRuntime struct {
	mu         sync.Mutex
	recoveries int
}

func (*upgradeNegotiationProbeRuntime) Ready() bool { return true }
func (runtime *upgradeNegotiationProbeRuntime) Recover(context.Context) error {
	runtime.mu.Lock()
	runtime.recoveries++
	runtime.mu.Unlock()
	return errUpgradeNegotiationProbeRecover
}
func (*upgradeNegotiationProbeRuntime) AcceptCommand(context.Context, []byte) error { return nil }
func (*upgradeNegotiationProbeRuntime) PendingStatuses(context.Context) ([]updater.QueuedUpgradeStatus, error) {
	return nil, nil
}
func (*upgradeNegotiationProbeRuntime) AcknowledgeStatus(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (runtime *upgradeNegotiationProbeRuntime) recoveryCount() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.recoveries
}

type upgradeNegotiationGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	enabled []*agentv1.Capability
	offered chan *agentv1.AgentHello
}

func (gateway *upgradeNegotiationGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return err
	}
	gateway.offered <- proto.Clone(first.GetHello()).(*agentv1.AgentHello)
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "upgrade-negotiation-test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(50 * time.Millisecond), OfflineAfterDuration: durationpb.New(5 * time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: gateway.enabled,
		}},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

type helloMutationAgentGatewayClient struct {
	agentv1.AgentGatewayServiceClient
	mutate func(*agentv1.AgentHello)
}

func (client *helloMutationAgentGatewayClient) Connect(ctx context.Context, options ...grpc.CallOption) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], error) {
	stream, err := client.AgentGatewayServiceClient.Connect(ctx, options...)
	if err != nil {
		return nil, err
	}
	return &helloMutationStream{BidiStreamingClient: stream, mutate: client.mutate}, nil
}

type helloMutationStream struct {
	grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse]
	mutate func(*agentv1.AgentHello)
}

func (stream *helloMutationStream) Send(request *agentv1.ConnectRequest) error {
	if hello := request.GetHello(); hello != nil && stream.mutate != nil {
		stream.mutate(hello)
	}
	return stream.BidiStreamingClient.Send(request)
}

func runUpgradeNegotiationSession(t *testing.T, ctx context.Context, client *Client, enabled []*agentv1.Capability,
	mutate func(*agentv1.AgentHello),
) (bool, error, *agentv1.AgentHello) {
	t.Helper()
	gateway := &upgradeNegotiationGateway{enabled: enabled, offered: make(chan *agentv1.AgentHello, 1)}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	gatewayClient := agentv1.AgentGatewayServiceClient(connection.Client())
	if mutate != nil {
		gatewayClient = &helloMutationAgentGatewayClient{AgentGatewayServiceClient: gatewayClient, mutate: mutate}
	}
	established, runErr := client.runSession(ctx, gatewayClient)
	select {
	case offered := <-gateway.offered:
		return established, runErr, offered
	default:
		t.Fatal("Gateway did not observe the sent Hello")
		return false, nil, nil
	}
}

func TestRunSessionBindsBaseUpgradeCapabilitiesToSentHello(t *testing.T) {
	capability := func(name agentv1.CapabilityName) *agentv1.Capability {
		return &agentv1.Capability{Name: name, ApiVersion: 1}
	}
	for _, test := range []struct {
		name             string
		enabled          []*agentv1.Capability
		mutate           func(*agentv1.AgentHello)
		wantOfferUpgrade bool
		wantOfferPubAck  bool
		wantInvalid      bool
	}{
		{
			name:        "nil offer",
			enabled:     []*agentv1.Capability{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE)},
			mutate:      func(hello *agentv1.AgentHello) { hello.Capabilities = nil },
			wantInvalid: true,
		},
		{
			name:    "unoffered base",
			enabled: []*agentv1.Capability{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE)},
			mutate: func(hello *agentv1.AgentHello) {
				hello.Capabilities.Features = removeCapability(hello.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE)
			},
			wantOfferPubAck: true,
			wantInvalid:     true,
		},
		{
			name: "unoffered puback",
			enabled: []*agentv1.Capability{
				capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE),
				capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK),
			},
			mutate: func(hello *agentv1.AgentHello) {
				hello.Capabilities.Features = removeCapability(hello.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK)
			},
			wantOfferUpgrade: true,
			wantInvalid:      true,
		},
		{
			name:    "offered base",
			enabled: []*agentv1.Capability{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE)},
			mutate: func(hello *agentv1.AgentHello) {
				hello.Capabilities.Features = removeCapability(hello.Capabilities.Features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK)
			},
			wantOfferUpgrade: true,
		},
		{
			name: "offered base and puback",
			enabled: []*agentv1.Capability{
				capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE),
				capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK),
			},
			wantOfferUpgrade: true,
			wantOfferPubAck:  true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := &upgradeNegotiationProbeRuntime{}
			client := newUpgradeCapabilityClient(t, runtime, true)
			established, runErr, offered := runUpgradeNegotiationSession(t, context.Background(), client, test.enabled, test.mutate)
			if got := hasCapability(offered.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE); got != test.wantOfferUpgrade {
				t.Fatalf("sent edge upgrade offer = %t, want %t", got, test.wantOfferUpgrade)
			}
			if got := hasCapability(offered.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK); got != test.wantOfferPubAck {
				t.Fatalf("sent PubAck offer = %t, want %t", got, test.wantOfferPubAck)
			}
			if test.wantInvalid {
				if established || !errors.Is(runErr, ErrInvalidMessage) || runtime.recoveryCount() != 0 {
					t.Fatalf("invalid negotiation = (established=%t err=%v recoveries=%d), want (false, ErrInvalidMessage, 0)",
						established, runErr, runtime.recoveryCount())
				}
				return
			}
			if !established || !errors.Is(runErr, errUpgradeNegotiationProbeRecover) || runtime.recoveryCount() != 1 {
				t.Fatalf("valid negotiation = (established=%t err=%v recoveries=%d), want (true, probe error, 1)",
					established, runErr, runtime.recoveryCount())
			}
		})
	}
}

func TestRunSessionNilUpgradeRuntimeDoesNotScheduleInitialRecovery(t *testing.T) {
	const helper = "CDNCA_NIL_UPGRADE_RUNTIME_HELPER"
	if os.Getenv(helper) != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunSessionNilUpgradeRuntimeDoesNotScheduleInitialRecovery$", "-test.count=1")
		command.Env = append(os.Environ(), helper+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("nil-runtime session subprocess failed: %v\n%s", err, output)
		}
		return
	}
	client := newUpgradeCapabilityClient(t, nil, false)
	enabled := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	established, runErr, offered := runUpgradeNegotiationSession(t, ctx, client, enabled, func(hello *agentv1.AgentHello) {
		hello.Capabilities.Features = append(hello.Capabilities.Features, proto.Clone(enabled[0]).(*agentv1.Capability))
	})
	if !hasCapability(offered.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) {
		t.Fatal("test did not send the defensive edge upgrade offer")
	}
	if !established || runErr == nil || errors.Is(runErr, ErrInvalidMessage) {
		t.Fatalf("nil-runtime defensive session = (established=%t err=%v), want established local shutdown without panic", established, runErr)
	}
}

func TestEdgeUpgradeCapabilitiesDeriveCap24AndCap25FromRuntime(t *testing.T) {
	base := func() *agentv1.AgentCapabilities {
		return &agentv1.AgentCapabilities{Features: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT, ApiVersion: 99},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE, ApiVersion: 99},
		}}
	}
	for _, test := range []struct {
		name        string
		runtime     UpgradeRuntime
		wantReceipt bool
		wantV2      bool
	}{
		{name: "base", runtime: newUpgradeOrderingRuntime()},
		{name: "spoofed prepare activate", runtime: &v2CapabilityUpgradeRuntime{newUpgradeOrderingRuntime()}},
		{name: "spoofed ack receipt", runtime: &receiptCapabilityUpgradeRuntime{newUpgradeOrderingRuntime()}},
		{name: "spoofed full", runtime: &fullCapabilityUpgradeRuntime{&receiptCapabilityUpgradeRuntime{newUpgradeOrderingRuntime()}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			capabilities := base()
			ensureEdgeUpgradeCapabilities(capabilities, test.runtime)
			if !hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE) ||
				!hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK) ||
				hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT) != test.wantReceipt ||
				hasCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE) != test.wantV2 {
				t.Fatalf("derived capabilities = %#v", capabilities.Features)
			}
		})
	}
}

func TestGatewayUpgradeExtendedCapabilityDependenciesFailClosed(t *testing.T) {
	capability := func(name agentv1.CapabilityName) *agentv1.Capability {
		return &agentv1.Capability{Name: name, ApiVersion: 1}
	}
	offered := &agentv1.AgentCapabilities{Features: []*agentv1.Capability{
		capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE),
		capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK),
		capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT),
		capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE),
	}}
	valid := [][]*agentv1.Capability{
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE)},
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE), capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE)},
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE), capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK), capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT)},
		offered.Features,
	}
	for _, features := range valid {
		hello := &agentv1.GatewayHello{EnabledCapabilities: features}
		upgrade, pubAck, receipt, prepareActivate, err := gatewayHelloEdgeUpgradeExtendedCapabilities(hello, offered)
		if err != nil || !upgrade || receipt != hasGatewayCapability(features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT) ||
			prepareActivate != hasGatewayCapability(features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE) ||
			pubAck != hasGatewayCapability(features, agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_PUBACK) {
			t.Fatalf("valid negotiation = (%t,%t,%t,%t,%v) for %#v", upgrade, pubAck, receipt, prepareActivate, err, features)
		}
	}
	invalid := [][]*agentv1.Capability{
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT)},
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE), capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT)},
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_PREPARE_ACTIVATE)},
		{capability(agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE), {Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE_STATUS_ACK_RECEIPT, ApiVersion: 2}},
	}
	for _, features := range invalid {
		if _, _, _, _, err := gatewayHelloEdgeUpgradeExtendedCapabilities(&agentv1.GatewayHello{EnabledCapabilities: features}, offered); err == nil {
			t.Fatalf("invalid capability set accepted: %#v", features)
		}
	}
	unoffered := &agentv1.AgentCapabilities{Features: offered.Features[:2]}
	if _, _, _, _, err := gatewayHelloEdgeUpgradeExtendedCapabilities(&agentv1.GatewayHello{EnabledCapabilities: valid[2]}, unoffered); err == nil {
		t.Fatal("Gateway enabled unoffered cap24")
	}
}

func hasGatewayCapability(features []*agentv1.Capability, name agentv1.CapabilityName) bool {
	for _, feature := range features {
		if feature != nil && feature.Name == name && feature.ApiVersion == 1 {
			return true
		}
	}
	return false
}

func TestNegotiatedUpgradePubAckIsValidatedBeforeDurableAcknowledgement(t *testing.T) {
	runtime := newUpgradeOrderingRuntime()
	if err := runtime.AcceptCommand(context.Background(), []byte("command")); err != nil {
		t.Fatal(err)
	}
	client := &Client{upgrades: runtime}
	status := runtime.status
	base := func() *agentv1.UpgradeStatusAck {
		return &agentv1.UpgradeStatusAck{
			StatusEventId: status.Status.StatusID, CommandId: status.Status.CommandID,
			StatusRevision: status.Status.StatusRevision, StatusSha256: mustDecodeHex(t, status.SHA256),
			PersistedTime: timestamppb.Now(),
		}
	}
	for _, publication := range []struct {
		name     string
		stream   string
		sequence uint64
	}{
		{name: "legacy stream only", stream: "AGENT_DEPLOYMENT_STATUS"},
		{name: "legacy sequence only", sequence: 41},
		{name: "legacy populated", stream: "AGENT_DEPLOYMENT_STATUS", sequence: 41},
	} {
		t.Run(publication.name, func(t *testing.T) {
			polluted := base()
			polluted.PublishedStream = publication.stream
			polluted.PublishedSequence = publication.sequence
			if _, err := client.acknowledgeUpgradeStatus(context.Background(), polluted, false); err == nil {
				t.Fatal("unnegotiated publication acknowledgement was durably acknowledged")
			}
			runtime.mu.Lock()
			acked := runtime.acceptedAcked
			runtime.mu.Unlock()
			if acked {
				t.Fatal("outbox compacted after unnegotiated publication acknowledgement")
			}
		})
	}
	if _, err := client.acknowledgeUpgradeStatus(context.Background(), base(), true); err == nil {
		t.Fatal("missing negotiated PubAck was durably acknowledged")
	}
	runtime.mu.Lock()
	ackedBeforePubAck := runtime.acceptedAcked
	runtime.mu.Unlock()
	if ackedBeforePubAck {
		t.Fatal("outbox compacted before PubAck validation")
	}
	exact := base()
	exact.PublishedStream = "AGENT_DEPLOYMENT_STATUS"
	exact.PublishedSequence = 41
	accepted, err := client.acknowledgeUpgradeStatus(context.Background(), exact, true)
	if err != nil || !accepted {
		t.Fatalf("exact PubAck acknowledgement = (%t, %v)", accepted, err)
	}
}

type durableReceiptUpgradeRuntime struct {
	*upgradeOrderingRuntime
	acknowledgement *updater.UpgradeStatusAcknowledgement
	confirmed       bool
}

func (runtime *durableReceiptUpgradeRuntime) PendingStatusAcknowledgements(context.Context) ([]updater.UpgradeStatusAcknowledgement, error) {
	if runtime.acknowledgement == nil || runtime.confirmed {
		return nil, nil
	}
	return []updater.UpgradeStatusAcknowledgement{cloneUpgradeStatusAcknowledgement(*runtime.acknowledgement)}, nil
}

func (runtime *durableReceiptUpgradeRuntime) PersistStatusAcknowledgement(_ context.Context, acknowledgement updater.UpgradeStatusAcknowledgement) (bool, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.acknowledgement != nil && !sameUpgradeStatusAcknowledgement(*runtime.acknowledgement, acknowledgement) {
		return false, errors.New("conflicting exact acknowledgement")
	}
	cloned := cloneUpgradeStatusAcknowledgement(acknowledgement)
	runtime.acknowledgement = &cloned
	runtime.acceptedAcked = true
	return true, nil
}

func (runtime *durableReceiptUpgradeRuntime) ConfirmStatusAcknowledgement(_ context.Context, acknowledgement updater.UpgradeStatusAcknowledgement) (bool, error) {
	if runtime.acknowledgement == nil || !sameUpgradeStatusAcknowledgement(*runtime.acknowledgement, acknowledgement) {
		return false, errors.New("wrong exact acknowledgement confirmation")
	}
	runtime.confirmed = true
	return true, nil
}

func TestClientPersistsAndReplaysUpgradeAckReceiptUntilExactConfirmation(t *testing.T) {
	runtime := &durableReceiptUpgradeRuntime{upgradeOrderingRuntime: newUpgradeOrderingRuntime()}
	if err := runtime.AcceptCommand(context.Background(), []byte("command")); err != nil {
		t.Fatal(err)
	}
	client := &Client{upgrades: runtime}
	status := runtime.status
	ack := &agentv1.UpgradeStatusAck{
		StatusEventId: status.Status.StatusID, CommandId: status.Status.CommandID,
		StatusRevision: status.Status.StatusRevision, StatusSha256: mustDecodeHex(t, status.SHA256),
		PersistedTime:   timestamppb.New(time.Unix(100, 0).UTC()),
		PublishedStream: edgeUpgradeStatusStream, PublishedSequence: 41,
	}
	accepted, receipt, err := client.persistUpgradeStatusAcknowledgement(context.Background(), ack)
	if err != nil || !accepted || receipt == nil || runtime.acknowledgement == nil {
		t.Fatalf("persist receipt = (%t, %#v, %v), durable=%#v", accepted, receipt, err, runtime.acknowledgement)
	}
	pending, err := client.pendingUpgradeStatusAcknowledgements(context.Background())
	if err != nil || len(pending) != 1 || !proto.Equal(pending[0], receipt) {
		t.Fatalf("pending receipt replay = (%#v, %v), want %#v", pending, err, receipt)
	}

	wrong := proto.Clone(receipt).(*agentv1.UpgradeStatusAckReceipt)
	wrong.PublishedSequence++
	if confirmed, err := client.confirmUpgradeStatusAcknowledgement(context.Background(), wrong); err == nil || confirmed {
		t.Fatalf("wrong confirmation = (%t, %v)", confirmed, err)
	}
	pending, err = client.pendingUpgradeStatusAcknowledgements(context.Background())
	if err != nil || len(pending) != 1 || !proto.Equal(pending[0], receipt) {
		t.Fatalf("wrong confirmation changed replay = (%#v, %v)", pending, err)
	}
	confirmed, err := client.confirmUpgradeStatusAcknowledgement(context.Background(), receipt)
	if err != nil || !confirmed {
		t.Fatalf("exact confirmation = (%t, %v)", confirmed, err)
	}
	pending, err = client.pendingUpgradeStatusAcknowledgements(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("confirmed receipt replayed = (%#v, %v)", pending, err)
	}
}

func cloneUpgradeStatusAcknowledgement(value updater.UpgradeStatusAcknowledgement) updater.UpgradeStatusAcknowledgement {
	value.Encoded = append([]byte(nil), value.Encoded...)
	return value
}

func sameUpgradeStatusAcknowledgement(left, right updater.UpgradeStatusAcknowledgement) bool {
	return left.StatusID == right.StatusID && left.CommandID == right.CommandID &&
		left.StatusRevision == right.StatusRevision && left.StatusSHA256 == right.StatusSHA256 &&
		left.PersistedAt.Equal(right.PersistedAt) && left.PublishedStream == right.PublishedStream &&
		left.PublishedSequence == right.PublishedSequence && left.SHA256 == right.SHA256 &&
		bytes.Equal(left.Encoded, right.Encoded)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestUpgradeAcceptedAckIsDurableBeforeRecoveryIsScheduled(t *testing.T) {
	root := secureTempDir(t)
	t.Cleanup(func() { makeTestTreeWritable(root) })
	config := testClientConfig(filepath.Join(root, "journal"))
	ensureEdgeUpgradeCapability(config.Capabilities)
	store, err := newDurableStore(config.JournalDir, config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	overlayStore, err := newOverlayDurableStore(filepath.Join(config.JournalDir, "acme-http01-overlay"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	cacheStore, err := newCacheControlDurableStore(filepath.Join(config.JournalDir, "cache-control"), config.MaxCommandBytes, config.MaxStatusBytes)
	if err != nil {
		t.Fatal(err)
	}
	runtime := newUpgradeOrderingRuntime()
	client := &Client{
		config: config, manager: noOpManager{}, store: store, overlayStore: overlayStore,
		cacheStore: cacheStore, upgrades: runtime, now: time.Now,
	}
	command := []byte(`{"command":"exact"}`)
	commandDigest := sha256.Sum256(command)
	gateway := &upgradeOrderingGateway{
		command:    &agentv1.UpgradeCommand{Command: command, CommandSha256: commandDigest[:]},
		statusSeen: make(chan struct{}), releaseAck: make(chan struct{}),
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	agentv1.RegisterAgentGatewayServiceServer(server, gateway)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	connection, err := (&bufDialer{listener: listener}).Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := client.runSession(ctx, connection.Client())
		done <- runErr
	}()
	select {
	case <-gateway.statusSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted status was not sent")
	}
	if beforeAck, afterAck := runtime.recoveryCounts(); beforeAck != 0 || afterAck != 0 {
		t.Fatalf("recovery before accepted ACK: before=%d after=%d", beforeAck, afterAck)
	}
	close(gateway.releaseAck)
	select {
	case <-runtime.recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("matching accepted ACK did not schedule recovery")
	}
	if beforeAck, afterAck := runtime.recoveryCounts(); beforeAck != 0 || afterAck != 1 {
		t.Fatalf("recovery ordering: before=%d after=%d", beforeAck, afterAck)
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && status.Code(err) != codes.Canceled {
		t.Fatalf("runSession error = %v", err)
	}
}

type upgradeOrderingRuntime struct {
	mu                sync.Mutex
	accepted          bool
	acceptedAcked     bool
	recoveryBeforeAck int
	recoveryAfterAck  int
	recovered         chan struct{}
	status            updater.QueuedUpgradeStatus
	recoverOnce       sync.Once
}

func newUpgradeOrderingRuntime() *upgradeOrderingRuntime {
	status := updater.EdgeUpgradeStatus{
		StatusID: "00000000-0000-4000-8000-000000000021", StatusRevision: 1,
		CommandID: "00000000-0000-4000-8000-000000000011", State: updater.EdgeUpgradeStateAccepted,
	}
	encoded := []byte(`{"state":"accepted"}`)
	return &upgradeOrderingRuntime{
		recovered: make(chan struct{}),
		status:    updater.QueuedUpgradeStatus{Status: status, Encoded: encoded, SHA256: hexDigest(encoded)},
	}
}

func (*upgradeOrderingRuntime) Ready() bool { return true }

func (runtime *upgradeOrderingRuntime) AcceptCommand(_ context.Context, _ []byte) error {
	runtime.mu.Lock()
	runtime.accepted = true
	runtime.mu.Unlock()
	return nil
}

func (runtime *upgradeOrderingRuntime) PendingStatuses(context.Context) ([]updater.QueuedUpgradeStatus, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.accepted || runtime.acceptedAcked {
		return nil, nil
	}
	return []updater.QueuedUpgradeStatus{runtime.status}, nil
}

func (runtime *upgradeOrderingRuntime) AcknowledgeStatus(_ context.Context, statusID, commandID, digest string) (bool, error) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if statusID != runtime.status.Status.StatusID || commandID != runtime.status.Status.CommandID || digest != runtime.status.SHA256 {
		return false, errors.New("unexpected upgrade status ACK")
	}
	runtime.acceptedAcked = true
	return true, nil
}

func (runtime *upgradeOrderingRuntime) AcknowledgeStatusWithPublication(_ context.Context, acknowledgement updater.UpgradeStatusAcknowledgement) (bool, error) {
	if acknowledgement.PublishedStream != edgeUpgradeStatusStream || acknowledgement.PublishedSequence == 0 {
		return false, errors.New("missing publication identity")
	}
	return runtime.AcknowledgeStatus(context.Background(), acknowledgement.StatusID, acknowledgement.CommandID, acknowledgement.StatusSHA256)
}

func (runtime *upgradeOrderingRuntime) Recover(context.Context) error {
	runtime.mu.Lock()
	if !runtime.accepted {
		runtime.mu.Unlock()
		return nil
	}
	if !runtime.acceptedAcked {
		runtime.recoveryBeforeAck++
		runtime.mu.Unlock()
		return errors.New("recovery ran before accepted ACK")
	}
	runtime.recoveryAfterAck++
	runtime.mu.Unlock()
	runtime.recoverOnce.Do(func() { close(runtime.recovered) })
	return nil
}

func (runtime *upgradeOrderingRuntime) recoveryCounts() (int, int) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.recoveryBeforeAck, runtime.recoveryAfterAck
}

type upgradeOrderingGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	command    *agentv1.UpgradeCommand
	statusSeen chan struct{}
	releaseAck chan struct{}
	once       sync.Once
}

func (gateway *upgradeOrderingGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil || first.GetHello() == nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(1),
		Payload: &agentv1.ConnectResponse_Hello{Hello: &agentv1.GatewayHello{
			SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(50 * time.Millisecond), OfflineAfterDuration: durationpb.New(5 * time.Second),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128,
			EnabledCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}},
		}},
	}); err != nil {
		return err
	}
	if err := stream.Send(&agentv1.ConnectResponse{
		Stream: responseMetadata(2), Payload: &agentv1.ConnectResponse_UpgradeCommand{UpgradeCommand: gateway.command},
	}); err != nil {
		return err
	}
	responseSequence := uint64(2)
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if upgradeStatus := request.GetUpgradeStatus(); upgradeStatus != nil {
			digest := sha256.Sum256(upgradeStatus.Status)
			if !bytes.Equal(digest[:], upgradeStatus.StatusSha256) {
				return status.Error(codes.InvalidArgument, "upgrade status digest mismatch")
			}
			gateway.once.Do(func() { close(gateway.statusSeen) })
			select {
			case <-gateway.releaseAck:
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_UpgradeStatusAck{UpgradeStatusAck: &agentv1.UpgradeStatusAck{
					StatusEventId: "00000000-0000-4000-8000-000000000021",
					CommandId:     "00000000-0000-4000-8000-000000000011", StatusRevision: 1,
					StatusSha256: digest[:], PersistedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
			continue
		}
		if heartbeat := request.GetHeartbeat(); heartbeat != nil {
			responseSequence++
			if err := stream.Send(&agentv1.ConnectResponse{
				Stream: responseMetadata(responseSequence),
				Payload: &agentv1.ConnectResponse_HeartbeatAck{HeartbeatAck: &agentv1.HeartbeatAck{
					HeartbeatEventId: heartbeat.Event.EventId, SessionEpoch: 1, ReceivedTime: timestamppb.Now(),
				}},
			}); err != nil {
				return err
			}
		}
	}
}

func hexDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
