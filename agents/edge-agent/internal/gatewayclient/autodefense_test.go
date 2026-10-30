package gatewayclient

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/autodefense"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type autoDefenseRuntimeStub struct {
	results []AutoDefenseResult
	applied chan []byte
	reports chan []byte
}

func (stub *autoDefenseRuntimeStub) ApplyAutoDefense(encoded []byte) AutoDefenseResult {
	stub.applied <- encoded
	result := stub.results[0]
	stub.results = stub.results[1:]
	return result
}
func (stub *autoDefenseRuntimeStub) Reports() <-chan []byte { return stub.reports }

// autoDefenseGateway enables AUTO_DEFENSE, sends its commands one after each receipt and records receipts and
// reports.
type autoDefenseGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	enable   bool
	commands []*agentv1.AutoDefenseCommand
	hellos   chan *agentv1.AgentHello
	receipts chan *agentv1.AutoDefenseReceipt
	reports  chan *agentv1.AutoDefenseReport
}

func (g *autoDefenseGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	g.hellos <- first.GetHello()
	enabled := []*agentv1.Capability{}
	if g.enable {
		enabled = append(enabled, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: 1})
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled}}}); err != nil {
		return err
	}
	sequence := uint64(1)
	next := 0
	sendNext := func() error {
		if next >= len(g.commands) {
			return nil
		}
		sequence++
		command := g.commands[next]
		next++
		return stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(sequence),
			Payload: &agentv1.ConnectResponse_AutoDefenseCommand{AutoDefenseCommand: command}})
	}
	if err := sendNext(); err != nil {
		return err
	}
	for {
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		if receipt := request.GetAutoDefenseReceipt(); receipt != nil {
			g.receipts <- receipt
			if err := sendNext(); err != nil {
				return err
			}
		}
		if report := request.GetAutoDefenseReport(); report != nil {
			g.reports <- report
		}
	}
}

func autoDefenseCarrier(nodeID string, wire []byte, revision uint64) *agentv1.AutoDefenseCommand {
	digest := sha256.Sum256(wire)
	return &agentv1.AutoDefenseCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, Revision: revision, SnapshotJson: wire, SnapshotSha256: digest[:],
	}
}

// The Agent advertises AUTO_DEFENSE, hands each part to the runtime and answers with a receipt bound to the part;
// a refusal carries the runtime's error code and no counts; runtime reports are sent upstream.
func TestClientAutoDefenseReceiptsAndReports(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStore(map[string]crypto.PublicKey{"edge-publish": public})
	if err != nil {
		t.Fatal(err)
	}
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	first := autoDefenseCarrier(config.NodeID, []byte(`{"part":1}`), 4)
	second := autoDefenseCarrier(config.NodeID, []byte(`{"part":2}`), 3)
	runtime := &autoDefenseRuntimeStub{applied: make(chan []byte, 4), reports: make(chan []byte, 4),
		results: []AutoDefenseResult{{Applied: true, Sites: 3, Signatures: 2, Mitigations: 1},
			{ErrorCode: autodefense.ErrorStale, Sites: 9}}}
	gateway := &autoDefenseGateway{enable: true, commands: []*agentv1.AutoDefenseCommand{first, second},
		hellos: make(chan *agentv1.AgentHello, 4), receipts: make(chan *agentv1.AutoDefenseReceipt, 4),
		reports: make(chan *agentv1.AutoDefenseReport, 4)}
	client := startBufconnClient(t, gateway, config, trust, WithAutoDefense(runtime))
	defer client.cancel()
	if hello := <-gateway.hellos; !hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE) {
		t.Fatalf("hello does not advertise auto defense: %v", hello.GetCapabilities().GetFeatures())
	}
	for index, want := range []struct {
		command *agentv1.AutoDefenseCommand
		applied bool
		sites   uint32
		code    string
	}{{first, true, 3, ""}, {second, false, 0, autodefense.ErrorStale}} {
		select {
		case receipt := <-gateway.receipts:
			if receipt.NodeId != config.NodeID || receipt.CommandEventId != want.command.Event.EventId ||
				receipt.Revision != want.command.Revision || string(receipt.SnapshotSha256) != string(want.command.SnapshotSha256) ||
				receipt.Applied != want.applied || receipt.Sites != want.sites || receipt.ErrorCode != want.code ||
				!canonicalUUID(receipt.Event.GetEventId()) || !canonicalUUID(receipt.Event.GetRequestId()) {
				t.Fatalf("receipt %d = %+v", index, receipt)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no receipt %d", index)
		}
		if got := <-runtime.applied; string(got) != string(want.command.SnapshotJson) {
			t.Fatalf("runtime got %s", got)
		}
	}
	runtime.reports <- []byte(`{"schema":"cdnca.autodefense.report/v1"}`)
	runtime.reports <- make([]byte, autodefense.MaxReportBytes+1) // dropped by the Agent
	runtime.reports <- []byte(`{"seq":2}`)
	for _, want := range []string{`{"schema":"cdnca.autodefense.report/v1"}`, `{"seq":2}`} {
		select {
		case report := <-gateway.reports:
			if string(report.ReportJson) != want {
				t.Fatalf("report = %q, want %q", report.ReportJson, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("report %s not sent", want)
		}
	}
}

func TestAutoDefenseCarrierAndNegotiation(t *testing.T) {
	if _, err := negotiateAutoDefenseV1(&agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: 1}}}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unrequested enablement err=%v", err)
	}
	runtime := &autoDefenseRuntimeStub{applied: make(chan []byte, 1), results: []AutoDefenseResult{{}}}
	if _, err := negotiateAutoDefenseV1(&agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_AUTO_DEFENSE, ApiVersion: 2}}}, runtime); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unsupported version err=%v", err)
	}
	client := &Client{config: Config{NodeID: uuid.NewString()}, autoDefense: runtime}
	command := autoDefenseCarrier(client.config.NodeID, []byte(`{}`), 1)
	for name, mutate := range map[string]func(*agentv1.AutoDefenseCommand){
		"node":     func(value *agentv1.AutoDefenseCommand) { value.NodeId = uuid.NewString() },
		"digest":   func(value *agentv1.AutoDefenseCommand) { value.SnapshotSha256 = make([]byte, sha256.Size) },
		"revision": func(value *agentv1.AutoDefenseCommand) { value.Revision = 0 },
		"event":    func(value *agentv1.AutoDefenseCommand) { value.Event.EventId = "x" },
	} {
		changed := autoDefenseCarrier(client.config.NodeID, []byte(`{}`), 1)
		mutate(changed)
		if _, err := client.autoDefenseReceipt(changed, time.Now()); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	// A runtime that refuses without a code reports runtime_unavailable.
	receipt, err := client.autoDefenseReceipt(command, time.Now())
	if err != nil || receipt.Applied || receipt.ErrorCode != autodefense.ErrorRuntime {
		t.Fatalf("receipt = %+v %v", receipt, err)
	}
	// No runtime: not_supported.
	client.autoDefense = nil
	if receipt, err := client.autoDefenseReceipt(command, time.Now()); err != nil || receipt.ErrorCode != autodefense.ErrorNotSupported {
		t.Fatalf("receipt without runtime = %+v %v", receipt, err)
	}
}
