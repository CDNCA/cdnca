package gatewayclient

import (
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/signertrust"
	"github.com/cdnca/cdnca/libs/entitlement/edgesignertrust"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// signerTrustGateway enables EDGE_SIGNER_TRUST, delivers its bundles in
// order (one after each receipt) and records the receipts.
type signerTrustGateway struct {
	agentv1.UnimplementedAgentGatewayServiceServer
	bundles  []*agentv1.EdgeSignerTrustBundle
	enable   bool
	hellos   chan *agentv1.AgentHello
	receipts chan *agentv1.EdgeSignerTrustReceipt
}

func (g *signerTrustGateway) Connect(stream grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	g.hellos <- first.GetHello()
	enabled := []*agentv1.Capability{}
	if g.enable {
		enabled = append(enabled, &agentv1.Capability{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1})
	}
	if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(1), Payload: &agentv1.ConnectResponse_Hello{
		Hello: &agentv1.GatewayHello{SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, GatewayVersion: "test",
			SessionId: uuid.NewString(), SessionEpoch: 1, ServerTime: timestamppb.Now(),
			HeartbeatIntervalDuration: durationpb.New(time.Hour), OfflineAfterDuration: durationpb.New(2 * time.Hour),
			MaximumArtifactChunkBytes: 1024, MessageIdReplayWindow: 128, EnabledCapabilities: enabled}}}); err != nil {
		return err
	}
	sequence := uint64(1)
	for _, bundle := range g.bundles {
		sequence++
		if err := stream.Send(&agentv1.ConnectResponse{Stream: responseMetadata(sequence),
			Payload: &agentv1.ConnectResponse_EdgeSignerTrustBundle{EdgeSignerTrustBundle: bundle}}); err != nil {
			return err
		}
		for {
			request, err := stream.Recv()
			if err != nil {
				return err
			}
			if receipt := request.GetEdgeSignerTrustReceipt(); receipt != nil {
				g.receipts <- receipt
				break
			}
		}
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func signerTrustCarrier(nodeID string, wire []byte, revision uint64) *agentv1.EdgeSignerTrustBundle {
	digest := sha256.Sum256(wire)
	return &agentv1.EdgeSignerTrustBundle{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		Schema: agentv1.EdgeSignerTrustSchema_EDGE_SIGNER_TRUST_SCHEMA_V1, NodeId: nodeID, Revision: revision,
		BundleJson: wire, BundleSha256: digest[:],
	}
}

// TestClientAppliesSignerTrustBundleAndRejectsRollback: the Agent advertises
// the capability, applies a revoking bundle and reports a bound receipt; a
// later bundle with a lower revision is rejected and the revocation stays.
func TestClientAppliesSignerTrustBundleAndRejectsRollback(t *testing.T) {
	fixture := newSignerTrustFixture(t)
	root := secureTempDir(t)
	config := testClientConfig(filepath.Join(root, "journal"))
	runtime, err := NewSignerTrustRuntime(filepath.Join(root, "signer-trust"), config.NodeID, fixture.trust, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	current := fixture.bundle(config.NodeID, "edge-publish", fixture.control,
		fixture.document(2, nil, revokedKey("release-old")))
	rollback := fixture.bundle(config.NodeID, "edge-publish", fixture.control, fixture.document(1, nil))
	gateway := &signerTrustGateway{enable: true, hellos: make(chan *agentv1.AgentHello, 4),
		receipts: make(chan *agentv1.EdgeSignerTrustReceipt, 4),
		bundles:  []*agentv1.EdgeSignerTrustBundle{signerTrustCarrier(config.NodeID, current, 2), signerTrustCarrier(config.NodeID, rollback, 1)}}
	client := startBufconnClient(t, gateway, config, fixture.trust, WithSignerTrustRuntime(runtime))
	defer client.cancel()
	if hello := <-gateway.hellos; !hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST) {
		t.Fatalf("hello does not advertise edge signer trust: %v", hello.GetCapabilities().GetFeatures())
	}
	for index, want := range []struct {
		wire     []byte
		revision uint64
		result   string
		reason   string
	}{{current, 2, edgesignertrust.ResultApplied, ""}, {rollback, 2, edgesignertrust.ResultRejected, edgesignertrust.ReasonStale}} {
		select {
		case receipt := <-gateway.receipts:
			body, err := edgesignertrust.DecodeReceipt(receipt.ReceiptJson)
			carrier := gateway.bundles[index]
			if err != nil || receipt.BundleEventId != carrier.Event.EventId || receipt.Revision != carrier.Revision ||
				string(receipt.BundleSha256) != string(carrier.BundleSha256) || receipt.NodeId != config.NodeID ||
				body.BundleSHA256 != edgesignertrust.Digest(want.wire) || body.Revision != want.revision ||
				body.Result != want.result || body.Reason != want.reason {
				t.Fatalf("receipt %d = %+v body=%+v err=%v", index, receipt, body, err)
			}
			if _, err := signertrust.RouteReceipt(receipt.ReceiptJson); err != nil {
				t.Fatalf("gateway binding rejects the receipt body: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no receipt %d", index)
		}
	}
	if _, ok := fixture.trust.key("release-old"); ok || fixture.trust.SignerTrustRevision() != 2 {
		t.Fatal("the rollback bundle lifted the revocation")
	}
}

func TestClientWithoutSignerTrustRuntimeDoesNotAdvertiseAndRejectsEnablement(t *testing.T) {
	if _, err := negotiateSignerTrustV1(&agentv1.GatewayHello{EnabledCapabilities: []*agentv1.Capability{{
		Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST, ApiVersion: 1}}}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("unrequested enablement err=%v", err)
	}
	fixture := newSignerTrustFixture(t)
	runtime, err := NewSignerTrustRuntime(filepath.Join(t.TempDir(), "signer-trust"), "node-1", fixture.trust, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if enabled, err := negotiateSignerTrustV1(&agentv1.GatewayHello{}, runtime); err != nil || enabled {
		t.Fatalf("gateway without the bus = %v, %v", enabled, err)
	}
	gateway := &signerTrustGateway{hellos: make(chan *agentv1.AgentHello, 4)}
	client := startBufconnClient(t, gateway, testClientConfig(filepath.Join(secureTempDir(t), "journal")), fixture.trust)
	defer client.cancel()
	if hello := <-gateway.hellos; hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_EDGE_SIGNER_TRUST) {
		t.Fatal("agent without a signer trust runtime advertised the capability")
	}
}

// The transport limits in libs/edgeconfig/signertrust mirror the body limits.
func TestSignerTrustTransportLimitsMatchBodies(t *testing.T) {
	if signertrust.MaxBundleBytes != edgesignertrust.MaxBundleBytes {
		t.Fatalf("MaxBundleBytes %d != %d", signertrust.MaxBundleBytes, edgesignertrust.MaxBundleBytes)
	}
	big := make([]byte, signertrust.MaxReceiptBytes+1)
	if _, err := edgesignertrust.DecodeReceipt(big); err == nil {
		t.Fatal("receipt body limit is larger than the transport's")
	}
}
