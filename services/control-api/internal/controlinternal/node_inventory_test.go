package controlinternal

import (
	"context"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type inventoryTestIdentity struct {
	*fakeIdentityService
	report func(context.Context, nodeidentity.NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
}

func (identity *inventoryTestIdentity) ReportNetworkInventory(ctx context.Context, request nodeidentity.NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	return identity.report(ctx, request)
}

func TestNodeInventoryControlContract(t *testing.T) {
	peerIP := "203.0.113.125"
	request := &controlv1.ReportNodeNetworkInventoryV1Request{Inventory: &agentv1.ReportNodeNetworkInventoryV1Request{SchemaVersion: 1, Request: metadata(), Ipv4: &agentv1.NodeNetworkCandidateV1{Address: peerIP, InterfaceName: "ens17"}, Ipv6Reason: "no_default_route"}, NodeId: testNodeID, CertificateSerialNumber: "123456", CertificateSha256: testCertificateSHA256[:], GatewayInstanceId: testGatewayID, PeerIp: &peerIP, PeerIpSource: "trusted_proxy"}
	calls := 0
	identity := &inventoryTestIdentity{fakeIdentityService: &fakeIdentityService{}, report: func(_ context.Context, value nodeidentity.NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
		calls++
		if value.NodeID.String() != testNodeID || value.CertificateSerialNumber != "123456" || value.CertificateSHA256 != testCertificateSHA256 || value.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN || value.GatewayInstanceID != testGatewayID || value.PeerIP != peerIP || value.PeerIPSource != "trusted_proxy" || !proto.Equal(value.Inventory, request.Inventory) {
			t.Fatal("trusted Gateway/domain mapping changed")
		}
		return &agentv1.ReportNodeNetworkInventoryV1Response{SchemaVersion: 1, NodeId: testNodeID, Ipv4State: "verified", Ipv6State: "no_default_route", ReceivedTime: timestamppb.New(testNow)}, nil
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	if _, err := service.ReportNodeNetworkInventoryV1(gatewayContext(t), request); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("report not delegated")
	}
	if _, err := service.ReportNodeNetworkInventoryV1(context.Background(), request); err == nil {
		t.Fatal("untrusted caller accepted")
	}
	for name, mutate := range map[string]func(*controlv1.ReportNodeNetworkInventoryV1Request){
		"missing-inventory":   func(r *controlv1.ReportNodeNetworkInventoryV1Request) { r.Inventory = nil },
		"wrong-digest-length": func(r *controlv1.ReportNodeNetworkInventoryV1Request) { r.CertificateSha256 = []byte{1} },
		"bad-node-id":         func(r *controlv1.ReportNodeNetworkInventoryV1Request) { r.NodeId = "bad" },
		"bad-gateway-id":      func(r *controlv1.ReportNodeNetworkInventoryV1Request) { r.GatewayInstanceId = "bad" },
		"bad-peer-source":     func(r *controlv1.ReportNodeNetworkInventoryV1Request) { r.PeerIpSource = "header" },
		"unknown-nested": func(r *controlv1.ReportNodeNetworkInventoryV1Request) {
			r.Inventory.Ipv4.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.Clone(request).(*controlv1.ReportNodeNetworkInventoryV1Request)
			mutate(bad)
			_, err := service.ReportNodeNetworkInventoryV1(gatewayContext(t), bad)
			assertCode(t, err, codes.InvalidArgument)
		})
	}
	if calls != 1 {
		t.Fatal("invalid caller or fields reached domain")
	}
	old := newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{})
	_, err := old.ReportNodeNetworkInventoryV1(gatewayContext(t), request)
	assertCode(t, err, codes.Unimplemented)
	identity.report = func(context.Context, nodeidentity.NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
		return nil, nodeidentity.ErrNodeStateDenied
	}
	_, err = service.ReportNodeNetworkInventoryV1(gatewayContext(t), request)
	assertCode(t, err, codes.FailedPrecondition)
}
