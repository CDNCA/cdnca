package controlinternal

import (
	"context"
	"crypto/sha256"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type nodeInventoryReporter interface {
	ReportNetworkInventory(context.Context, nodeidentity.NetworkInventoryRequest) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
}

func (s *Service) ReportNodeNetworkInventoryV1(ctx context.Context, request *controlv1.ReportNodeNetworkInventoryV1Request) (*controlv1.ReportNodeNetworkInventoryV1Response, error) {
	workload, err := s.authenticateGateway(ctx, request.GetGatewayInstanceId())
	if err != nil {
		return nil, err
	}
	if invalidMessage(request) || request.Inventory == nil || len(request.CertificateSha256) != sha256.Size || !canonicalUUID(request.GatewayInstanceId) ||
		(request.PeerIpSource != "" && request.PeerIpSource != "tcp" && request.PeerIpSource != "trusted_proxy") {
		return nil, invalidRequestError()
	}
	nodeID, err := parseUUID(request.NodeId)
	if err != nil {
		return nil, invalidRequestError()
	}
	reporter, ok := s.identity.(nodeInventoryReporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "node network inventory is unavailable")
	}
	result, err := reporter.ReportNetworkInventory(ctx, nodeidentity.NetworkInventoryRequest{
		GetAuthorizationRequest: nodeidentity.GetAuthorizationRequest{NodeID: nodeID, CertificateSerialNumber: request.CertificateSerialNumber, CertificateSHA256: [32]byte(request.CertificateSha256), GatewayWorkloadIdentity: workload, GatewayInstanceID: request.GatewayInstanceId}, Inventory: request.Inventory, PeerIP: request.GetPeerIp(), PeerIPSource: request.PeerIpSource,
	})
	if err != nil {
		return nil, rpcError(err)
	}
	return &controlv1.ReportNodeNetworkInventoryV1Response{Receipt: result}, nil
}
