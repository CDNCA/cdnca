package gateway

import (
	"context"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type nodeInventoryControl interface {
	ReportNodeNetworkInventoryV1(context.Context, *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
}

func (c GeneratedControlClient) ReportNodeNetworkInventoryV1(ctx context.Context, request *controlv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	result, err := c.Client.ReportNodeNetworkInventoryV1(ctx, request)
	if err != nil {
		return nil, err
	}
	if result == nil || cacheControlMessageHasUnknown(result.ProtoReflect()) {
		return nil, status.Error(codes.Internal, "invalid inventory receipt envelope")
	}
	return result.Receipt, nil
}

func (g *Gateway) ReportNodeNetworkInventoryV1(ctx context.Context, request *agentv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error) {
	identity, err := authenticatedNode(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateTelemetryCertificate(ctx, g.now()); err != nil {
		return nil, err
	}
	if request == nil || request.SchemaVersion != 1 || proto.Size(request) > 4096 || cacheControlMessageHasUnknown(request.ProtoReflect()) || g.validateRequestMetadata(request.Request) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid network inventory")
	}
	control, ok := g.control.(nodeInventoryControl)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "node network inventory is unavailable")
	}
	// A tunnel connection carries the trusted CDN forwarded address (ADR
	// 0013 §4.4); a direct session is the TCP peer.
	var peer *string
	peerSource := PeerIPSourceTCP
	if address, source, ok := peerAddress(ctx); ok {
		value := address.String()
		peer, peerSource = &value, source
	}
	ctx, cancel := context.WithTimeout(ctx, g.config.ControlDecisionTimeout)
	defer cancel()
	result, err := control.ReportNodeNetworkInventoryV1(ctx, &controlv1.ReportNodeNetworkInventoryV1Request{Inventory: request, NodeId: identity.NodeID, CertificateSerialNumber: identity.SerialNumber, CertificateSha256: identity.CertificateSHA256[:], GatewayInstanceId: g.config.GatewayInstanceID, PeerIp: peer, PeerIpSource: peerSource})
	if err != nil {
		return nil, rpcError(err)
	}
	if result == nil || cacheControlMessageHasUnknown(result.ProtoReflect()) || result.SchemaVersion != 1 || result.NodeId != identity.NodeID || result.ReceivedTime == nil || result.ReceivedTime.CheckValid() != nil || !inventoryReceiptState(result.Ipv4State) || !inventoryReceiptState(result.Ipv6State) {
		return nil, status.Error(codes.Internal, "invalid inventory receipt")
	}
	return result, nil
}

func inventoryReceiptState(value string) bool {
	switch value {
	case "verified", "address_conflict", "peer_mismatch", "no_default_route", "no_global_address", "ambiguous_route", "unavailable":
		return true
	default:
		return false
	}
}

func networkInventoryHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(agentv1.ReportNodeNetworkInventoryV1Request)
	if err := decode(request); err != nil {
		return nil, err
	}
	handler := func(ctx context.Context, value any) (any, error) {
		return service.(mtlsRPC).ReportNodeNetworkInventoryV1(ctx, value.(*agentv1.ReportNodeNetworkInventoryV1Request))
	}
	if interceptor == nil {
		return handler(ctx, request)
	}
	return interceptor(ctx, request, &grpc.UnaryServerInfo{Server: service, FullMethod: agentv1.AgentGatewayService_ReportNodeNetworkInventoryV1_FullMethodName}, handler)
}
