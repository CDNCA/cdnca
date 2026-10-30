package gateway

import (
	"context"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
)

type enrollmentRPC interface {
	Enroll(context.Context, *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error)
	RecoverCertificate(context.Context, *agentv1.RecoverCertificateRequest) (*agentv1.RecoverCertificateResponse, error)
}

type mtlsRPC interface {
	ReportNodeNetworkInventoryV1(context.Context, *agentv1.ReportNodeNetworkInventoryV1Request) (*agentv1.ReportNodeNetworkInventoryV1Response, error)
	RenewCertificate(context.Context, *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error)
	Connect(grpc.BidiStreamingServer[agentv1.ConnectRequest, agentv1.ConnectResponse]) error
	FetchArtifact(*agentv1.FetchArtifactRequest, grpc.ServerStreamingServer[agentv1.FetchArtifactResponse]) error
	FetchSiteObjects(*agentv1.FetchSiteObjectsRequest, grpc.ServerStreamingServer[agentv1.FetchSiteObjectsResponse]) error
}

func registerEnrollmentRPC(server grpc.ServiceRegistrar, service enrollmentRPC) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "agent.v1.AgentGatewayService",
		HandlerType: (*enrollmentRPC)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Enroll", Handler: enrollmentHandler},
			{MethodName: "RecoverCertificate", Handler: recoveryHandler}},
		Metadata: "agent/v1/gateway_service.proto",
	}, service)
}

func registerMTLSRPC(server grpc.ServiceRegistrar, service mtlsRPC) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "agent.v1.AgentGatewayService",
		HandlerType: (*mtlsRPC)(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "RenewCertificate", Handler: renewalHandler}, {MethodName: "ReportNodeNetworkInventoryV1", Handler: networkInventoryHandler}},
		Streams: []grpc.StreamDesc{
			{StreamName: "Connect", Handler: connectHandler, ServerStreams: true, ClientStreams: true},
			{StreamName: "FetchArtifact", Handler: fetchArtifactHandler, ServerStreams: true},
			{StreamName: "FetchSiteObjects", Handler: fetchSiteObjectsHandler, ServerStreams: true},
		},
		Metadata: "agent/v1/gateway_service.proto",
	}, service)
}

func enrollmentHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(agentv1.EnrollRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return service.(enrollmentRPC).Enroll(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: agentv1.AgentGatewayService_Enroll_FullMethodName}
	handler := func(ctx context.Context, request any) (any, error) {
		return service.(enrollmentRPC).Enroll(ctx, request.(*agentv1.EnrollRequest))
	}
	return interceptor(ctx, request, info, handler)
}

func recoveryHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(agentv1.RecoverCertificateRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return service.(enrollmentRPC).RecoverCertificate(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: agentv1.AgentGatewayService_RecoverCertificate_FullMethodName}
	handler := func(ctx context.Context, request any) (any, error) {
		return service.(enrollmentRPC).RecoverCertificate(ctx, request.(*agentv1.RecoverCertificateRequest))
	}
	return interceptor(ctx, request, info, handler)
}

func renewalHandler(service any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	request := new(agentv1.RenewCertificateRequest)
	if err := decode(request); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return service.(mtlsRPC).RenewCertificate(ctx, request)
	}
	info := &grpc.UnaryServerInfo{Server: service, FullMethod: agentv1.AgentGatewayService_RenewCertificate_FullMethodName}
	handler := func(ctx context.Context, request any) (any, error) {
		return service.(mtlsRPC).RenewCertificate(ctx, request.(*agentv1.RenewCertificateRequest))
	}
	return interceptor(ctx, request, info, handler)
}

func connectHandler(service any, stream grpc.ServerStream) error {
	return service.(mtlsRPC).Connect(&grpc.GenericServerStream[agentv1.ConnectRequest, agentv1.ConnectResponse]{ServerStream: stream})
}

func fetchArtifactHandler(service any, stream grpc.ServerStream) error {
	request := new(agentv1.FetchArtifactRequest)
	if err := stream.RecvMsg(request); err != nil {
		return err
	}
	return service.(mtlsRPC).FetchArtifact(request, &grpc.GenericServerStream[agentv1.FetchArtifactRequest, agentv1.FetchArtifactResponse]{ServerStream: stream})
}

func fetchSiteObjectsHandler(service any, stream grpc.ServerStream) error {
	request := new(agentv1.FetchSiteObjectsRequest)
	if err := stream.RecvMsg(request); err != nil {
		return err
	}
	return service.(mtlsRPC).FetchSiteObjects(request,
		&grpc.GenericServerStream[agentv1.FetchSiteObjectsRequest, agentv1.FetchSiteObjectsResponse]{ServerStream: stream})
}
