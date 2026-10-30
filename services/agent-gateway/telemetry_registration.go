package gateway

import (
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc"
)

type telemetryMTLSRPC interface {
	mtlsRPC
	StreamTelemetry(grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error
}

func registerMTLSRPCWithTelemetry(server grpc.ServiceRegistrar, service telemetryMTLSRPC) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "agent.v1.AgentGatewayService",
		HandlerType: (*telemetryMTLSRPC)(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "RenewCertificate", Handler: renewalHandler}, {MethodName: "ReportNodeNetworkInventoryV1", Handler: networkInventoryHandler}},
		Streams: []grpc.StreamDesc{
			{StreamName: "Connect", Handler: connectHandler, ServerStreams: true, ClientStreams: true},
			{StreamName: "StreamTelemetry", Handler: streamTelemetryHandler, ServerStreams: true, ClientStreams: true},
			{StreamName: "FetchArtifact", Handler: fetchArtifactHandler, ServerStreams: true},
			{StreamName: "FetchSiteObjects", Handler: fetchSiteObjectsHandler, ServerStreams: true},
		},
		Metadata: "agent/v1/gateway_service.proto",
	}, service)
}

func streamTelemetryHandler(service any, stream grpc.ServerStream) error {
	return service.(telemetryMTLSRPC).StreamTelemetry(
		&grpc.GenericServerStream[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]{ServerStream: stream},
	)
}
