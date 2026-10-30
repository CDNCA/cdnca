package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// Servers are intentionally separate physical gRPC servers. Each server's
// service descriptor contains only the methods valid on its TLS boundary.
type Servers struct {
	Enrollment *grpc.Server
	MTLS       *grpc.Server
}

// extra options are appended to both servers (tests add interceptors).
func NewServers(service *Gateway, enrollmentTLS, mtlsTLS *tls.Config, extra ...grpc.ServerOption) (*Servers, error) {
	if service == nil {
		return nil, fmt.Errorf("gateway service is required")
	}
	config := service.config
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := validateServerTLS(enrollmentTLS); err != nil {
		return nil, fmt.Errorf("enrollment TLS: %w", err)
	}
	if err := validateServerTLS(mtlsTLS); err != nil {
		return nil, fmt.Errorf("mTLS: %w", err)
	}
	if mtlsTLS.ClientCAs == nil {
		return nil, fmt.Errorf("mTLS client CA pool is required")
	}
	enrollmentConfig := enrollmentTLS.Clone()
	enrollmentConfig.MinVersion = tls.VersionTLS13
	enrollmentConfig.ClientAuth = tls.NoClientCert

	mutualConfig := mtlsTLS.Clone()
	mutualConfig.MinVersion = tls.VersionTLS13
	mutualConfig.ClientAuth = tls.RequireAndVerifyClientCert

	enrollment := grpc.NewServer(append(serverOptions(config, enrollmentConfig), extra...)...)
	mutualTransportConfig := config
	if service.telemetry != nil && service.telemetry.config.grpcReceiveLimit() > mutualTransportConfig.MaxReceiveMessageBytes {
		mutualTransportConfig.MaxReceiveMessageBytes = service.telemetry.config.grpcReceiveLimit()
	}
	mutual := grpc.NewServer(append(serverOptions(mutualTransportConfig, mutualConfig), extra...)...)
	registerEnrollmentRPC(enrollment, service)
	registerMTLSRPCWithTelemetry(mutual, service)
	return &Servers{Enrollment: enrollment, MTLS: mutual}, nil
}

func serverOptions(config Config, tlsConfig *tls.Config) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.MaxRecvMsgSize(config.MaxReceiveMessageBytes),
		grpc.MaxSendMsgSize(config.MaxSendMessageBytes),
		grpc.MaxConcurrentStreams(config.MaxConcurrentStreams),
		grpc.ConnectionTimeout(config.ConnectionTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: config.KeepaliveTime, Timeout: config.KeepaliveTimeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: config.MinimumClientPingTime, PermitWithoutStream: false}),
		grpc.ChainStreamInterceptor(logStreamRPCError),
	}
}

func validateServerTLS(config *tls.Config) error {
	// GetCertificate alone serves a renewable certificate (bound Gateways,
	// ADR 0013 §3.2); it never changes the listener's TLS policy.
	if config == nil || (len(config.Certificates) == 0 && config.GetCertificate == nil) {
		return fmt.Errorf("server certificate is required")
	}
	if config.GetConfigForClient != nil {
		return fmt.Errorf("dynamic TLS configuration can bypass the fixed listener policy")
	}
	return nil
}

func logStreamRPCError(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	err := handler(srv, stream)
	if err == nil || err == context.Canceled {
		return err
	}
	converted := status.Convert(err)
	log.Printf("agent-gateway stream failed method=%s code=%s error=%q", info.FullMethod, converted.Code(), converted.Message())
	return err
}
