package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestStreamTelemetryIsMountedOnlyOnAgentMTLSListener(t *testing.T) {
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 42, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	control := &telemetryTestControl{fakeControl: defaultFakeControl(), states: []telemetryAuthorizationState{{}}}
	publisher := &scriptedTelemetryPublisher{}
	service := newTelemetryGateway(t, control, publisher)
	servers, err := NewServers(service,
		&tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool},
	)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentInfo := servers.Enrollment.GetServiceInfo()["agent.v1.AgentGatewayService"]
	for _, method := range enrollmentInfo.Methods {
		if method.Name == "StreamTelemetry" {
			t.Fatal("enrollment listener exposed StreamTelemetry")
		}
	}
	mtlsInfo := servers.MTLS.GetServiceInfo()["agent.v1.AgentGatewayService"]
	foundTelemetry := false
	for _, method := range mtlsInfo.Methods {
		foundTelemetry = foundTelemetry || method.Name == "StreamTelemetry" && method.IsClientStream && method.IsServerStream
	}
	if !foundTelemetry {
		t.Fatal("Agent mTLS listener did not register bidirectional StreamTelemetry")
	}
	enrollmentListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mtlsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.Enrollment.Serve(enrollmentListener) }()
	go func() { _ = servers.MTLS.Serve(mtlsListener) }()
	t.Cleanup(func() {
		servers.Enrollment.Stop()
		servers.MTLS.Stop()
		_ = enrollmentListener.Close()
		_ = mtlsListener.Close()
	})

	mtlsConnection := dialGateway(t, mtlsListener.Addr().String(), pki.rootPool, clientCertificate)
	defer mtlsConnection.Close()
	stream, err := agentv1.NewAgentGatewayServiceClient(mtlsConnection).StreamTelemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(telemetryHelloRequest(0, 1)); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil || response.GetHello() == nil || response.GetHello().MaximumInflightBatches != 1 {
		t.Fatalf("mTLS telemetry hello = %+v, err=%v", response, err)
	}
	if err := stream.Send(telemetryBatchRequest(telemetryBatch(t, 1, 1), 2)); err != nil {
		t.Fatal(err)
	}
	response, err = stream.Recv()
	if err != nil || response.GetAck() == nil || response.GetAck().AcceptedThroughSequence != 1 {
		t.Fatalf("mTLS telemetry ACK = %+v, err=%v", response, err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
}

func TestTelemetryCertificateRequiresExplicitClientAudience(t *testing.T) {
	tests := []struct {
		name   string
		usages []x509.ExtKeyUsage
		valid  bool
	}{
		{name: "client", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, valid: true},
		{name: "server", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "any", usages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		{name: "missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := allowsClientAuthentication(&x509.Certificate{ExtKeyUsage: test.usages}); got != test.valid {
				t.Fatalf("allowsClientAuthentication = %t, want %t", got, test.valid)
			}
		})
	}
}
