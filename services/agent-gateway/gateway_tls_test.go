package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testNodeID = "018f47a2-5b9c-7d31-8a60-104c9c0b717f"

type fakeControl struct {
	accepted *commonv1.ProtocolVersionRange
	mu       sync.Mutex
	renewal  *controlv1.RenewNodeCertificateRequest
}

func (f *fakeControl) AuthorizeEnrollment(_ context.Context, request *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	return &controlv1.AuthorizeEnrollmentResponse{
		AuthorizationId:         uuid.NewString(),
		NodeId:                  testNodeID,
		SelectedProtocolVersion: f.accepted.Maximum,
		ArtifactEncryptionKeyId: "artifact-key",
	}, nil
}

func (f *fakeControl) CompleteEnrollment(context.Context, *controlv1.CompleteEnrollmentRequest) (*controlv1.CompleteEnrollmentResponse, error) {
	return &controlv1.CompleteEnrollmentResponse{
		NodeId:                  testNodeID,
		Certificate:             &agentv1.CertificateBundle{LeafCertificatePem: []byte("public test certificate")},
		ArtifactEncryptionKeyId: "artifact-key",
	}, nil
}

func (f *fakeControl) RenewNodeCertificate(_ context.Context, request *controlv1.RenewNodeCertificateRequest) (*controlv1.RenewNodeCertificateResponse, error) {
	f.mu.Lock()
	f.renewal = &controlv1.RenewNodeCertificateRequest{
		NodeId:                       request.GetNodeId(),
		CurrentSerialNumber:          request.GetCurrentSerialNumber(),
		CurrentCertificateSha256:     bytes.Clone(request.GetCurrentCertificateSha256()),
		CertificateSigningRequestDer: bytes.Clone(request.GetCertificateSigningRequestDer()),
		GatewayInstanceId:            request.GetGatewayInstanceId(),
	}
	f.mu.Unlock()
	return &controlv1.RenewNodeCertificateResponse{Certificate: &agentv1.CertificateBundle{LeafCertificatePem: []byte("renewed public test certificate")}}, nil
}

func (f *fakeControl) GetNodeAuthorization(_ context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId:                   request.NodeId,
		AdministrativeState:      controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE,
		ConnectionAllowed:        true,
		AcceptedProtocolVersions: f.accepted,
		SnapshotExpirationTime:   timestamppb.New(time.Now().Add(time.Hour)),
		ArtifactEncryptionKeyId:  "artifact-key",
		NodeScopeId:              testNodeOwnerScopeID,
	}, nil
}

// testNodeOwnerScopeID owns the test node (GetNodeAuthorization node_scope_id).
const testNodeOwnerScopeID = "6f2a4c1e-0b7d-4e3a-9c55-1a2b3c4d5e6f"

func (f *fakeControl) FetchArtifact(context.Context, *controlv1.FetchArtifactRequest) (ArtifactStream, error) {
	return &fakeArtifactStream{}, nil
}

type fakeArtifactStream struct{}

func (*fakeArtifactStream) Recv() (*controlv1.FetchArtifactResponse, error) { return nil, io.EOF }

type testServers struct {
	enrollmentAddress string
	mtlsAddress       string
	pki               *testPKI
	clientCertificate tls.Certificate
}

func startTestServers(t *testing.T, control ControlPlane) testServers {
	return startTestServersWithConfig(t, control, nil)
}

func startTestServersWithConfig(t *testing.T, control ControlPlane, configure func(*Config)) testServers {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID = "gateway-test"
	config.GatewayVersion = "test"
	if configure != nil {
		configure(&config)
	}
	gateway, err := New(config, control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(gateway,
		&tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool},
	)
	if err != nil {
		t.Fatal(err)
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
	return testServers{
		enrollmentAddress: enrollmentListener.Addr().String(),
		mtlsAddress:       mtlsListener.Addr().String(),
		pki:               pki,
		clientCertificate: clientCertificate,
	}
}

func TestRenewCertificateCarriesExactAuthenticatedLeafDigest(t *testing.T) {
	control := defaultFakeControl()
	servers := startTestServers(t, control)
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer connection.Close()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.RenewCertificate(ctx, &agentv1.RenewCertificateRequest{
		Request:                      &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		CurrentSerialNumber:          "a",
		CertificateSigningRequestDer: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(servers.clientCertificate.Certificate[0])
	control.mu.Lock()
	renewal := control.renewal
	control.mu.Unlock()
	if renewal == nil || renewal.NodeId != testNodeID || renewal.CurrentSerialNumber != "a" ||
		!bytes.Equal(renewal.CurrentCertificateSha256, want[:]) {
		t.Fatalf("renewal request = %#v, want node %q serial a digest %x", renewal, testNodeID, want)
	}
}

func TestListenersExposeOnlyTheirAuthorizedMethods(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	enrollmentConnection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer enrollmentConnection.Close()
	enrollmentClient := agentv1.NewAgentGatewayServiceClient(enrollmentConnection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connect, err := enrollmentClient.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sendErr := connect.Send(validHello(testNodeID, versionRange(1, 0), 1))
	_, recvErr := connect.Recv()
	if recvErr != nil {
		err = recvErr
	} else {
		err = sendErr
	}
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("enrollment listener Connect code = %v, want Unimplemented", status.Code(err))
	}

	mtlsConnection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer mtlsConnection.Close()
	mtlsClient := agentv1.NewAgentGatewayServiceClient(mtlsConnection)
	_, err = mtlsClient.Enroll(ctx, validEnrollment())
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("mTLS listener Enroll code = %v, want Unimplemented", status.Code(err))
	}
}

func TestEnrollmentRequestMetadataLimit(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	connection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer connection.Close()
	request := validEnrollment()
	request.Request.CorrelationId = strings.Repeat("x", defaultMaxMetadataBytes)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := agentv1.NewAgentGatewayServiceClient(connection).Enroll(ctx, request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Enroll code = %v, want InvalidArgument", status.Code(err))
	}
}

func TestMTLSRejectsInvalidClientCertificates(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	now := time.Now()
	otherPKI := newTestPKI(t)
	cases := []struct {
		name         string
		certificates []tls.Certificate
	}{
		{name: "missing"},
		{name: "untrusted", certificates: []tls.Certificate{otherPKI.client(t, 20, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))}},
		{name: "expired", certificates: []tls.Certificate{servers.pki.client(t, 21, nodeSPIFFEPrefix+testNodeID, now.Add(-2*time.Hour), now.Add(-time.Hour))}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, test.certificates...)
			defer connection.Close()
			client := agentv1.NewAgentGatewayServiceClient(connection)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := client.Connect(ctx)
			if err == nil {
				err = stream.Send(validHello(testNodeID, versionRange(1, 0), 1))
			}
			if err == nil {
				_, err = stream.Recv()
			}
			if err == nil {
				t.Fatal("connection unexpectedly succeeded")
			}
		})
	}
}

func TestConnectRejectsWrongSANAndNodeMismatch(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	now := time.Now()
	tests := []struct {
		name   string
		cert   tls.Certificate
		nodeID string
	}{
		{name: "wrong SAN", cert: servers.pki.client(t, 30, "spiffe://cdn-platform/node/not-a-uuid", now.Add(-time.Hour), now.Add(time.Hour)), nodeID: testNodeID},
		{name: "node mismatch", cert: servers.clientCertificate, nodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7180"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, test.cert)
			defer connection.Close()
			client := agentv1.NewAgentGatewayServiceClient(connection)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, err := client.Connect(ctx)
			if err != nil {
				t.Fatal(err)
			}
			sendErr := stream.Send(validHello(test.nodeID, versionRange(1, 0), 1))
			_, recvErr := stream.Recv()
			if recvErr != nil {
				err = recvErr
			} else {
				err = sendErr
			}
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("Connect code = %v, want Unauthenticated", status.Code(err))
			}
		})
	}
}

func TestConnectRequiresHelloFirst(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer connection.Close()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	requestID, eventID := uuid.NewString(), uuid.NewString()
	if err := stream.Send(validHeartbeatRequest(1, 1, 1, requestID, eventID)); err != nil {
		t.Fatal(err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Connect code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestConnectReportsNoProtocolIntersection(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer connection.Close()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(validHello(testNodeID, versionRange(2, 0), 1)); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if response.GetError().GetError().GetCode() != commonv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION {
		t.Fatalf("protocol error = %v, want unsupported version", response.GetError())
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("terminal code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestConnectHeartbeatAckAndValidation(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	t.Run("ack", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		requestID, eventID := uuid.NewString(), uuid.NewString()
		if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch, 1, 2, requestID, eventID)); err != nil {
			t.Fatal(err)
		}
		response, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		ack := response.GetHeartbeatAck()
		if ack == nil || ack.HeartbeatEventId != eventID || ack.SessionEpoch != hello.SessionEpoch || response.Stream.Sequence != 2 {
			t.Fatalf("unexpected heartbeat ack: %+v", response)
		}
	})
	t.Run("stream sequence", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch, 1, 1, uuid.NewString(), uuid.NewString())); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Recv()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})
	t.Run("heartbeat sequence", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch, 2, 2, uuid.NewString(), uuid.NewString())); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch, 1, 3, uuid.NewString(), uuid.NewString())); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Recv()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})
	t.Run("session epoch", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		if err := stream.Send(validHeartbeatRequest(hello.SessionEpoch+1, 1, 2, uuid.NewString(), uuid.NewString())); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Recv()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})
	t.Run("event limit", func(t *testing.T) {
		stream, hello, cleanup := establishSession(t, servers)
		defer cleanup()
		request := validHeartbeatRequest(hello.SessionEpoch, 1, 2, uuid.NewString(), uuid.NewString())
		request.GetHeartbeat().Event.CorrelationId = strings.Repeat("x", defaultMaxMetadataBytes)
		if err := stream.Send(request); err != nil {
			t.Fatal(err)
		}
		_, err := stream.Recv()
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})
}

func TestNewSessionSupersedesExistingSession(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	first, firstHello, firstCleanup := establishSession(t, servers)
	defer firstCleanup()
	_, secondHello, secondCleanup := establishSession(t, servers)
	defer secondCleanup()
	if secondHello.SessionEpoch <= firstHello.SessionEpoch {
		t.Fatalf("second epoch = %d, want greater than %d", secondHello.SessionEpoch, firstHello.SessionEpoch)
	}
	_, err := first.Recv()
	if status.Code(err) != codes.Aborted {
		t.Fatalf("superseded stream code = %v, want Aborted", status.Code(err))
	}
}

func establishSession(t *testing.T, servers testServers) (grpc.BidiStreamingClient[agentv1.ConnectRequest, agentv1.ConnectResponse], *agentv1.GatewayHello, func()) {
	t.Helper()
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := client.Connect(ctx)
	if err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	if err := stream.Send(validHello(testNodeID, versionRange(1, 0), 1)); err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	response, err := stream.Recv()
	if err != nil {
		cancel()
		connection.Close()
		t.Fatal(err)
	}
	hello := response.GetHello()
	if hello == nil || response.Stream.Sequence != 1 {
		cancel()
		connection.Close()
		t.Fatalf("first response is not GatewayHello: %+v", response)
	}
	return stream, hello, func() {
		cancel()
		_ = connection.Close()
	}
}

func dialGateway(t *testing.T, address string, roots *x509.CertPool, certificates ...tls.Certificate) *grpc.ClientConn {
	t.Helper()
	connection, err := grpc.NewClient("passthrough:///"+address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   "localhost",
		RootCAs:      roots,
		Certificates: certificates,
	})))
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func validHello(nodeID string, supported *commonv1.ProtocolVersionRange, sequence uint64) *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: sequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_Hello{Hello: &agentv1.AgentHello{
			NodeId:                    nodeID,
			BootId:                    uuid.NewString(),
			SupportedProtocolVersions: supported,
			Capabilities:              &agentv1.AgentCapabilities{},
			ArtifactEncryptionKeyId:   "artifact-key",
		}},
	}
}

func validHeartbeatRequest(epoch, heartbeatSequence, streamSequence uint64, requestID, eventID string) *agentv1.ConnectRequest {
	return &agentv1.ConnectRequest{
		Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), Sequence: streamSequence, SentTime: timestamppb.Now()},
		Payload: &agentv1.ConnectRequest_Heartbeat{Heartbeat: &agentv1.Heartbeat{
			Event:             &commonv1.EventMetadata{EventId: eventID, RequestId: requestID, OccurredTime: timestamppb.Now()},
			SessionEpoch:      epoch,
			HeartbeatSequence: heartbeatSequence,
		}},
	}
}

func validEnrollment() *agentv1.EnrollRequest {
	return &agentv1.EnrollRequest{
		Request:                      &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		EnrollmentToken:              "one-time-token",
		CertificateSigningRequestDer: []byte{1},
		MachineFingerprintSha256:     make([]byte, 32),
		SupportedProtocolVersions:    versionRange(1, 0),
		Capabilities:                 &agentv1.AgentCapabilities{},
		ArtifactEncryptionPublicKey:  make([]byte, 32),
	}
}

func defaultFakeControl() *fakeControl { return &fakeControl{accepted: versionRange(1, 0)} }

func versionRange(major, minor uint32) *commonv1.ProtocolVersionRange {
	version := &commonv1.ProtocolVersion{Major: major, Minor: minor}
	return &commonv1.ProtocolVersionRange{Minimum: version, Maximum: version}
}
