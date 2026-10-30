package gateway

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recoveringControl struct {
	*fakeControl
	mu       sync.Mutex
	recovery *controlv1.RecoverNodeCertificateRequest
	err      error
}

func (control *recoveringControl) RecoverNodeCertificate(_ context.Context, request *controlv1.RecoverNodeCertificateRequest) (*controlv1.RecoverNodeCertificateResponse, error) {
	control.mu.Lock()
	defer control.mu.Unlock()
	control.recovery = proto.Clone(request).(*controlv1.RecoverNodeCertificateRequest)
	if control.err != nil {
		return nil, control.err
	}
	return &controlv1.RecoverNodeCertificateResponse{Certificate: &agentv1.CertificateBundle{LeafCertificatePem: []byte("recovered")}}, nil
}

func validRecovery() *agentv1.RecoverCertificateRequest {
	return &agentv1.RecoverCertificateRequest{
		Request:               &commonv1.RequestMetadata{RequestId: uuid.NewString(), SentTime: timestamppb.Now()},
		NodeId:                testNodeID,
		ExpiredCertificateDer: []byte{1, 2, 3}, CertificateSigningRequestDer: []byte{4, 5},
		Nonce: bytes.Repeat([]byte{7}, 32), Signature: bytes.Repeat([]byte{9}, 64),
	}
}

// GW-02: an expired node holds no valid client certificate, so recovery is
// served on the enrollment listener (server TLS only) and forwarded unchanged
// with the Gateway's instance and the observed peer; the mTLS listener does
// not expose it.
func TestRecoverCertificateOnEnrollmentListener(t *testing.T) {
	control := &recoveringControl{fakeControl: defaultFakeControl()}
	servers := startTestServers(t, control)
	connection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer connection.Close()
	client := agentv1.NewAgentGatewayServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := validRecovery()
	response, err := client.RecoverCertificate(ctx, request)
	if err != nil || string(response.GetCertificate().GetLeafCertificatePem()) != "recovered" {
		t.Fatalf("RecoverCertificate() = %v, %v", response, err)
	}
	control.mu.Lock()
	forwarded := control.recovery
	control.mu.Unlock()
	if forwarded == nil || !proto.Equal(forwarded.Recovery, request) || forwarded.GatewayInstanceId == "" ||
		forwarded.GetPeerIp() != "127.0.0.1" {
		t.Fatalf("forwarded = %v", forwarded)
	}

	for name, mutate := range map[string]func(*agentv1.RecoverCertificateRequest){
		"short nonce":     func(request *agentv1.RecoverCertificateRequest) { request.Nonce = request.Nonce[:31] },
		"short signature": func(request *agentv1.RecoverCertificateRequest) { request.Signature = request.Signature[:63] },
		"no sent time":    func(request *agentv1.RecoverCertificateRequest) { request.Request.SentTime = nil },
		"bad node id":     func(request *agentv1.RecoverCertificateRequest) { request.NodeId = "node" },
		"no certificate":  func(request *agentv1.RecoverCertificateRequest) { request.ExpiredCertificateDer = nil },
	} {
		invalid := validRecovery()
		mutate(invalid)
		if _, err := client.RecoverCertificate(ctx, invalid); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: code = %v, want InvalidArgument", name, status.Code(err))
		}
	}
	control.mu.Lock()
	control.err = status.Error(codes.PermissionDenied, "node certificate recovery is not authorized")
	control.mu.Unlock()
	if _, err := client.RecoverCertificate(ctx, validRecovery()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("refused recovery code = %v, want PermissionDenied", status.Code(err))
	}

	mtls := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	defer mtls.Close()
	if _, err := agentv1.NewAgentGatewayServiceClient(mtls).RecoverCertificate(ctx, validRecovery()); status.Code(err) != codes.Unimplemented {
		t.Fatalf("mTLS listener RecoverCertificate code = %v, want Unimplemented", status.Code(err))
	}
}

func TestRecoverCertificateWithoutRecoveryControlPlane(t *testing.T) {
	servers := startTestServers(t, defaultFakeControl())
	connection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer connection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := agentv1.NewAgentGatewayServiceClient(connection).RecoverCertificate(ctx, validRecovery()); status.Code(err) != codes.Unimplemented {
		t.Fatalf("code = %v, want Unimplemented", status.Code(err))
	}
}
