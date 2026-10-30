package controlinternal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestControlInternalSessionFacts(t *testing.T) {
	request := getRequest()
	request.SessionFacts = &controlv1.GatewaySessionFactsV1{SchemaVersion: 1, NodeId: testNodeID, SessionEpoch: 42, CertificateSha256: bytes.Clone(testCertificateSHA256[:]), SelectedProtocolVersion: &commonv1.ProtocolVersion{Major: 1}, ArtifactEncryptionKeyId: "x25519:test-key", Capabilities: &agentv1.AgentCapabilities{AgentVersion: "1.0.22", BuildId: "build", OperatingSystem: "linux", Architecture: "amd64", Features: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}}}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(request.SessionFacts)
	digest := sha256.Sum256(encoded)
	identity := &fakeIdentityService{get: func(_ context.Context, value nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		if value.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN || !proto.Equal(value.SessionFacts, request.SessionFacts) {
			t.Fatal("missing authenticated workload/facts")
		}
		snapshot := testSnapshot("active")
		snapshot.SessionFactsSHA256 = bytes.Clone(digest[:])
		return snapshot, nil
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	for _, ctx := range []context.Context{context.Background(), tlsContext(nil, nil), tlsContext(nil, [][]*x509.Certificate{{testCertificateWithURI(t, "spiffe://cdn-platform/node/"+testNodeID, 1)}})} {
		if _, err := service.GetNodeAuthorization(ctx, request); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("unauthenticated writer: %v", err)
		}
	}
	if identity.getCalls != 0 {
		t.Fatal("untrusted peer reached identity store")
	}
	result, err := service.GetNodeAuthorization(gatewayContext(t), request)
	if err != nil || !bytes.Equal(result.GetSessionFactsSha256(), digest[:]) {
		t.Fatalf("receipt mapping: %v", err)
	}
	deployments := true
	identity.get = func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		snapshot := testSnapshot("active")
		snapshot.DeploymentsAllowed = deployments
		return snapshot, nil
	}
	if _, err := service.GetNodeAuthorization(gatewayContext(t), request); status.Code(err) != codes.Internal {
		t.Fatalf("new Control missing committed receipt: %v", err)
	}
	// Paused deployments may record no facts: no receipt, no upgrade authority.
	deployments = false
	if result, err := service.GetNodeAuthorization(gatewayContext(t), request); err != nil || len(result.GetSessionFactsSha256()) != 0 {
		t.Fatalf("paused deployments without receipt: %v", err)
	}
}
