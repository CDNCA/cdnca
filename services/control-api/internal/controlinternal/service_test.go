package controlinternal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeartifact"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testRequestID       = "018f47a2-5b9c-7d31-8a60-104c9c0b7101"
	testAuthorizationID = "018f47a2-5b9c-7d31-8a60-104c9c0b7102"
	testNodeID          = "018f47a2-5b9c-7d31-8a60-104c9c0b7103"
	testGatewayID       = "018f47a2-5b9c-7d31-8a60-104c9c0b7104"
	testEventID         = "018f47a2-5b9c-7d31-8a60-104c9c0b7105"
	testDeploymentID    = "018f47a2-5b9c-7d31-8a60-104c9c0b7106"
	testArtifactID      = "018f47a2-5b9c-7d31-8a60-104c9c0b7107"
)

var testNow = time.Date(2026, 7, 22, 8, 30, 0, 0, time.UTC)

var testCertificateSHA256 = [32]byte{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31,
	2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32}

type fakeIdentityService struct {
	authorizeCalls int
	completeCalls  int
	renewCalls     int
	getCalls       int

	authorize func(context.Context, nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error)
	complete  func(context.Context, nodeidentity.CompleteRequest) (nodeidentity.EnrollmentCompletion, error)
	renew     func(context.Context, nodeidentity.RenewRequest) (nodeidentity.Certificate, error)
	get       func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error)
}

func (f *fakeIdentityService) Authorize(ctx context.Context, request nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error) {
	f.authorizeCalls++
	if f.authorize != nil {
		return f.authorize(ctx, request)
	}
	return testAuthorization(), nil
}

func (f *fakeIdentityService) Complete(ctx context.Context, request nodeidentity.CompleteRequest) (nodeidentity.EnrollmentCompletion, error) {
	f.completeCalls++
	if f.complete != nil {
		return f.complete(ctx, request)
	}
	return nodeidentity.EnrollmentCompletion{Certificate: testCertificate(), ArtifactEncryptionKeyID: "x25519:test-key"}, nil
}

func (f *fakeIdentityService) Renew(ctx context.Context, request nodeidentity.RenewRequest) (nodeidentity.Certificate, error) {
	f.renewCalls++
	if f.renew != nil {
		return f.renew(ctx, request)
	}
	return testCertificate(), nil
}

func (f *fakeIdentityService) GetAuthorization(ctx context.Context, request nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
	f.getCalls++
	if f.get != nil {
		return f.get(ctx, request)
	}
	return testSnapshot("active"), nil
}

type fakeArtifactStore struct {
	calls int
	last  *controlv1.FetchArtifactRequest
	fetch func(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error)
}

func (f *fakeArtifactStore) FetchChunk(ctx context.Context, request *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
	f.calls++
	f.last = request
	if f.fetch != nil {
		return f.fetch(ctx, request)
	}
	return edgeartifact.FetchResult{EOF: true}, nil
}

type fakeFetchStream struct {
	grpc.ServerStream
	ctx       context.Context
	sendError error
	sent      []*controlv1.FetchArtifactResponse
}

func (f *fakeFetchStream) Context() context.Context { return f.ctx }

func (f *fakeFetchStream) Send(response *controlv1.FetchArtifactResponse) error {
	f.sent = append(f.sent, response)
	return f.sendError
}

type fakeAuthInfo struct{}

func (fakeAuthInfo) AuthType() string { return "not-tls" }

func TestNewServiceRequiresDependenciesAndExactGatewayIdentity(t *testing.T) {
	identity := &fakeIdentityService{}
	artifacts := &fakeArtifactStore{}

	service, err := NewService(identity, artifacts, Config{})
	if err != nil || service.gatewayWorkloadURISAN != DefaultGatewayWorkloadURISAN {
		t.Fatalf("default service = %#v, %v", service, err)
	}
	custom := "spiffe://example.internal/workload/gateway-a"
	service, err = NewService(identity, artifacts, Config{GatewayWorkloadURISAN: custom})
	if err != nil || service.gatewayWorkloadURISAN != custom {
		t.Fatalf("custom service = %#v, %v", service, err)
	}

	var typedNilIdentity *fakeIdentityService
	var typedNilArtifacts *fakeArtifactStore
	tests := []struct {
		name      string
		identity  NodeIdentityService
		artifacts ArtifactStore
		uri       string
	}{
		{name: "nil identity", artifacts: artifacts, uri: custom},
		{name: "typed nil identity", identity: typedNilIdentity, artifacts: artifacts, uri: custom},
		{name: "nil artifacts", identity: identity, uri: custom},
		{name: "typed nil artifacts", identity: identity, artifacts: typedNilArtifacts, uri: custom},
		{name: "wildcard", identity: identity, artifacts: artifacts, uri: "spiffe://example.internal/workload/*"},
		{name: "encoded wildcard", identity: identity, artifacts: artifacts, uri: "spiffe://example.internal/workload/%2A"},
		{name: "relative", identity: identity, artifacts: artifacts, uri: "gateway/control"},
		{name: "missing path", identity: identity, artifacts: artifacts, uri: "spiffe://example.internal"},
		{name: "query", identity: identity, artifacts: artifacts, uri: custom + "?role=control"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewService(test.identity, test.artifacts, Config{GatewayWorkloadURISAN: test.uri}); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("NewService() error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	var _ controlv1.ControlInternalServiceServer = service
}

func TestEveryRPCRequiresAuthenticatedGateway(t *testing.T) {
	service := newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{})
	tests := []struct {
		name string
		call func() error
	}{
		{name: "authorize", call: func() error {
			_, err := service.AuthorizeEnrollment(context.Background(), authorizeRequest())
			return err
		}},
		{name: "complete", call: func() error {
			_, err := service.CompleteEnrollment(context.Background(), completeRequest())
			return err
		}},
		{name: "renew", call: func() error { _, err := service.RenewNodeCertificate(context.Background(), renewRequest()); return err }},
		{name: "get", call: func() error { _, err := service.GetNodeAuthorization(context.Background(), getRequest()); return err }},
		{name: "fetch", call: func() error {
			return service.FetchArtifact(fetchRequest(), &fakeFetchStream{ctx: context.Background()})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCode(t, test.call(), codes.Unauthenticated)
		})
	}
}

func TestGatewayAuthenticationRejectsEveryUnverifiedOrAmbiguousIdentity(t *testing.T) {
	identity := &fakeIdentityService{}
	service := newTestService(t, identity, &fakeArtifactStore{})
	expected := testCertificateWithURI(t, DefaultGatewayWorkloadURISAN, 1)
	wrong := testCertificateWithURI(t, "spiffe://cdn-platform/gateway/other", 2)
	multiple := testCertificateWithURI(t, DefaultGatewayWorkloadURISAN, 3)
	multiple.URIs = append(multiple.URIs, mustURL(t, "spiffe://cdn-platform/gateway/other"))

	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "no peer", ctx: context.Background()},
		{name: "non TLS", ctx: peer.NewContext(context.Background(), &peer.Peer{AuthInfo: fakeAuthInfo{}})},
		{name: "no verified chains", ctx: tlsContext(nil, nil)},
		{name: "empty verified chain", ctx: tlsContext(nil, [][]*x509.Certificate{{}})},
		{name: "nil verified leaf", ctx: tlsContext(nil, [][]*x509.Certificate{{nil}})},
		{name: "missing URI SAN", ctx: tlsContext(nil, [][]*x509.Certificate{{{Raw: []byte{4}}}})},
		{name: "multiple URI SAN", ctx: tlsContext(nil, [][]*x509.Certificate{{multiple}})},
		{name: "wrong URI SAN", ctx: tlsContext(nil, [][]*x509.Certificate{{wrong}})},
		{name: "different leaves", ctx: tlsContext(nil, [][]*x509.Certificate{{expected}, {wrong}})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.AuthorizeEnrollment(test.ctx, authorizeRequest())
			assertCode(t, err, codes.Unauthenticated)
			if status.Convert(err).Message() != "verified gateway client certificate required" {
				t.Fatalf("authentication message = %q", status.Convert(err).Message())
			}
		})
	}
	if identity.authorizeCalls != 0 {
		t.Fatalf("domain authorize calls = %d, want 0", identity.authorizeCalls)
	}

	pointerTLS := credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{expected}}}}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: &pointerTLS})
	if _, err := service.AuthorizeEnrollment(ctx, authorizeRequest()); err != nil {
		t.Fatalf("pointer TLSInfo was rejected: %v", err)
	}
}

func TestNilAndUnknownRequestsAreRejectedBeforeDomainCalls(t *testing.T) {
	identity := &fakeIdentityService{}
	artifacts := &fakeArtifactStore{}
	service := newTestService(t, identity, artifacts)
	ctx := gatewayContext(t)
	stream := &fakeFetchStream{ctx: ctx}

	tests := []struct {
		name string
		call func() error
	}{
		{name: "nil authorize", call: func() error { _, err := service.AuthorizeEnrollment(ctx, nil); return err }},
		{name: "nil complete", call: func() error { _, err := service.CompleteEnrollment(ctx, nil); return err }},
		{name: "nil renew", call: func() error { _, err := service.RenewNodeCertificate(ctx, nil); return err }},
		{name: "nil get", call: func() error { _, err := service.GetNodeAuthorization(ctx, nil); return err }},
		{name: "nil fetch", call: func() error { return service.FetchArtifact(nil, stream) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertCode(t, test.call(), codes.InvalidArgument) })
	}

	authorize := authorizeRequest()
	authorize.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, err := service.AuthorizeEnrollment(ctx, authorize); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("top-level unknown field error = %v", err)
	}
	get := getRequest()
	get.Request.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if _, err := service.GetNodeAuthorization(ctx, get); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nested unknown field error = %v", err)
	}
	fetch := fetchRequest()
	fetch.Request.SentTime.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
	if err := service.FetchArtifact(fetch, stream); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("deep unknown field error = %v", err)
	}
	for _, call := range []func() error{
		func() error {
			request := authorizeRequest()
			request.GatewayInstanceId = "not-a-uuid"
			_, err := service.AuthorizeEnrollment(ctx, request)
			return err
		},
		func() error {
			request := completeRequest()
			request.GatewayInstanceId = "not-a-uuid"
			_, err := service.CompleteEnrollment(ctx, request)
			return err
		},
		func() error {
			request := renewRequest()
			request.GatewayInstanceId = "not-a-uuid"
			_, err := service.RenewNodeCertificate(ctx, request)
			return err
		},
		func() error {
			request := getRequest()
			request.GatewayInstanceId = "not-a-uuid"
			_, err := service.GetNodeAuthorization(ctx, request)
			return err
		},
		func() error {
			request := fetchRequest()
			request.GatewayInstanceId = "not-a-uuid"
			return service.FetchArtifact(request, stream)
		},
	} {
		assertCode(t, call(), codes.InvalidArgument)
	}
	if identity.authorizeCalls+identity.completeCalls+identity.renewCalls+identity.getCalls != 0 || artifacts.calls != 0 {
		t.Fatal("a domain dependency was called for an invalid request")
	}
}

func TestIdentityRPCFieldMappingAndDefensiveCopies(t *testing.T) {
	identity := &fakeIdentityService{}
	service := newTestService(t, identity, &fakeArtifactStore{})
	ctx := gatewayContextWithAddress(t, &net.TCPAddr{IP: net.ParseIP("203.0.113.99"), Port: 443})

	authorize := authorizeRequest()
	authorization := testAuthorization()
	identity.authorize = func(_ context.Context, got nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error) {
		if got.RequestID != testRequestID || got.EnrollmentToken != authorize.EnrollmentToken ||
			got.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN || got.GatewayInstanceID != testGatewayID ||
			got.PeerIP != authorize.GetPeerIp() {
			t.Fatal("authorize scalar fields were not mapped exactly")
		}
		assertClonedBytes(t, got.CertificateSigningRequestDER, authorize.CertificateSigningRequestDer, "CSR")
		assertClonedBytes(t, got.MachineFingerprintSHA256, authorize.MachineFingerprintSha256, "fingerprint")
		assertClonedBytes(t, got.ArtifactEncryptionPublicKey, authorize.ArtifactEncryptionPublicKey, "artifact key")
		if got.SupportedProtocolVersions == authorize.SupportedProtocolVersions || !proto.Equal(got.SupportedProtocolVersions, authorize.SupportedProtocolVersions) {
			t.Fatal("protocol range was not cloned")
		}
		if got.Capabilities == authorize.Capabilities || !proto.Equal(got.Capabilities, authorize.Capabilities) {
			t.Fatal("capabilities were not cloned")
		}
		got.CertificateSigningRequestDER[0] = 99
		got.Capabilities.AgentVersion = "mutated"
		return authorization, nil
	}
	authorizeResponse, err := service.AuthorizeEnrollment(ctx, authorize)
	if err != nil {
		t.Fatal(err)
	}
	if authorize.CertificateSigningRequestDer[0] != 1 || authorize.Capabilities.AgentVersion != "1.2.3" {
		t.Fatal("domain mutation reached the wire request")
	}
	if authorizeResponse.AuthorizationId != authorization.ID.String() || authorizeResponse.NodeId != authorization.NodeID.String() ||
		authorizeResponse.Replayed != authorization.Replayed || authorizeResponse.ArtifactEncryptionKeyId != authorization.ArtifactEncryptionKeyID ||
		!authorizeResponse.AuthorizationExpirationTime.AsTime().Equal(authorization.ExpiresAt) ||
		!proto.Equal(authorizeResponse.SelectedProtocolVersion, authorization.SelectedProtocolVersion) {
		t.Fatal("authorize response fields were not mapped exactly")
	}
	authorizeResponse.SelectedProtocolVersion.Major = 99
	if authorization.SelectedProtocolVersion.Major == 99 {
		t.Fatal("authorize response shares the domain protocol version")
	}

	completion := nodeidentity.EnrollmentCompletion{Certificate: testCertificate(), ArtifactEncryptionKeyID: "x25519:completion-key"}
	identity.complete = func(_ context.Context, got nodeidentity.CompleteRequest) (nodeidentity.EnrollmentCompletion, error) {
		if got.RequestID != testRequestID || got.AuthorizationID.String() != testAuthorizationID ||
			got.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN || got.GatewayInstanceID != testGatewayID {
			t.Fatal("complete fields were not mapped exactly")
		}
		return completion, nil
	}
	completeResponse, err := service.CompleteEnrollment(ctx, completeRequest())
	if err != nil {
		t.Fatal(err)
	}
	assertCertificateResponse(t, completeResponse.Certificate, completion.Certificate)
	if completeResponse.NodeId != completion.Certificate.NodeID.String() || completeResponse.ArtifactEncryptionKeyId != completion.ArtifactEncryptionKeyID {
		t.Fatal("complete response fields were not mapped exactly")
	}
	completeResponse.Certificate.LeafCertificatePem[0] = 99
	completeResponse.Certificate.IssuingChainPem[0][0] = 99
	if completion.Certificate.LeafCertificatePEM[0] == 99 || completion.Certificate.IssuingChainPEM[0][0] == 99 {
		t.Fatal("complete response shares certificate bytes with the domain")
	}

	renew := renewRequest()
	renewed := testCertificate()
	identity.renew = func(_ context.Context, got nodeidentity.RenewRequest) (nodeidentity.Certificate, error) {
		if got.RequestID != testRequestID || got.NodeID.String() != testNodeID ||
			got.CurrentSerialNumber != renew.CurrentSerialNumber || got.CurrentCertificateSHA256 != testCertificateSHA256 ||
			got.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN ||
			got.GatewayInstanceID != testGatewayID {
			t.Fatal("renewal fields were not mapped exactly")
		}
		assertClonedBytes(t, got.CertificateSigningRequestDER, renew.CertificateSigningRequestDer, "renewal CSR")
		got.CertificateSigningRequestDER[0] = 99
		got.CurrentCertificateSHA256[0] ^= 0xff
		return renewed, nil
	}
	renewResponse, err := service.RenewNodeCertificate(ctx, renew)
	if err != nil {
		t.Fatal(err)
	}
	if renew.CertificateSigningRequestDer[0] != 8 {
		t.Fatal("domain mutation reached renewal wire request")
	}
	if !bytes.Equal(renew.CurrentCertificateSha256, testCertificateSHA256[:]) {
		t.Fatal("domain mutation reached renewal wire digest")
	}
	assertCertificateResponse(t, renewResponse.Certificate, renewed)

	snapshot := testSnapshot("draining")
	identity.get = func(_ context.Context, got nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		if got.NodeID.String() != testNodeID || got.CertificateSerialNumber != "123456" ||
			got.CertificateSHA256 != testCertificateSHA256 ||
			got.GatewayWorkloadIdentity != DefaultGatewayWorkloadURISAN || got.GatewayInstanceID != testGatewayID {
			t.Fatal("authorization query fields were not mapped exactly")
		}
		got.CertificateSHA256[0] ^= 0xff
		return snapshot, nil
	}
	get := getRequest()
	getResponse, err := service.GetNodeAuthorization(ctx, get)
	if err != nil {
		t.Fatal(err)
	}
	if getResponse.NodeId != snapshot.NodeID.String() || getResponse.AuthorizationRevision != snapshot.AuthorizationRevision ||
		getResponse.AdministrativeState != controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING ||
		getResponse.ConnectionAllowed != snapshot.ConnectionAllowed || getResponse.DeploymentsAllowed != snapshot.DeploymentsAllowed ||
		getResponse.CertificateRevoked != snapshot.CertificateRevoked ||
		!getResponse.CertificateExpirationTime.AsTime().Equal(snapshot.CertificateExpirationTime) ||
		!getResponse.SnapshotExpirationTime.AsTime().Equal(snapshot.SnapshotExpirationTime) ||
		getResponse.ArtifactEncryptionKeyId != snapshot.ArtifactEncryptionKeyID ||
		getResponse.InstallationId != snapshot.InstallationID || getResponse.TenantId != snapshot.TenantID.String() ||
		len(getResponse.TelemetrySiteScopes) != 1 || getResponse.TelemetrySiteScopes[0].SiteId != snapshot.TelemetrySites[0].SiteID.String() ||
		getResponse.TelemetrySiteScopes[0].TenantId != snapshot.TenantID.String() ||
		getResponse.TelemetrySiteScopes[0].ConfigurationScopeId != snapshot.TelemetrySites[0].ConfigurationScopeID.String() ||
		getResponse.TelemetrySiteScopes[0].ConfigVersionId != snapshot.TelemetrySites[0].ConfigVersionID.String() ||
		!proto.Equal(getResponse.AcceptedProtocolVersions, snapshot.AcceptedProtocolVersions) {
		t.Fatal("authorization response fields were not mapped exactly")
	}
	getResponse.AcceptedProtocolVersions.Minimum.Major = 99
	getResponse.TelemetrySiteScopes[0].SiteId = testNodeID
	if snapshot.AcceptedProtocolVersions.Minimum.Major == 99 {
		t.Fatal("authorization response shares the domain protocol range")
	}
	if snapshot.TelemetrySites[0].SiteID.String() == testNodeID {
		t.Fatal("authorization response shares the domain telemetry site scope")
	}
	if !bytes.Equal(get.CertificateSha256, testCertificateSHA256[:]) {
		t.Fatal("domain mutation reached authorization wire digest")
	}
}

func TestRenewNodeCertificateRejectsInvalidCurrentCertificateDigestBeforeDomainCall(t *testing.T) {
	for _, test := range []struct {
		name   string
		digest []byte
	}{
		{name: "missing"},
		{name: "short", digest: make([]byte, 31)},
		{name: "long", digest: make([]byte, 33)},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := &fakeIdentityService{}
			service := newTestService(t, identity, &fakeArtifactStore{})
			request := renewRequest()
			request.CurrentCertificateSha256 = test.digest
			_, err := service.RenewNodeCertificate(gatewayContext(t), request)
			assertCode(t, err, codes.InvalidArgument)
			if identity.renewCalls != 0 {
				t.Fatalf("identity calls = %d, want 0", identity.renewCalls)
			}
		})
	}

	wrongLeaf := testCertificateSHA256
	wrongLeaf[0] ^= 0xff
	identity := &fakeIdentityService{renew: func(_ context.Context, got nodeidentity.RenewRequest) (nodeidentity.Certificate, error) {
		if got.CurrentCertificateSHA256 != wrongLeaf {
			t.Fatalf("domain digest = %x, want %x", got.CurrentCertificateSHA256, wrongLeaf)
		}
		return nodeidentity.Certificate{}, nodeidentity.ErrCertificateNotFound
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	request := renewRequest()
	request.CurrentCertificateSha256 = bytes.Clone(wrongLeaf[:])
	_, err := service.RenewNodeCertificate(gatewayContext(t), request)
	assertCode(t, err, codes.NotFound)
	if identity.renewCalls != 1 {
		t.Fatalf("identity calls = %d, want 1", identity.renewCalls)
	}
	if strings.Contains(status.Convert(err).Message(), fmt.Sprintf("%x", wrongLeaf)) {
		t.Fatal("current certificate digest leaked into renewal error")
	}
}

func TestGetNodeAuthorizationValidatesAndRedactsCertificateDigest(t *testing.T) {
	for _, test := range []struct {
		name   string
		digest []byte
	}{
		{name: "missing"},
		{name: "short", digest: make([]byte, 31)},
		{name: "long", digest: make([]byte, 33)},
	} {
		t.Run(test.name, func(t *testing.T) {
			identity := &fakeIdentityService{}
			service := newTestService(t, identity, &fakeArtifactStore{})
			request := getRequest()
			request.CertificateSha256 = test.digest
			_, err := service.GetNodeAuthorization(gatewayContext(t), request)
			assertCode(t, err, codes.InvalidArgument)
			if identity.getCalls != 0 {
				t.Fatalf("identity calls = %d, want 0", identity.getCalls)
			}
		})
	}

	tampered := testCertificateSHA256
	tampered[0] ^= 0xff
	identity := &fakeIdentityService{get: func(_ context.Context, got nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		if got.CertificateSHA256 != tampered {
			t.Fatalf("domain digest = %x, want %x", got.CertificateSHA256, tampered)
		}
		return nodeidentity.AuthorizationSnapshot{}, nodeidentity.ErrCertificateNotFound
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	request := getRequest()
	request.CertificateSha256 = bytes.Clone(tampered[:])
	_, err := service.GetNodeAuthorization(gatewayContext(t), request)
	assertCode(t, err, codes.NotFound)
	if identity.getCalls != 1 {
		t.Fatalf("identity calls = %d, want 1", identity.getCalls)
	}
	if strings.Contains(status.Convert(err).Message(), fmt.Sprintf("%x", tampered)) {
		t.Fatal("certificate digest leaked into authorization error")
	}
}

func TestAdministrativeStateMappingAndInvalidDomainResults(t *testing.T) {
	want := map[string]controlv1.NodeAdministrativeState{
		"pending":  controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_PENDING,
		"active":   controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE,
		"draining": controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DRAINING,
		"disabled": controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_DISABLED,
		"retired":  controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_RETIRED,
	}
	for value, expected := range want {
		if got, ok := nodeAdministrativeState(value); !ok || got != expected {
			t.Fatalf("nodeAdministrativeState(%q) = %v, %v", value, got, ok)
		}
	}
	if got, ok := nodeAdministrativeState("unknown"); ok || got != controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_UNSPECIFIED {
		t.Fatalf("unknown state = %v, %v", got, ok)
	}

	identity := &fakeIdentityService{get: func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		return testSnapshot("database-secret-state"), nil
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	_, err := service.GetNodeAuthorization(gatewayContext(t), getRequest())
	assertCode(t, err, codes.Internal)
	if strings.Contains(status.Convert(err).Message(), "database-secret-state") {
		t.Fatal("invalid domain state leaked into the RPC response")
	}

	tests := []struct {
		name   string
		mutate func(*nodeidentity.AuthorizationSnapshot)
	}{
		{name: "missing installation", mutate: func(value *nodeidentity.AuthorizationSnapshot) { value.InstallationID = "" }},
		{name: "site without tenant", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TenantID = uuid.Nil
			value.TelemetrySites[0].TenantID = uuid.Nil
		}},
		{name: "cross tenant site", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TelemetrySites[0].TenantID = uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7192")
		}},
		{name: "site without configuration scope", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TelemetrySites[0].ConfigurationScopeID = uuid.Nil
		}},
		{name: "multi-scope scope maps to two tenants", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TenantID = uuid.Nil
			second := value.TelemetrySites[0]
			second.SiteID = uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7199")
			second.TenantID = uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7198")
			value.TelemetrySites = append(value.TelemetrySites, second)
		}},
		{name: "missing config version", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TelemetrySites[0].ConfigVersionID = uuid.Nil
		}},
		{name: "duplicate site config tuple", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TelemetrySites = append(value.TelemetrySites, value.TelemetrySites[0])
		}},
		{name: "site scope overflow", mutate: func(value *nodeidentity.AuthorizationSnapshot) {
			value.TelemetrySites = make([]nodeidentity.TelemetrySiteScope, nodeidentity.MaxTelemetrySiteScopes+1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := testSnapshot("active")
			test.mutate(&invalid)
			identity := &fakeIdentityService{get: func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
				return invalid, nil
			}}
			service := newTestService(t, identity, &fakeArtifactStore{})
			_, err := service.GetNodeAuthorization(gatewayContext(t), getRequest())
			assertCode(t, err, codes.Internal)
		})
	}
}

func TestGetNodeAuthorizationMapsMultiScopeTelemetrySites(t *testing.T) {
	snapshot := testSnapshot("active")
	snapshot.TenantID = uuid.Nil
	second := nodeidentity.TelemetrySiteScope{
		SiteID:               uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7199"),
		TenantID:             uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7198"),
		ConfigurationScopeID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7197"),
		ConfigVersionID:      uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7196"),
	}
	snapshot.TelemetrySites = append(snapshot.TelemetrySites, second)
	identity := &fakeIdentityService{get: func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		return snapshot, nil
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	response, err := service.GetNodeAuthorization(gatewayContext(t), getRequest())
	if err != nil {
		t.Fatal(err)
	}
	if response.TenantId != "" || len(response.TelemetrySiteScopes) != 2 {
		t.Fatalf("multi-scope authorization = %v", response)
	}
	for index, site := range snapshot.TelemetrySites {
		got := response.TelemetrySiteScopes[index]
		if got.SiteId != site.SiteID.String() || got.TenantId != site.TenantID.String() ||
			got.ConfigurationScopeId != site.ConfigurationScopeID.String() ||
			got.ConfigVersionId != site.ConfigVersionID.String() {
			t.Fatalf("multi-scope site %d = %v, want %#v", index, got, site)
		}
	}
}

func TestDomainErrorMappingIsStableAndRedacted(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "node invalid", err: nodeidentity.ErrInvalidInput, code: codes.InvalidArgument},
		{name: "artifact invalid", err: edgeartifact.ErrInvalidRequest, code: codes.InvalidArgument},
		{name: "invalid token", err: nodeidentity.ErrInvalidToken, code: codes.Unauthenticated},
		{name: "expired token", err: nodeidentity.ErrTokenExpired, code: codes.Unauthenticated},
		{name: "consumed token", err: nodeidentity.ErrTokenConsumed, code: codes.Unauthenticated},
		{name: "identity conflict", err: nodeidentity.ErrIdempotencyConflict, code: codes.AlreadyExists},
		{name: "renewal conflict", err: nodeidentity.ErrRenewalConflict, code: codes.AlreadyExists},
		{name: "artifact conflict", err: edgeartifact.ErrIdempotencyConflict, code: codes.AlreadyExists},
		{name: "enrollment denied", err: nodeidentity.ErrEnrollmentDenied, code: codes.FailedPrecondition},
		{name: "authorization expired", err: nodeidentity.ErrAuthorizationExpired, code: codes.FailedPrecondition},
		{name: "node state", err: nodeidentity.ErrNodeStateDenied, code: codes.FailedPrecondition},
		{name: "request failed", err: edgeartifact.ErrRequestFailed, code: codes.FailedPrecondition},
		{name: "deployment ineligible", err: edgeartifact.ErrDeploymentIneligible, code: codes.FailedPrecondition},
		{name: "gateway binding", err: nodeidentity.ErrGatewayBinding, code: codes.PermissionDenied},
		{name: "certificate revoked", err: nodeidentity.ErrCertificateRevoked, code: codes.PermissionDenied},
		{name: "artifact binding", err: edgeartifact.ErrBindingConflict, code: codes.PermissionDenied},
		{name: "authorization missing", err: nodeidentity.ErrAuthorizationNotFound, code: codes.NotFound},
		{name: "certificate missing", err: nodeidentity.ErrCertificateNotFound, code: codes.NotFound},
		{name: "renewal too early", err: nodeidentity.ErrRenewalTooEarly, code: codes.FailedPrecondition},
		{name: "issuance in progress", err: nodeidentity.ErrIssuanceInProgress, code: codes.Aborted},
		{name: "fetch in progress", err: edgeartifact.ErrRequestInProgress, code: codes.Aborted},
		{name: "offset", err: edgeartifact.ErrOffsetOutOfRange, code: codes.OutOfRange},
		{name: "integrity", err: edgeartifact.ErrArtifactIntegrity, code: codes.DataLoss},
		{name: "signing", err: nodeidentity.ErrSigningFailed, code: codes.Unavailable},
		{name: "persistence", err: nodeidentity.ErrPersistence, code: codes.Unavailable},
		{name: "storage", err: edgeartifact.ErrStorage, code: codes.Unavailable},
		{name: "invalid certificate", err: nodeidentity.ErrCertificateInvalid, code: codes.Internal},
		{name: "unknown", err: errors.New("postgres://admin:secret@db/internal SQL SELECT token"), code: codes.Internal},
		{name: "canceled", err: fmt.Errorf("wrapped: %w", context.Canceled), code: codes.Canceled},
		{name: "deadline", err: fmt.Errorf("wrapped: %w", context.DeadlineExceeded), code: codes.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapped := rpcError(test.err)
			assertCode(t, mapped, test.code)
			message := status.Convert(mapped).Message()
			for _, secret := range []string{"postgres://", "secret", "SELECT", "token"} {
				if strings.Contains(message, secret) {
					t.Fatalf("mapped error leaked %q: %q", secret, message)
				}
			}
		})
	}
	if rpcError(nil) != nil {
		t.Fatal("rpcError(nil) must be nil")
	}
}

func TestRenewalRetryErrorsExposeStableMachineDetails(t *testing.T) {
	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		cause      error
		reason     string
		retryAt    time.Time
		retryAfter time.Duration
	}{
		{name: "too early", cause: nodeidentity.ErrRenewalTooEarly, reason: nodeidentity.RenewalReasonTooEarly,
			retryAt: now.Add(7*time.Minute + 21*time.Second), retryAfter: 7*time.Minute + 21*time.Second},
		{name: "expired and eligible", cause: nodeidentity.ErrAuthorizationExpired, reason: nodeidentity.RenewalReasonRequestExpired,
			retryAt: now.Add(-time.Minute), retryAfter: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mapped := renewalRPCError(&nodeidentity.RenewalRetryError{
				Cause: test.cause, Reason: test.reason, RetryAt: test.retryAt, RetryAfter: test.retryAfter,
			})
			assertCode(t, mapped, codes.FailedPrecondition)
			var gotInfo *errdetails.ErrorInfo
			var gotRetry *errdetails.RetryInfo
			for _, detail := range status.Convert(mapped).Details() {
				switch typed := detail.(type) {
				case *errdetails.ErrorInfo:
					gotInfo = typed
				case *errdetails.RetryInfo:
					gotRetry = typed
				}
			}
			if gotInfo == nil || gotInfo.GetReason() != test.reason || gotInfo.GetDomain() != renewalErrorDomain ||
				gotInfo.GetMetadata()["retry_at"] != test.retryAt.UTC().Truncate(time.Second).Format(time.RFC3339) {
				t.Fatalf("ErrorInfo = %#v", gotInfo)
			}
			if gotRetry == nil || gotRetry.GetRetryDelay() == nil || gotRetry.GetRetryDelay().AsDuration() != test.retryAfter {
				t.Fatalf("RetryInfo = %#v", gotRetry)
			}
			if !errors.Is(mapped, test.cause) && strings.Contains(status.Convert(mapped).Message(), test.cause.Error()) {
				t.Fatal("renewal RPC message exposed its internal cause")
			}
		})
	}
	plain := renewalRPCError(nodeidentity.ErrAuthorizationExpired)
	if len(status.Convert(plain).Details()) != 0 {
		t.Fatalf("plain authorization error unexpectedly carried renewal details: %#v", status.Convert(plain).Details())
	}
}

func TestFetchArtifactSendsOneClonedChunkAndPreservesRangeIdentity(t *testing.T) {
	request := fetchRequest()
	domainResponse := &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: testRequestID, ArtifactId: testArtifactID, Offset: 4096,
		Data: []byte{1, 2, 3}, ChunkSha256: make([]byte, 32), TotalSizeBytes: 8192,
	}}
	artifacts := &fakeArtifactStore{fetch: func(_ context.Context, got *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
		if got == request || got.Request == request.Request || !proto.Equal(got, request) {
			t.Fatal("fetch request was not cloned exactly")
		}
		got.EventId = "mutated"
		return edgeartifact.FetchResult{Response: domainResponse}, nil
	}}
	service := newTestService(t, &fakeIdentityService{}, artifacts)
	stream := &fakeFetchStream{ctx: gatewayContext(t)}
	if err := service.FetchArtifact(request, stream); err != nil {
		t.Fatal(err)
	}
	if request.EventId != testEventID || artifacts.calls != 1 || len(stream.sent) != 1 {
		t.Fatalf("fetch calls/sends = %d/%d, event = %q", artifacts.calls, len(stream.sent), request.EventId)
	}
	if stream.sent[0] == domainResponse || stream.sent[0].Chunk == domainResponse.Chunk || !proto.Equal(stream.sent[0], domainResponse) {
		t.Fatal("fetch response was not cloned exactly")
	}
	stream.sent[0].Chunk.Data[0] = 99
	if domainResponse.Chunk.Data[0] == 99 {
		t.Fatal("sent response shares bytes with artifact store response")
	}
}

func TestFetchArtifactEOFAndInvalidResultsNeverSendEmptyChunks(t *testing.T) {
	request := fetchRequest()
	validResponse := &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: testRequestID, ArtifactId: testArtifactID, Offset: 4096, Data: []byte{1},
	}}
	tests := []struct {
		name      string
		result    edgeartifact.FetchResult
		wantCode  codes.Code
		wantSends int
	}{
		{name: "EOF", result: edgeartifact.FetchResult{EOF: true}, wantCode: codes.OK},
		{name: "EOF with response", result: edgeartifact.FetchResult{EOF: true, Response: validResponse}, wantCode: codes.Internal},
		{name: "missing response", result: edgeartifact.FetchResult{}, wantCode: codes.Internal},
		{name: "missing chunk", result: edgeartifact.FetchResult{Response: &controlv1.FetchArtifactResponse{}}, wantCode: codes.Internal},
		{name: "empty chunk", result: edgeartifact.FetchResult{Response: &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{RequestId: testRequestID, ArtifactId: testArtifactID, Offset: 4096}}}, wantCode: codes.Internal},
		{name: "wrong request", result: edgeartifact.FetchResult{Response: cloneChunkWith(validResponse, func(chunk *agentv1.ArtifactChunk) { chunk.RequestId = testEventID })}, wantCode: codes.Internal},
		{name: "wrong artifact", result: edgeartifact.FetchResult{Response: cloneChunkWith(validResponse, func(chunk *agentv1.ArtifactChunk) { chunk.ArtifactId = testEventID })}, wantCode: codes.Internal},
		{name: "wrong offset", result: edgeartifact.FetchResult{Response: cloneChunkWith(validResponse, func(chunk *agentv1.ArtifactChunk) { chunk.Offset++ })}, wantCode: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifacts := &fakeArtifactStore{fetch: func(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
				return test.result, nil
			}}
			service := newTestService(t, &fakeIdentityService{}, artifacts)
			stream := &fakeFetchStream{ctx: gatewayContext(t)}
			err := service.FetchArtifact(request, stream)
			assertCode(t, err, test.wantCode)
			if len(stream.sent) != test.wantSends {
				t.Fatalf("sent chunks = %d, want %d", len(stream.sent), test.wantSends)
			}
		})
	}
}

func TestFetchArtifactMapsStoreSendAndCancellationErrors(t *testing.T) {
	request := fetchRequest()
	response := &controlv1.FetchArtifactResponse{Chunk: &agentv1.ArtifactChunk{
		RequestId: testRequestID, ArtifactId: testArtifactID, Offset: 4096, Data: []byte{1},
	}}
	service := newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{fetch: func(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
		return edgeartifact.FetchResult{}, fmt.Errorf("%w: nats://user:password@internal", edgeartifact.ErrStorage)
	}})
	stream := &fakeFetchStream{ctx: gatewayContext(t)}
	err := service.FetchArtifact(request, stream)
	assertCode(t, err, codes.Unavailable)
	if strings.Contains(status.Convert(err).Message(), "nats://") || len(stream.sent) != 0 {
		t.Fatalf("store error leaked or sent data: %v", err)
	}

	service = newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{fetch: func(context.Context, *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
		return edgeartifact.FetchResult{Response: response}, nil
	}})
	stream = &fakeFetchStream{ctx: gatewayContext(t), sendError: errors.New("transport secret")}
	err = service.FetchArtifact(request, stream)
	assertCode(t, err, codes.Internal)
	if strings.Contains(status.Convert(err).Message(), "transport secret") || len(stream.sent) != 1 {
		t.Fatalf("send error leaked or send count changed: %v", err)
	}

	canceled, cancel := context.WithCancel(gatewayContext(t))
	cancel()
	service = newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{fetch: func(ctx context.Context, _ *controlv1.FetchArtifactRequest) (edgeartifact.FetchResult, error) {
		return edgeartifact.FetchResult{}, ctx.Err()
	}})
	err = service.FetchArtifact(request, &fakeFetchStream{ctx: canceled})
	assertCode(t, err, codes.Canceled)
}

func newTestService(t *testing.T, identity NodeIdentityService, artifacts ArtifactStore) *Service {
	t.Helper()
	service, err := NewService(identity, artifacts, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func metadata() *commonv1.RequestMetadata {
	return &commonv1.RequestMetadata{RequestId: testRequestID, SentTime: timestamppb.New(testNow)}
}

func authorizeRequest() *controlv1.AuthorizeEnrollmentRequest {
	peerIP := "192.0.2.10"
	return &controlv1.AuthorizeEnrollmentRequest{
		Request: metadata(), EnrollmentToken: "sensitive-enrollment-token",
		CertificateSigningRequestDer: []byte{1, 2, 3}, MachineFingerprintSha256: make([]byte, 32),
		SupportedProtocolVersions: testProtocolRange(),
		Capabilities:              &agentv1.AgentCapabilities{AgentVersion: "1.2.3", BuildId: "build-1", OperatingSystem: "linux", Architecture: "amd64"},
		GatewayInstanceId:         testGatewayID, PeerIp: &peerIP, ArtifactEncryptionPublicKey: make([]byte, 32),
	}
}

func completeRequest() *controlv1.CompleteEnrollmentRequest {
	return &controlv1.CompleteEnrollmentRequest{Request: metadata(), AuthorizationId: testAuthorizationID, GatewayInstanceId: testGatewayID}
}

func renewRequest() *controlv1.RenewNodeCertificateRequest {
	return &controlv1.RenewNodeCertificateRequest{
		Request: metadata(), NodeId: testNodeID, CurrentSerialNumber: "123456",
		CurrentCertificateSha256:     bytes.Clone(testCertificateSHA256[:]),
		CertificateSigningRequestDer: []byte{8, 9, 10}, GatewayInstanceId: testGatewayID,
	}
}

func getRequest() *controlv1.GetNodeAuthorizationRequest {
	return &controlv1.GetNodeAuthorizationRequest{
		Request: metadata(), NodeId: testNodeID, CertificateSerialNumber: "123456",
		CertificateSha256: bytes.Clone(testCertificateSHA256[:]), GatewayInstanceId: testGatewayID,
	}
}

func fetchRequest() *controlv1.FetchArtifactRequest {
	return &controlv1.FetchArtifactRequest{
		Request: metadata(), EventId: testEventID, NodeId: testNodeID, DeploymentId: testDeploymentID,
		Attempt: 2, ArtifactId: testArtifactID, Offset: 4096, GatewayInstanceId: testGatewayID,
	}
}

func testProtocolRange() *commonv1.ProtocolVersionRange {
	return &commonv1.ProtocolVersionRange{
		Minimum: &commonv1.ProtocolVersion{Major: 1, Minor: 0},
		Maximum: &commonv1.ProtocolVersion{Major: 1, Minor: 2},
	}
}

func testAuthorization() nodeidentity.Authorization {
	return nodeidentity.Authorization{
		ID: uuid.MustParse(testAuthorizationID), NodeID: uuid.MustParse(testNodeID),
		CertificateSigningRequestSHA256: [32]byte{1, 2, 3},
		SelectedProtocolVersion:         &commonv1.ProtocolVersion{Major: 1, Minor: 1},
		ExpiresAt:                       testNow.Add(5 * time.Minute), ArtifactEncryptionKeyID: "x25519:test-key", Replayed: true,
	}
}

func testCertificate() nodeidentity.Certificate {
	return nodeidentity.Certificate{
		ID: uuid.MustParse(testAuthorizationID), NodeID: uuid.MustParse(testNodeID),
		LeafCertificatePEM: []byte("leaf"), IssuingChainPEM: [][]byte{[]byte("issuer-one"), []byte("issuer-two")},
		SerialNumber: "123456", NotBefore: testNow.Add(-time.Minute), NotAfter: testNow.Add(24 * time.Hour), RenewalAt: testNow.Add(18 * time.Hour),
	}
}

func testSnapshot(state string) nodeidentity.AuthorizationSnapshot {
	tenantID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7190")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7191")
	configVersionID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7192")
	scopeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7193")
	return nodeidentity.AuthorizationSnapshot{
		NodeID: uuid.MustParse(testNodeID), InstallationID: "installation-test", TenantID: tenantID,
		TelemetrySites: []nodeidentity.TelemetrySiteScope{{
			SiteID: siteID, TenantID: tenantID, ConfigurationScopeID: scopeID, ConfigVersionID: configVersionID,
		}},
		AuthorizationRevision: 42, AdministrativeState: state,
		ConnectionAllowed: true, DeploymentsAllowed: false, CertificateRevoked: false,
		CertificateExpirationTime: testNow.Add(24 * time.Hour), AcceptedProtocolVersions: testProtocolRange(),
		SnapshotExpirationTime: testNow.Add(time.Minute), ArtifactEncryptionKeyID: "x25519:test-key",
	}
}

func gatewayContext(t *testing.T) context.Context {
	t.Helper()
	return gatewayContextWithAddress(t, nil)
}

func gatewayContextWithAddress(t *testing.T, address net.Addr) context.Context {
	t.Helper()
	leaf := testCertificateWithURI(t, DefaultGatewayWorkloadURISAN, 1)
	return tlsContext(address, [][]*x509.Certificate{{leaf}})
}

func tlsContext(address net.Addr, chains [][]*x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr:     address,
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{VerifiedChains: chains}},
	})
}

func testCertificateWithURI(t *testing.T, raw string, marker byte) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{Raw: []byte{marker}, URIs: []*url.URL{mustURL(t, raw)}}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("status code = %s (%v), want %s", got, err, want)
	}
}

func assertClonedBytes(t *testing.T, got, source []byte, name string) {
	t.Helper()
	if !bytes.Equal(got, source) || len(got) == 0 || &got[0] == &source[0] {
		t.Fatalf("%s was not cloned exactly", name)
	}
}

func assertCertificateResponse(t *testing.T, got *agentv1.CertificateBundle, want nodeidentity.Certificate) {
	t.Helper()
	if got == nil || !bytes.Equal(got.LeafCertificatePem, want.LeafCertificatePEM) || len(got.IssuingChainPem) != len(want.IssuingChainPEM) ||
		got.SerialNumber != want.SerialNumber || !got.NotBeforeTime.AsTime().Equal(want.NotBefore) ||
		!got.ExpirationTime.AsTime().Equal(want.NotAfter) || !got.RenewalTime.AsTime().Equal(want.RenewalAt) {
		t.Fatal("certificate response fields were not mapped exactly")
	}
	for index := range want.IssuingChainPEM {
		if !bytes.Equal(got.IssuingChainPem[index], want.IssuingChainPEM[index]) {
			t.Fatalf("issuing chain %d differs", index)
		}
	}
}

func cloneChunkWith(source *controlv1.FetchArtifactResponse, mutate func(*agentv1.ArtifactChunk)) *controlv1.FetchArtifactResponse {
	cloned := proto.Clone(source).(*controlv1.FetchArtifactResponse)
	mutate(cloned.Chunk)
	return cloned
}

// A refusal the node cannot fix itself (Unavailable, Internal) is logged with
// the RPC, the node and the underlying error; the RPC response stays generic.
func TestGetNodeAuthorizationLogsUnderlyingFailure(t *testing.T) {
	identity := &fakeIdentityService{get: func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		return nodeidentity.AuthorizationSnapshot{}, fmt.Errorf("%w: configuration scope 0190 cannot carry telemetry: platform_scope", nodeidentity.ErrPersistence)
	}}
	service := newTestService(t, identity, &fakeArtifactStore{})
	var logs bytes.Buffer
	service.logger = slog.New(slog.NewTextHandler(&logs, nil))
	request := getRequest()
	_, err := service.GetNodeAuthorization(gatewayContext(t), request)
	assertCode(t, err, codes.Unavailable)
	if strings.Contains(status.Convert(err).Message(), "platform_scope") {
		t.Fatal("underlying error leaked into the RPC response")
	}
	line := logs.String()
	for _, want := range []string{"level=WARN", "rpc=GetNodeAuthorization", "node_id=" + request.GetNodeId(), "code=Unavailable", "platform_scope"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q lacks %q", line, want)
		}
	}

	logs.Reset()
	identity.get = func(context.Context, nodeidentity.GetAuthorizationRequest) (nodeidentity.AuthorizationSnapshot, error) {
		return nodeidentity.AuthorizationSnapshot{}, nodeidentity.ErrCertificateNotFound
	}
	_, err = service.GetNodeAuthorization(gatewayContext(t), request)
	assertCode(t, err, codes.NotFound)
	if logs.Len() != 0 {
		t.Fatalf("an expected refusal was logged: %q", logs.String())
	}
}
