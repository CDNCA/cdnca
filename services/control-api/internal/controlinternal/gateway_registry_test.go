package controlinternal

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeidentity"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
)

type fakeGatewayRegistry struct {
	authorized map[string]bool // "<id>/<serial>"
	disabled   bool            // every authorized Gateway is within the disable grace period
	calls      int
	ready      []string
	renewKind  string
}

func (f *fakeGatewayRegistry) AuthorizeGateway(_ context.Context, id uuid.UUID, serial string, digest [32]byte) (bool, error) {
	f.calls++
	if f.authorized[id.String()+"/"+serial] {
		return f.disabled, nil
	}
	return false, errGatewayRefused
}

func (f *fakeGatewayRegistry) MarkReady(_ context.Context, id uuid.UUID, version string) error {
	f.ready = append(f.ready, id.String()+"@"+version)
	return nil
}

func (f *fakeGatewayRegistry) Renew(_ context.Context, id uuid.UUID, kind string, csr []byte) (GatewayCertificate, error) {
	f.renewKind = kind
	return GatewayCertificate{PEM: []byte("pem"), NotAfter: testNow.Add(30 * 24 * 3600e9), RenewAt: testNow.Add(15 * 24 * 3600e9)}, nil
}

func (f *fakeGatewayRegistry) InstallationID() string { return "00000000-0000-4000-8000-0000000000aa" }

func boundGatewayContext(t *testing.T, id uuid.UUID, serial int64) context.Context {
	t.Helper()
	leaf := testCertificateWithURI(t, "spiffe://cdn-platform/gateway/"+id.String(), byte(serial))
	leaf.SerialNumber = big.NewInt(serial)
	return tlsContext(nil, [][]*x509.Certificate{{leaf}})
}

func TestBoundGatewayIdentityIsCheckedAgainstTheRegistry(t *testing.T) {
	gatewayID := uuid.MustParse(testGatewayID)
	registry := &fakeGatewayRegistry{authorized: map[string]bool{gatewayID.String() + "/1c": true}}
	var seenWorkload string
	identity := &fakeIdentityService{authorize: func(_ context.Context, request nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error) {
		seenWorkload = request.GatewayWorkloadIdentity
		return testAuthorization(), nil
	}}
	config := DefaultConfig()
	config.Gateways = registry
	service, err := NewService(identity, &fakeArtifactStore{}, config)
	if err != nil {
		t.Fatal(err)
	}

	// Bound, unrevoked certificate whose gateway_id equals the request's
	// instance ID: accepted, and the node identity layer sees the shared
	// Gateway service identity (nodes may move between Gateways).
	if _, err := service.AuthorizeEnrollment(boundGatewayContext(t, gatewayID, 0x1c), authorizeRequest()); err != nil {
		t.Fatalf("bound gateway rejected: %v", err)
	}
	if seenWorkload != DefaultGatewayWorkloadURISAN {
		t.Fatalf("workload passed to node identity = %q", seenWorkload)
	}

	other := uuid.New()
	for name, ctx := range map[string]context.Context{
		"revoked or unknown serial":      boundGatewayContext(t, gatewayID, 0x1d),
		"instance ID of another gateway": boundGatewayContext(t, other, 0x1c),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.AuthorizeEnrollment(ctx, authorizeRequest())
			assertCode(t, err, codes.Unauthenticated)
		})
	}

	// Without a registry (all mode, no standalone access) a per-gateway SAN is refused.
	plain := newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{})
	_, err = plain.AuthorizeEnrollment(boundGatewayContext(t, gatewayID, 0x1c), authorizeRequest())
	assertCode(t, err, codes.Unauthenticated)
}

func TestReportGatewayReadyAndRenew(t *testing.T) {
	gatewayID := uuid.MustParse(testGatewayID)
	registry := &fakeGatewayRegistry{authorized: map[string]bool{gatewayID.String() + "/1c": true}}
	config := DefaultConfig()
	config.Gateways = registry
	config.InstallationID = registry.InstallationID()
	service, err := NewService(&fakeIdentityService{}, &fakeArtifactStore{}, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := boundGatewayContext(t, gatewayID, 0x1c)
	response, err := service.ReportGatewayReady(ctx, &controlv1.ReportGatewayReadyRequest{Request: metadata(), GatewayInstanceId: testGatewayID, Version: "1.0.35"})
	if err != nil || response.GetInstallationId() != registry.InstallationID() || len(registry.ready) != 1 {
		t.Fatalf("ready = %v %v %v", response, err, registry.ready)
	}
	// The co-located Gateway (shared SAN) learns the installation ID too, and
	// is not recorded in the registry.
	local, err := service.ReportGatewayReady(gatewayContext(t), &controlv1.ReportGatewayReadyRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
	if err != nil || local.GetInstallationId() != registry.InstallationID() || len(registry.ready) != 1 {
		t.Fatalf("co-located ready = %v %v %v", local, err, registry.ready)
	}

	renewed, err := service.RenewGatewayCertificate(ctx, &controlv1.RenewGatewayCertificateRequest{Request: metadata(),
		GatewayInstanceId: testGatewayID, Kind: "client", CertificateSigningRequestDer: []byte{1}})
	if err != nil || string(renewed.GetCertificatePem()) != "pem" || registry.renewKind != "client" {
		t.Fatalf("renew = %v %v", renewed, err)
	}
	_, err = service.RenewGatewayCertificate(gatewayContext(t), &controlv1.RenewGatewayCertificateRequest{Request: metadata(),
		GatewayInstanceId: testGatewayID, Kind: "client", CertificateSigningRequestDer: []byte{1}})
	assertCode(t, err, codes.FailedPrecondition)
}

func (f *fakeGatewayRegistry) Settings(context.Context) (GatewaySettings, error) {
	return GatewaySettings{
		TrustedProxies:   []GatewayTrustedProxy{{CIDR: "173.245.48.0/20", Header: "CF-Connecting-IP"}},
		Endpoints: []GatewayEndpoint{{Address: "gw.example.com:21444", ServerName: "gw.example.com", Transport: "grpc",
			EnrollmentAddress: "gw.example.com:21443"}},
		EndpointsVersion: "v1",
	}, nil
}

func TestGetGatewaySettingsServesEveryGateway(t *testing.T) {
	gatewayID := uuid.MustParse(testGatewayID)
	registry := &fakeGatewayRegistry{authorized: map[string]bool{gatewayID.String() + "/1c": true}}
	config := DefaultConfig()
	config.Gateways = registry
	service, err := NewService(&fakeIdentityService{}, &fakeArtifactStore{}, config)
	if err != nil {
		t.Fatal(err)
	}
	for name, ctx := range map[string]context.Context{"bound": boundGatewayContext(t, gatewayID, 0x1c), "co-located": gatewayContext(t)} {
		response, err := service.GetGatewaySettings(ctx, &controlv1.GetGatewaySettingsRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
		if err != nil || len(response.GetTrustedProxies()) != 1 || response.GetTrustedProxies()[0].GetHeader() != "CF-Connecting-IP" ||
			len(response.GetEndpoints()) != 1 || response.GetEndpoints()[0].GetTransport() != "grpc" || response.GetEndpointsVersion() != "v1" ||
			response.GetEndpoints()[0].GetEnrollmentAddress() != "gw.example.com:21443" || response.GetDisabled() {
			t.Fatalf("%s: %v %v", name, response, err)
		}
	}
	_, err = service.GetGatewaySettings(boundGatewayContext(t, gatewayID, 0x1d), &controlv1.GetGatewaySettingsRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
	assertCode(t, err, codes.Unauthenticated)
	// No registry (no Gateway CA configured): nothing to publish.
	plain := newTestService(t, &fakeIdentityService{}, &fakeArtifactStore{})
	_, err = plain.GetGatewaySettings(gatewayContext(t), &controlv1.GetGatewaySettingsRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
	assertCode(t, err, codes.FailedPrecondition)
}

// A Gateway disabled within the grace period keeps serving its connected
// nodes and learns it was disabled; it enrolls no node and reports no
// readiness (ADR 0013 §5.2).
func TestDisabledGatewayIsServedOnlyForItsConnectedNodes(t *testing.T) {
	gatewayID := uuid.MustParse(testGatewayID)
	registry := &fakeGatewayRegistry{authorized: map[string]bool{gatewayID.String() + "/1c": true}, disabled: true}
	config := DefaultConfig()
	config.Gateways = registry
	identity := &fakeIdentityService{authorize: func(context.Context, nodeidentity.AuthorizeRequest) (nodeidentity.Authorization, error) {
		t.Fatal("a disabled gateway reached enrollment")
		return nodeidentity.Authorization{}, nil
	}}
	service, err := NewService(identity, &fakeArtifactStore{}, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := boundGatewayContext(t, gatewayID, 0x1c)
	response, err := service.GetGatewaySettings(ctx, &controlv1.GetGatewaySettingsRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
	if err != nil || !response.GetDisabled() || len(response.GetEndpoints()) != 1 {
		t.Fatalf("settings of a disabled gateway = %v, %v", response, err)
	}
	if _, err := service.authenticateGateway(ctx, testGatewayID); err != nil {
		t.Fatalf("connected-node calls refused during the grace period: %v", err)
	}
	_, err = service.AuthorizeEnrollment(ctx, authorizeRequest())
	assertCode(t, err, codes.FailedPrecondition)
	_, err = service.ReportGatewayReady(ctx, &controlv1.ReportGatewayReadyRequest{Request: metadata(), GatewayInstanceId: testGatewayID})
	assertCode(t, err, codes.FailedPrecondition)
	_, err = service.RenewGatewayCertificate(ctx, &controlv1.RenewGatewayCertificateRequest{Request: metadata(),
		GatewayInstanceId: testGatewayID, Kind: "client", CertificateSigningRequestDer: []byte{1}})
	assertCode(t, err, codes.FailedPrecondition)
	if len(registry.ready) != 0 || registry.renewKind != "" {
		t.Fatalf("disabled gateway changed state: %v %q", registry.ready, registry.renewKind)
	}
}
