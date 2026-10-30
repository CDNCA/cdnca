package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// futureCapability stands for a capability a later Agent release declares and this Gateway's proto does not name.
const futureCapability = agentv1.CapabilityName(1000)

// skewControl answers like a control-api whose capability table ends at ceiling:
// session facts or an enrollment naming anything else are InvalidArgument (nodeidentity.canonicalCapabilities).
type skewControl struct {
	*fakeControl
	ceiling     agentv1.CapabilityName
	mu          sync.Mutex
	facts       []*controlv1.GatewaySessionFactsV1
	enrollments []*agentv1.AgentCapabilities
}

func (c *skewControl) unknown(capabilities *agentv1.AgentCapabilities) bool {
	for _, feature := range capabilities.GetFeatures() {
		if _, known := agentv1.CapabilityName_name[int32(feature.GetName())]; !known || feature.GetName() > c.ceiling {
			return true
		}
	}
	return false
}

func (c *skewControl) AuthorizeEnrollment(ctx context.Context, request *controlv1.AuthorizeEnrollmentRequest) (*controlv1.AuthorizeEnrollmentResponse, error) {
	c.mu.Lock()
	c.enrollments = append(c.enrollments, proto.Clone(request.Capabilities).(*agentv1.AgentCapabilities))
	c.mu.Unlock()
	if c.unknown(request.Capabilities) {
		return nil, status.Error(codes.InvalidArgument, "request is invalid")
	}
	return c.fakeControl.AuthorizeEnrollment(ctx, request)
}

func (c *skewControl) GetNodeAuthorization(ctx context.Context, request *controlv1.GetNodeAuthorizationRequest) (*controlv1.GetNodeAuthorizationResponse, error) {
	result, err := c.fakeControl.GetNodeAuthorization(ctx, request)
	if err != nil {
		return nil, err
	}
	result.DeploymentsAllowed = true
	result.InstallationId = "7a1f6c3e-2b4d-4e8f-9a0b-1c2d3e4f5a6b"
	if request.SessionFacts == nil {
		return result, nil
	}
	c.mu.Lock()
	c.facts = append(c.facts, proto.Clone(request.SessionFacts).(*controlv1.GatewaySessionFactsV1))
	c.mu.Unlock()
	if c.unknown(request.SessionFacts.Capabilities) {
		return nil, status.Error(codes.InvalidArgument, "request is invalid")
	}
	encoded, _ := (proto.MarshalOptions{Deterministic: true}).Marshal(request.SessionFacts)
	digest := sha256.Sum256(encoded)
	result.SessionFactsSha256 = digest[:]
	return result, nil
}

type skewUpgradeBus struct{}

func (skewUpgradeBus) SubscribeUpgrade(context.Context, string) (UpgradeCommandSubscription, error) {
	return skewUpgradeSubscription{}, nil
}

func (skewUpgradeBus) PublishUpgradeStatus(context.Context, string, []byte) (UpgradeStatusPublication, error) {
	return UpgradeStatusPublication{Stream: UpgradeStatusStream, Sequence: 1}, nil
}

type skewUpgradeSubscription struct{}

func (skewUpgradeSubscription) Next(ctx context.Context) (UpgradeCommandDelivery, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (skewUpgradeSubscription) Close() error { return nil }

// startSkewServers is startTestServers with edge upgrade messaging configured, as in production.
func startSkewServers(t *testing.T, control ControlPlane) testServers {
	t.Helper()
	pki := newTestPKI(t)
	now := time.Now()
	clientCertificate := pki.client(t, 10, nodeSPIFFEPrefix+testNodeID, now.Add(-time.Hour), now.Add(time.Hour))
	config := DefaultConfig()
	config.GatewayInstanceID, config.GatewayVersion = "gateway-test", "test"
	gateway, err := New(config, control, NewMemorySessionCoordinator())
	if err != nil {
		t.Fatal(err)
	}
	if err := gateway.ConfigureUpgradeMessaging(skewUpgradeBus{}); err != nil {
		t.Fatal(err)
	}
	servers, err := NewServers(gateway, &tls.Config{Certificates: []tls.Certificate{pki.server}},
		&tls.Config{Certificates: []tls.Certificate{pki.server}, ClientCAs: pki.rootPool})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mtls, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = servers.Enrollment.Serve(enrollment) }()
	go func() { _ = servers.MTLS.Serve(mtls) }()
	t.Cleanup(func() { servers.Enrollment.Stop(); servers.MTLS.Stop() })
	return testServers{enrollmentAddress: enrollment.Addr().String(), mtlsAddress: mtls.Addr().String(),
		pki: pki, clientCertificate: clientCertificate}
}

func skewHandshake(t *testing.T, control *skewControl, features ...*agentv1.Capability) (*agentv1.GatewayHello, error) {
	t.Helper()
	servers := startSkewServers(t, control)
	connection := dialGateway(t, servers.mtlsAddress, servers.pki.rootPool, servers.clientCertificate)
	t.Cleanup(func() { _ = connection.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	stream, err := agentv1.NewAgentGatewayServiceClient(connection).Connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hello := validHello(testNodeID, versionRange(1, 0), 1)
	hello.GetHello().Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "build",
		OperatingSystem: "linux", Architecture: "amd64", Features: features}
	if err := stream.Send(hello); err != nil {
		t.Fatal(err)
	}
	response, err := stream.Recv()
	return response.GetHello(), err
}

func enabledUpgrade(hello *agentv1.GatewayHello) bool {
	for _, capability := range hello.GetEnabledCapabilities() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE {
			return true
		}
	}
	return false
}

func upgradeFeatures(extra ...agentv1.CapabilityName) []*agentv1.Capability {
	features := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1},
	}
	for _, name := range extra {
		features = append(features, &agentv1.Capability{Name: name, ApiVersion: 1})
	}
	return features
}

// Newer Agent + this Gateway: a capability this release does not name must not cost the node its edge upgrades
// (dropping the whole session evidence would leave EDGE_UPGRADE disabled).
func TestGatewayKeepsUpgradesForAgentWithUnknownCapability(t *testing.T) {
	control := &skewControl{fakeControl: defaultFakeControl(), ceiling: futureCapability}
	hello, err := skewHandshake(t, control, upgradeFeatures(futureCapability)...)
	if err != nil || !enabledUpgrade(hello) {
		t.Fatalf("handshake = (%v, %v), want EDGE_UPGRADE enabled", hello.GetEnabledCapabilities(), err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.facts) != 1 {
		t.Fatalf("session facts calls = %d, want 1", len(control.facts))
	}
	for _, feature := range control.facts[0].Capabilities.Features {
		if feature.Name == futureCapability {
			t.Fatal("facts attested a capability this Gateway does not know")
		}
	}
}

// Session facts the control plane refuses (InvalidArgument) fail the session closed: the baseline is 1.0.35,
// so there is no older control-api whose capability table this Gateway retries with a smaller set.
func TestGatewayDoesNotRetryRefusedSessionFacts(t *testing.T) {
	control := &skewControl{fakeControl: defaultFakeControl(), ceiling: agentv1.CapabilityName_CAPABILITY_NAME_GATEWAY_PORT_TRANSITION}
	if _, err := skewHandshake(t, control, upgradeFeatures(agentv1.CapabilityName_CAPABILITY_NAME_WAF_CRS_MODULE)...); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("handshake error = %v, want InvalidArgument", err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.facts) != 1 {
		t.Fatalf("facts attempts = %d, want no retry with a smaller capability set", len(control.facts))
	}
}

// Newer Agent enrolling through this Gateway: capability names this release does not know are not forwarded, so
// the control plane of the same release accepts the enrollment.
func TestGatewayEnrollmentDropsUnknownCapabilities(t *testing.T) {
	control := &skewControl{fakeControl: defaultFakeControl(), ceiling: futureCapability}
	servers := startSkewServers(t, control)
	connection := dialGateway(t, servers.enrollmentAddress, servers.pki.rootPool)
	defer connection.Close()
	request := validEnrollment()
	request.Capabilities = &agentv1.AgentCapabilities{AgentVersion: "1.0.35", BuildId: "build", OperatingSystem: "linux",
		Architecture: "amd64", Features: upgradeFeatures(futureCapability)}
	if _, err := agentv1.NewAgentGatewayServiceClient(connection).Enroll(t.Context(), request); err != nil {
		t.Fatalf("Enroll() = %v", err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.enrollments) != 1 || control.unknown(control.enrollments[0]) || len(control.enrollments[0].Features) != 2 {
		t.Fatalf("forwarded capabilities = %v", control.enrollments)
	}
}

// unscopedControlTelemetryResponse names no configuration_scope_id, only sites of the node owner.
func unscopedControlTelemetryResponse() *controlv1.GetNodeAuthorizationResponse {
	return &controlv1.GetNodeAuthorizationResponse{
		InstallationId: testConnectionsInstallationID, TenantId: testTelemetryTenantID,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{{SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID,
			ConfigVersionId: testTelemetryConfigVersionID, PackageSubscriptionId: testConnectionsSubscriptionID}},
	}
}

// A MULTI_TENANT_RUNTIME Agent asks for scoped records; an authorization without configuration scopes cannot
// attribute them and is refused (no unscoped fallback for a control-api that predates scopes), as is a
// multi-tenant answer that lacks one scope.
func TestScopedTelemetryRefusesAuthorizationWithoutScopes(t *testing.T) {
	publisher := &connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{Stream: ConnectionsTelemetryIngestStream, Sequence: 9}}
	broken := func() *controlv1.GetNodeAuthorizationResponse {
		response := multiTenantTelemetryResponse()
		response.TelemetrySiteScopes[1].ConfigurationScopeId = ""
		return response
	}
	for name, response := range map[string]func() *controlv1.GetNodeAuthorizationResponse{
		"unscoped": unscopedControlTelemetryResponse, "missing scope": broken,
	} {
		gateway := newTelemetryGateway(t, &multiTenantTelemetryControl{fakeControl: defaultFakeControl(), response: response}, publisher)
		if err := gateway.StreamTelemetry(scopedConnectionsStream(t, true, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))); err == nil {
			t.Fatalf("%s: a scoped session was served without configuration scopes", name)
		}
	}
	if publications := publisher.publicationsSnapshot(); len(publications) != 0 {
		t.Fatalf("publications = %+v", publications)
	}
}
