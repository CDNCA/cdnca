//go:build integration

package nodeidentity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPlatformNodeAuthorizationUsesBoundConfigurationScope(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	platform := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")

	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = platform.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{
		RequestID:               uuid.NewString(),
		AuthorizationID:         authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}

	siteID := uuid.New()
	configVersionID := seedTelemetryConfig(t, pool, tenant, siteID, now)
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state
		(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
		VALUES($1,$2,$3,1,$4)`, platform.nodeID, tenant.scopeID, configVersionID, now); err != nil {
		t.Fatal(err)
	}

	snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{
		NodeID:                  platform.nodeID,
		CertificateSerialNumber: completion.Certificate.SerialNumber,
		CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover",
	})
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if !snapshot.ConnectionAllowed || !snapshot.DeploymentsAllowed {
		t.Fatalf("platform node authorization = %#v", snapshot)
	}
	if snapshot.TenantID != tenant.tenantID || len(snapshot.TelemetrySites) != 1 ||
		snapshot.TelemetrySites[0] != (TelemetrySiteScope{
			SiteID: siteID, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: configVersionID,
		}) {
		t.Fatalf("platform node configuration binding = %#v", snapshot)
	}
}

func TestPlatformNodeAuthorizationCarriesEveryConfigurationScope(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	signer := newIdentityTestCA(t, now)
	service := newIdentityTestService(t, pool, signer, clock)
	platform := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	first := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	second := seedIdentityNode(t, pool, now, "active", "initial_enrollment")

	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = platform.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{
		RequestID:               uuid.NewString(),
		AuthorizationID:         authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       authorize.GatewayInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}

	want := make(map[TelemetrySiteScope]struct{}, 2)
	for _, tenant := range []identityFixture{first, second} {
		if tenant.scopeID == tenant.tenantID {
			t.Fatal("fixture must keep configuration scope and tenant IDs distinct")
		}
		siteID := uuid.New()
		configVersionID := seedTelemetryConfig(t, pool, tenant, siteID, now)
		if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state
			(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
			VALUES($1,$2,$3,1,$4)`, platform.nodeID, tenant.scopeID, configVersionID, now); err != nil {
			t.Fatal(err)
		}
		want[TelemetrySiteScope{
			SiteID: siteID, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: configVersionID,
		}] = struct{}{}
	}

	snapshot, err := service.GetAuthorization(context.Background(), GetAuthorizationRequest{
		NodeID:                  platform.nodeID,
		CertificateSerialNumber: completion.Certificate.SerialNumber,
		CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity,
		GatewayInstanceID:       "gateway-takeover",
	})
	if err != nil {
		t.Fatalf("GetAuthorization() error = %v", err)
	}
	if !snapshot.ConnectionAllowed || snapshot.TenantID != uuid.Nil {
		t.Fatalf("multi-scope node authorization = %#v", snapshot)
	}
	for index := 1; index < len(snapshot.TelemetrySites); index++ {
		previous, current := snapshot.TelemetrySites[index-1], snapshot.TelemetrySites[index]
		if previous.SiteID.String()+"/"+previous.ConfigVersionID.String() >=
			current.SiteID.String()+"/"+current.ConfigVersionID.String() {
			t.Fatalf("multi-scope telemetry sites are not ordered: %#v", snapshot.TelemetrySites)
		}
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, want)
}
