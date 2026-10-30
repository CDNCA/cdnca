//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedSiteRuntimeV2TelemetryConfig stores a releasable site runtime v2
// config version for fixture's scope, built from the shared contract fixture
// (one site on 18090 and 18443, L4 streams), and returns it with its site.
func seedSiteRuntimeV2TelemetryConfig(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, publishedAt time.Time) (uuid.UUID, uuid.UUID) {
	t.Helper()
	raw, err := os.ReadFile("../../../../api/schemas/edge/v2/testdata/site-runtime-capability-v4-streams.json")
	if err != nil {
		t.Fatal(err)
	}
	configVersionID, siteID := uuid.New(), uuid.New()
	text := string(raw)
	// The fixture uses one UUID for scope and tenant; streams carry the tenant.
	head, streams, found := strings.Cut(text, `"streams"`)
	if !found {
		t.Fatal("fixture has no streams")
	}
	head = strings.ReplaceAll(head, "10000000-0000-4000-8000-000000000001", fixture.scopeID.String())
	streams = strings.ReplaceAll(streams, "10000000-0000-4000-8000-000000000001", fixture.tenantID.String())
	text = head + `"streams"` + streams
	text = strings.ReplaceAll(text, "10000000-0000-4000-8000-000000000002", configVersionID.String())
	text = strings.ReplaceAll(text, "11111111-1111-4111-8111-111111111111", siteID.String())
	snapshot := []byte(text)
	digest := sha256.Sum256(snapshot)
	if _, _, _, err := parseTelemetrySnapshot(snapshot, digest[:], fixture.scopeID, fixture.tenantID, configVersionID,
		telemetrySiteSubscriptions{}); err != nil {
		t.Fatalf("site runtime v2 fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions
		(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		 status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,$3,$4,'telemetry-test','1','releasable',$5,$6,$7,$7)`,
		configVersionID, fixture.scopeID, snapshot, digest[:], "telemetry-v2-"+configVersionID.String(), bytesOf(32, 5), publishedAt); err != nil {
		t.Fatal(err)
	}
	return configVersionID, siteID
}

// withFixtureStreams adds the bindings of the contract fixture's two L4
// forwards: since tcp/udp v12 each forward is its own telemetry partition
// (stream ID as site ID, 210f60f2e), bound without a package here.
func withFixtureStreams(want map[TelemetrySiteScope]struct{}, scope identityFixture, version uuid.UUID) map[TelemetrySiteScope]struct{} {
	for _, streamID := range []string{"70000000-0000-4000-8000-000000000001", "70000000-0000-4000-8000-000000000002"} {
		want[TelemetrySiteScope{SiteID: uuid.MustParse(streamID), TenantID: scope.tenantID,
			ConfigurationScopeID: scope.scopeID, ConfigVersionID: version}] = struct{}{}
	}
	return want
}

func newSiteRuntimeV2TelemetryTest(t *testing.T) (*pgxpool.Pool, *Service, time.Time) {
	t.Helper()
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	return pool, newIdentityTestService(t, pool, newIdentityTestCA(t, now), &identityTestClock{value: now}), now
}

// TestSiteRuntimeV2TelemetryAuthorizationSingleScope: a node whose current
// configuration is site runtime v2 keeps its authorization and its sites.
func TestSiteRuntimeV2TelemetryAuthorizationSingleScope(t *testing.T) {
	pool, service, now := newSiteRuntimeV2TelemetryTest(t)
	node := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, node)
	version, siteID := seedSiteRuntimeV2TelemetryConfig(t, pool, tenant, now)
	claimIdentityNode(t, pool, node.nodeID, tenant.scopeID, version, now)
	snapshot, err := authorize()
	if err != nil {
		t.Fatalf("single-scope v2 node authorization: %v", err)
	}
	if !snapshot.ConnectionAllowed || snapshot.TenantID != tenant.tenantID {
		t.Fatalf("authorization = %#v", snapshot)
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, withFixtureStreams(map[TelemetrySiteScope]struct{}{{
		SiteID: siteID, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: version,
	}: {}}, tenant, version))
}

// TestSiteRuntimeV2TelemetryAuthorizationRecordedSubscription: the package
// subscription a v2 publication recorded for a site (migration 295) reaches
// the site's binding, as the v1 snapshot's would.
func TestSiteRuntimeV2TelemetryAuthorizationRecordedSubscription(t *testing.T) {
	pool, service, now := newSiteRuntimeV2TelemetryTest(t)
	node := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, node)
	version, siteID := seedSiteRuntimeV2TelemetryConfig(t, pool, tenant, now)
	subscriptionID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_version_telemetry_site_bindings
		(config_version_id,site_id,package_subscription_id) VALUES($1,$2,$3)`, version, siteID, subscriptionID); err != nil {
		t.Fatal(err)
	}
	claimIdentityNode(t, pool, node.nodeID, tenant.scopeID, version, now)
	snapshot, err := authorize()
	if err != nil {
		t.Fatalf("authorization: %v", err)
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, withFixtureStreams(map[TelemetrySiteScope]struct{}{{
		SiteID: siteID, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: version,
		PackageSubscriptionID: subscriptionID,
	}: {}}, tenant, version))
}

// TestSiteRuntimeV2TelemetryAuthorizationMixedHistory: config-source v1 and
// site runtime v2 versions within the 90-day window both bind.
func TestSiteRuntimeV2TelemetryAuthorizationMixedHistory(t *testing.T) {
	pool, service, now := newSiteRuntimeV2TelemetryTest(t)
	node := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, node)
	v1Site := uuid.New()
	v1Version := seedTelemetryConfig(t, pool, tenant, v1Site, now.Add(-48*time.Hour))
	v2Version, v2Site := seedSiteRuntimeV2TelemetryConfig(t, pool, tenant, now)
	claimIdentityNode(t, pool, node.nodeID, tenant.scopeID, v2Version, now)
	// The v1 version was healthy on this node a day ago.
	onNode := identityFixture{nodeID: node.nodeID, scopeID: tenant.scopeID, tenantID: tenant.tenantID}
	seedTelemetryDeploymentFact(t, pool, onNode, v1Version, uuid.Nil, "apply", "healthy", "healthy", now.Add(-24*time.Hour))
	snapshot, err := authorize()
	if err != nil {
		t.Fatalf("mixed v1/v2 history authorization: %v", err)
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, withFixtureStreams(map[TelemetrySiteScope]struct{}{
		{SiteID: v1Site, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: v1Version}: {},
		{SiteID: v2Site, TenantID: tenant.tenantID, ConfigurationScopeID: tenant.scopeID, ConfigVersionID: v2Version}: {},
	}, tenant, v2Version))
}

// TestSiteRuntimeV2TelemetryAuthorizationSharedNode: on a shared node a
// scope published as v2 is no longer isolated.
func TestSiteRuntimeV2TelemetryAuthorizationSharedNode(t *testing.T) {
	pool, service, now := newSiteRuntimeV2TelemetryTest(t)
	node := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	v1Tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	v2Tenant := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, node)
	v1Site := uuid.New()
	v1Version := seedTelemetryConfig(t, pool, v1Tenant, v1Site, now)
	v2Version, v2Site := seedSiteRuntimeV2TelemetryConfig(t, pool, v2Tenant, now)
	claimIdentityNode(t, pool, node.nodeID, v1Tenant.scopeID, v1Version, now)
	claimIdentityNode(t, pool, node.nodeID, v2Tenant.scopeID, v2Version, now)
	snapshot, err := authorize()
	if err != nil {
		t.Fatalf("shared node authorization: %v", err)
	}
	if len(snapshot.TelemetryExcludedScopes) != 0 {
		t.Fatalf("v2 scope still excluded: %#v", snapshot.TelemetryExcludedScopes)
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, withFixtureStreams(map[TelemetrySiteScope]struct{}{
		{SiteID: v1Site, TenantID: v1Tenant.tenantID, ConfigurationScopeID: v1Tenant.scopeID, ConfigVersionID: v1Version}: {},
		{SiteID: v2Site, TenantID: v2Tenant.tenantID, ConfigurationScopeID: v2Tenant.scopeID, ConfigVersionID: v2Version}: {},
	}, v2Tenant, v2Version))
}
