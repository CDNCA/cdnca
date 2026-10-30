//go:build integration

package nodeidentity

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// enrolledIdentityNode enrolls fixture's node and returns how to read its
// authorization snapshot.
func enrolledIdentityNode(t *testing.T, service *Service, fixture identityFixture) func() (AuthorizationSnapshot, error) {
	t.Helper()
	authorize := validAuthorizeRequest(t, testCSR(t, false))
	authorize.EnrollmentToken = fixture.token
	authorization, err := service.Authorize(context.Background(), authorize)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := service.Complete(context.Background(), CompleteRequest{
		RequestID: uuid.NewString(), AuthorizationID: authorization.ID,
		GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: authorize.GatewayInstanceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return func() (AuthorizationSnapshot, error) {
		return service.GetAuthorization(context.Background(), GetAuthorizationRequest{
			NodeID: fixture.nodeID, CertificateSerialNumber: completion.Certificate.SerialNumber,
			CertificateSHA256:       certificateDERDigest(t, completion.Certificate),
			GatewayWorkloadIdentity: authorize.GatewayWorkloadIdentity, GatewayInstanceID: "gateway-takeover",
		})
	}
}

// seedUnreadableTelemetryConfig stores a releasable config version whose
// canonical snapshot the telemetry reader does not accept, as a site runtime
// v2 document is today.
func seedUnreadableTelemetryConfig(t *testing.T, pool *pgxpool.Pool, fixture identityFixture, publishedAt time.Time) uuid.UUID {
	t.Helper()
	configVersionID := uuid.New()
	snapshot := []byte(`{"schema":"cdnca.edge.site-runtime/v2","configuration_scope_id":"` + fixture.scopeID.String() + `"}`)
	digest := sha256.Sum256(snapshot)
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions
		(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		 status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,$3,$4,'telemetry-test','1','releasable',$5,$6,$7,$7)`,
		configVersionID, fixture.scopeID, snapshot, digest[:], "telemetry-bad-"+configVersionID.String(), bytesOf(32, 4), publishedAt); err != nil {
		t.Fatal(err)
	}
	return configVersionID
}

func claimIdentityNode(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID, configVersionID uuid.UUID, now time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state
		(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
		VALUES($1,$2,$3,1,$4)`, nodeID, scopeID, configVersionID, now); err != nil {
		t.Fatal(err)
	}
}

// TestMultiScopeAuthorizationIsolatesUnreadableScope: one tenant's
// unreadable configuration leaves only that tenant's telemetry out; the
// node keeps its session and the other tenant keeps its sites.
func TestMultiScopeAuthorizationIsolatesUnreadableScope(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	platform := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	healthy := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	broken := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, platform)

	siteID := uuid.New()
	healthyVersion := seedTelemetryConfig(t, pool, healthy, siteID, now)
	claimIdentityNode(t, pool, platform.nodeID, healthy.scopeID, healthyVersion, now)
	claimIdentityNode(t, pool, platform.nodeID, broken.scopeID, seedUnreadableTelemetryConfig(t, pool, broken, now), now)

	snapshot, err := authorize()
	if err != nil {
		t.Fatalf("one unreadable scope took the node's authorization down: %v", err)
	}
	if !snapshot.ConnectionAllowed || !snapshot.DeploymentsAllowed || snapshot.TenantID != uuid.Nil {
		t.Fatalf("multi-scope node authorization = %#v", snapshot)
	}
	assertTelemetryBindings(t, snapshot.TelemetrySites, map[TelemetrySiteScope]struct{}{{
		SiteID: siteID, TenantID: healthy.tenantID, ConfigurationScopeID: healthy.scopeID, ConfigVersionID: healthyVersion,
	}: {}})
	if len(snapshot.TelemetryExcludedScopes) != 1 ||
		snapshot.TelemetryExcludedScopes[broken.scopeID] != TelemetryExclusionInvalidConfig {
		t.Fatalf("excluded scopes = %#v", snapshot.TelemetryExcludedScopes)
	}

	// The shared-node view reads the same reason.
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	excluded, err := TelemetryScopeExclusions(context.Background(), tx, platform.nodeID, now)
	_ = tx.Rollback(context.Background())
	if err != nil || len(excluded) != 1 || excluded[broken.scopeID] != TelemetryExclusionInvalidConfig {
		t.Fatalf("TelemetryScopeExclusions = %#v, %v", excluded, err)
	}

}

// TestSingleScopeAuthorizationStillFailsClosed: isolation is for shared
// nodes only; a node serving one scope refuses an unreadable configuration
// as before.
func TestSingleScopeAuthorizationStillFailsClosed(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	single := seedIdentityPlatformNode(t, pool, now, "pending", "initial_enrollment")
	broken := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, single)
	claimIdentityNode(t, pool, single.nodeID, broken.scopeID, seedUnreadableTelemetryConfig(t, pool, broken, now), now)
	if _, err := authorize(); !errors.Is(err, ErrPersistence) {
		t.Fatalf("single-scope node with an unreadable config: err=%v, want fail closed", err)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	excluded, err := TelemetryScopeExclusions(context.Background(), tx, single.nodeID, now)
	_ = tx.Rollback(context.Background())
	if err != nil || len(excluded) != 0 {
		t.Fatalf("single-scope exclusions = %#v, %v", excluded, err)
	}
}

// TestMultiScopeAuthorizationRequiresPlatformNode: only platform nodes are
// shared, so a tenant-owned node holding several scopes is refused even if
// its rows got past the database constraints.
func TestMultiScopeAuthorizationRequiresPlatformNode(t *testing.T) {
	pool := openIdentityTestDatabase(t, true)
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := &identityTestClock{value: now}
	service := newIdentityTestService(t, pool, newIdentityTestCA(t, now), clock)
	owner := seedIdentityNode(t, pool, now, "pending", "initial_enrollment")
	other := seedIdentityNode(t, pool, now, "active", "initial_enrollment")
	authorize := enrolledIdentityNode(t, service, owner)
	claimIdentityNode(t, pool, owner.nodeID, owner.scopeID, seedTelemetryConfig(t, pool, owner, uuid.New(), now), now)
	if _, err := authorize(); err != nil {
		t.Fatalf("tenant node with its own scope: %v", err)
	}

	// Force a second scope past migration 291's checks, as a corrupted or
	// hand-edited database could.
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO node_config_state
		(node_id,configuration_scope_id,current_config_version_id,revision,updated_at)
		VALUES($1,$2,$3,1,$4)`, owner.nodeID, other.scopeID, seedTelemetryConfig(t, pool, other, uuid.New(), now), now); err != nil {
		t.Fatalf("seed second scope on a tenant node: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := authorize(); !errors.Is(err, ErrPersistence) {
		t.Fatalf("tenant node serving several scopes: err=%v, want refused", err)
	}
}
