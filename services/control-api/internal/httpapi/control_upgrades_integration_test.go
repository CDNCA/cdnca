//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/controlupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/platformpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type controlUpgradeTestSigner struct {
	id      string
	private ed25519.PrivateKey
}

func (signer controlUpgradeTestSigner) KeyID() string { return signer.id }

func (signer controlUpgradeTestSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

func TestControlUpgradeMigrationRoundTrip(t *testing.T) {
	// Only 1..023: rolling the release head back crosses migration 268's
	// one-way down gate (P2682).
	pool := migrationRoundTripPool(t, 23)
	assertControlUpgradeMigration(t, pool, true)
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("Migrate(down 023) error = %v", err)
	}
	assertControlUpgradeMigration(t, pool, false)

	// The 022 schema predates the current bootstrap path; seed the
	// platform_owner system role that migration 023 grants directly.
	bootstrap := struct{ RoleID uuid.UUID }{RoleID: uuid.New()}
	platformScopeID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')`, platformScopeID); err != nil {
		t.Fatalf("insert platform scope: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles (id, scope_id, name, description, system_role)
		VALUES ($1, $2, 'platform_owner', 'Upgrade migration platform owner', true)`, bootstrap.RoleID, platformScopeID); err != nil {
		t.Fatalf("insert platform owner role: %v", err)
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 23); err != nil {
		t.Fatalf("Migrate(up after 023 rollback) error = %v", err)
	}
	if version := controlUpgradeMigrationVersion(t, pool); version != 23 {
		t.Fatalf("migration version = %d, want 23", version)
	}
	assertControlUpgradeMigration(t, pool, true)
	var grants int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM role_permissions
		WHERE role_id = $1 AND permission_name = 'control.upgrades.check'`, bootstrap.RoleID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Fatalf("platform owner control upgrade grants = %d, want 1", grants)
	}
}

func controlUpgradeMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func TestControlUpgradeHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	// The revocation LKG guard (084) checks issued_at/expires_at against the
	// database's physical clock, so the test clock follows the database.
	var now time.Time
	if err := pool.QueryRow(context.Background(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	now = now.UTC()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := controlUpgradeTestSigner{id: "control-upgrade-test-key", private: privateKey}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: signer.id, PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	bootstrap, err := identityStore.BootstrapPlatformUser(
		context.Background(), "upgrade-owner", "Upgrade Owner", passwordHash, "upgrade-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "upgrade-viewer", "Upgrade Viewer", passwordHash, "active")
	insertControlUpgradeTenantUser(t, pool, "upgrade-tenant", passwordHash)
	tokens, err := identity.NewTokenManager("control-upgrade-integration-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	policyState := platformpolicy.NewState(func() time.Time { return now })
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure: false, Now: func() time.Time { return now }, EntitlementTrust: trust,
		PlatformPolicyState: policyState,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	owner, _ := loginOK(t, client, server.URL, "upgrade-owner")
	viewer, _ := loginOK(t, client, server.URL, "upgrade-viewer")
	tenant, _ := loginOK(t, client, server.URL, "upgrade-tenant")
	request := controlupgrade.CheckRequest{Component: "control-api", CurrentVersion: "1.4.0", Channel: "stable"}

	t.Run("authentication and scope", func(t *testing.T) {
		response := performControlUpgradeRequest(t, client, server.URL, request, "unauthenticated", "", "upgrade-unauthenticated")
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "upgrade-unauthenticated")
		response.Body.Close()

		response = performControlUpgradeRequest(t, client, server.URL, request, "missing-permission", viewer.AccessToken, "upgrade-missing-permission")
		assertError(t, response, http.StatusForbidden, "permission_denied", "upgrade-missing-permission")
		response.Body.Close()

		response = performControlUpgradeRequest(t, client, server.URL, request, "tenant-scope", tenant.AccessToken, "upgrade-tenant-scope")
		assertError(t, response, http.StatusForbidden, "permission_denied", "upgrade-tenant-scope")
		response.Body.Close()
	})

	t.Run("strict input", func(t *testing.T) {
		invalid := request
		invalid.CurrentVersion = "v1.4.0"
		response := performControlUpgradeRequest(t, client, server.URL, invalid, "invalid-version", owner.AccessToken, "upgrade-invalid-version")
		assertError(t, response, http.StatusBadRequest, "validation_error", "upgrade-invalid-version")
		response.Body.Close()

		response = performControlUpgradeRequest(t, client, server.URL, request, "", owner.AccessToken, "upgrade-missing-key")
		assertError(t, response, http.StatusBadRequest, "validation_error", "upgrade-missing-key")
		response.Body.Close()
	})

	assertControlUpgradeReason(t, client, server.URL, request, "no-lease", owner.AccessToken, controlupgrade.ReasonEntitlementUnavailable, false)

	installControlUpgradeLease(t, pool, trust, signer, controlUpgradeLease(now, 1, now.Add(-time.Hour), now.Add(time.Hour)))
	assertControlUpgradeReason(t, client, server.URL, request, "grace-lease", owner.AccessToken, controlupgrade.ReasonEntitlementStateDenied, false)

	installControlUpgradeLease(t, pool, trust, signer, controlUpgradeLease(now, 2, now.Add(-2*time.Hour), now.Add(-time.Hour)))
	assertControlUpgradeReason(t, client, server.URL, request, "expired-lease", owner.AccessToken, controlupgrade.ReasonEntitlementStateDenied, false)

	valid := controlUpgradeLease(now, 3, now.Add(time.Hour), now.Add(2*time.Hour))
	signed := installControlUpgradeLease(t, pool, trust, signer, valid)
	tampered := signed
	if tampered.Signature[0] == 'A' {
		tampered.Signature = "B" + tampered.Signature[1:]
	} else {
		tampered.Signature = "A" + tampered.Signature[1:]
	}
	tamperedWire, err := tampered.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE entitlement_cached_leases SET signed_lease = $2 WHERE serial = $1`, valid.Serial, tamperedWire); err != nil {
		t.Fatal(err)
	}
	assertControlUpgradeReason(t, client, server.URL, request, "damaged-signature", owner.AccessToken, controlupgrade.ReasonEntitlementInvalid, false)

	installControlUpgradeLease(t, pool, trust, signer, controlUpgradeLease(now, 4, now.Add(time.Hour), now.Add(2*time.Hour)))
	channelMismatch := request
	channelMismatch.Channel = "beta"
	assertControlUpgradeReason(t, client, server.URL, channelMismatch, "channel-mismatch", owner.AccessToken, controlupgrade.ReasonEntitlementChannelMismatch, false)
	versionDenied := request
	versionDenied.CurrentVersion = "2.1.0"
	assertControlUpgradeReason(t, client, server.URL, versionDenied, "version-denied", owner.AccessToken, controlupgrade.ReasonEntitlementVersionDenied, false)

	replaceControlUpgradePolicy(t, policyState, now.Add(-time.Second), []string{"stable"})
	assertControlUpgradeReason(t, client, server.URL, request, "stale-policy", owner.AccessToken, controlupgrade.ReasonPlatformPolicyStale, false)
	replaceControlUpgradePolicy(t, policyState, now.Add(time.Hour), []string{"beta"})
	assertControlUpgradeReason(t, client, server.URL, request, "channel-denied", owner.AccessToken, controlupgrade.ReasonReleaseChannelDenied, false)
	targetRevisionID := replaceControlUpgradePolicy(t, policyState, now.Add(time.Hour), []string{"stable"})
	allowed := assertControlUpgradeReason(t, client, server.URL, request, "allowed", owner.AccessToken, controlupgrade.ReasonEligible, true)
	if allowed.Policy.TargetRevisionID != targetRevisionID || allowed.Policy.Source != platformpolicy.ScopeInstallation || allowed.Policy.Stale {
		t.Fatalf("allowed policy metadata = %#v", allowed.Policy)
	}

	t.Run("idempotent replay and conflict", func(t *testing.T) {
		before := controlUpgradeAuditCount(t, pool)
		first := controlUpgradeResponse(t, performControlUpgradeRequest(t, client, server.URL, request, "replay-key", owner.AccessToken, "upgrade-replay-first"))
		second := controlUpgradeResponse(t, performControlUpgradeRequest(t, client, server.URL, request, "replay-key", owner.AccessToken, "upgrade-replay-second"))
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("replayed response changed: first=%#v second=%#v", first, second)
		}
		if delta := controlUpgradeAuditCount(t, pool) - before; delta != 1 {
			t.Fatalf("replay audit delta = %d, want 1", delta)
		}
		changed := request
		changed.CurrentVersion = "1.5.0"
		response := performControlUpgradeRequest(t, client, server.URL, changed, "replay-key", owner.AccessToken, "upgrade-replay-conflict")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "upgrade-replay-conflict")
		response.Body.Close()
	})

	t.Run("concurrent replay writes one audit event", func(t *testing.T) {
		before := controlUpgradeAuditCount(t, pool)
		const callers = 8
		var wait sync.WaitGroup
		errorsByCaller := make(chan error, callers)
		for caller := range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				response, err := rawControlUpgradeRequest(client, server.URL, request, "concurrent-key", owner.AccessToken,
					fmt.Sprintf("upgrade-concurrent-%d", caller))
				if err != nil {
					errorsByCaller <- err
					return
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK {
					errorsByCaller <- fmt.Errorf("status %d: %s", response.StatusCode, readBody(response.Body))
				}
			}()
		}
		wait.Wait()
		close(errorsByCaller)
		for err := range errorsByCaller {
			t.Error(err)
		}
		if delta := controlUpgradeAuditCount(t, pool) - before; delta != 1 {
			t.Fatalf("concurrent audit delta = %d, want 1", delta)
		}
	})

	if err := audit.New(pool).VerifyScope(context.Background(), bootstrap.ScopeID); err != nil {
		t.Fatalf("VerifyScope() error = %v", err)
	}
	var auditPayload string
	if err := pool.QueryRow(context.Background(), `
		SELECT payload::text FROM audit_events WHERE action = 'control.upgrade.check'
		ORDER BY stream_position DESC LIMIT 1`).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditPayload, signer.id) || strings.Contains(auditPayload, "signature") || strings.Contains(auditPayload, "key_id") {
		t.Fatalf("upgrade audit leaked signing material metadata: %s", auditPayload)
	}
}

func assertControlUpgradeMigration(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var tableExists, permissionExists bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass('control_upgrade_check_requests') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM permissions WHERE name = 'control.upgrades.check')`).Scan(&permissionExists); err != nil {
		t.Fatal(err)
	}
	if tableExists != want || permissionExists != want {
		t.Fatalf("control upgrade migration state = table:%t permission:%t, want %t", tableExists, permissionExists, want)
	}
}

func insertControlUpgradeTenantUser(t *testing.T, pool *pgxpool.Pool, username, passwordHash string) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1, 'Upgrade Tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO users (id, username, display_name, password_hash)
		VALUES ($1, $2, 'Upgrade Tenant User', $3)`, userID, username, passwordHash); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO memberships (scope_id, user_id) VALUES ($1, $2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func controlUpgradeLease(now time.Time, serial uint64, expiresAt, graceUntil time.Time) entitlement.Lease {
	return entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		// 撤销集只接受规范 UUID（libs/entitlement/revocation.go），安装前要先有撤销 LKG。
		CustomerID: "44444444-4444-4444-8444-444444444444", InstallationID: "55555555-5555-4555-8555-555555555555",
		LicenseID: "66666666-6666-4666-8666-666666666666", Serial: serial, NotBefore: now.Add(-4 * time.Hour).Unix(), ExpiresAt: expiresAt.Unix(), GraceUntil: graceUntil.Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "1.0.0", Max: "2.0.0"},
		Features: []entitlement.Feature{}, Quotas: []entitlement.Quota{},
	}
}

func installControlUpgradeLease(t *testing.T, pool *pgxpool.Pool, trust *entitlementguard.TrustStore,
	signer controlUpgradeTestSigner, lease entitlement.Lease) entitlement.SignedLease {
	t.Helper()
	// controlUpgradeLease anchors NotBefore four hours before the test clock.
	installedAt := time.Unix(lease.NotBefore, 0).Add(4 * time.Hour).UTC()
	ensureHTTPTestRevocation(t, pool, trust, siteTestKey{
		id: signer.id, public: signer.private.Public().(ed25519.PublicKey), private: signer.private,
	}, installedAt, lease)
	signed, err := entitlement.Sign(context.Background(), lease, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(context.Background(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed,
	}, installedAt); err != nil {
		t.Fatal(err)
	}
	return signed
}

func replaceControlUpgradePolicy(t *testing.T, state *platformpolicy.State, expiresAt time.Time, channels []string) string {
	t.Helper()
	policy := platformpolicy.DefaultPolicy()
	policy.AllowedReleaseChannels = channels
	targetRevisionID := uuid.NewString()
	if err := state.Replace(platformpolicy.Snapshot{
		Policy: policy, Source: platformpolicy.ScopeInstallation, TargetRevisionID: targetRevisionID, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	return targetRevisionID
}

func assertControlUpgradeReason(t *testing.T, client *http.Client, baseURL string, request controlupgrade.CheckRequest,
	key, token, reason string, eligible bool) controlupgrade.CheckResponse {
	t.Helper()
	result := controlUpgradeResponse(t, performControlUpgradeRequest(t, client, baseURL, request, key, token, "upgrade-"+key))
	if result.Reason != reason || result.Eligible != eligible {
		t.Fatalf("upgrade decision = eligible:%t reason:%q, want eligible:%t reason:%q", result.Eligible, result.Reason, eligible, reason)
	}
	return result
}

func controlUpgradeResponse(t *testing.T, response *http.Response) controlupgrade.CheckResponse {
	t.Helper()
	defer response.Body.Close()
	var result controlupgrade.CheckResponse
	decodeResponse(t, response, http.StatusOK, &result)
	return result
}

func performControlUpgradeRequest(t *testing.T, client *http.Client, baseURL string, body controlupgrade.CheckRequest,
	key, token, requestID string) *http.Response {
	t.Helper()
	response, err := rawControlUpgradeRequest(client, baseURL, body, key, token, requestID)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func rawControlUpgradeRequest(client *http.Client, baseURL string, body controlupgrade.CheckRequest,
	key, token, requestID string) (*http.Response, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/admin/control-upgrade-checks", bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	return client.Do(request)
}

func controlUpgradeAuditCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_events WHERE action = 'control.upgrade.check'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
