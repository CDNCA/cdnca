//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/siteaccess"
	"github.com/google/uuid"
)

// TestSiteAccessHTTP: GET/PUT /v1/sites/{site_id}/access.
// Settings round-trip without passwords, the site version advances
// (If-Match), replays are idempotent, HTTPS-only settings need HTTPS, a
// locked site refuses tenants, another tenant cannot see the site, the
// stored document holds only the password digest, and the write is audited
// without secrets.
func TestSiteAccessHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenantA := insertSecurityTenant(t, pool, "Site Access A", "site-access-a", passwordHash)
	tenantB := insertSecurityTenant(t, pool, "Site Access B", "site-access-b", passwordHash)
	for _, tenant := range []securityTenantFixture{tenantA, tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			SELECT id,permission FROM roles,unnest(ARRAY['sites.read','sites.manage']) permission
			WHERE scope_id=$1 AND name='tenant_owner' AND system_role ON CONFLICT DO NOTHING`, tenant.scopeID); err != nil {
			t.Fatalf("grant site permissions: %v", err)
		}
	}
	tokens, err := identity.NewTokenManager("site-access-secret-at-least-32-bytes!!", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x53}, 32)}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	siteID := insertQuickBlockSite(t, pool, tenantA.scopeID, tenantA.userID)
	var domain string
	if err := pool.QueryRow(ctx, `SELECT domain FROM sites WHERE id=$1`, siteID).Scan(&domain); err != nil {
		t.Fatal(err)
	}
	path := server.URL + "/v1/sites/" + siteID.String() + "/access"

	var state siteaccess.State
	response := siteRequest(t, client, http.MethodGet, path, nil, authA.AccessToken, "", "")
	decodeResponse(t, response, http.StatusOK, &state)
	if state.Version != 1 || state.HTTPS || state.Settings.ForceHTTPS.Status != 301 || state.UpdatedAt != nil {
		t.Fatalf("initial state = %+v", state)
	}
	// HSTS needs HTTPS.
	response = siteRequest(t, client, http.MethodPut, path, map[string]any{"hsts": map[string]any{"max_age_seconds": 600}},
		authA.AccessToken, "sa-hsts", `"1"`)
	assertErrorBody(t, response, http.StatusUnprocessableEntity, "site_access_https_required")

	settings := map[string]any{
		"compression": map[string]any{"enabled": true, "types": []string{"text/css", "application/json"}, "min_length_bytes": 128},
		"limits":      map[string]any{"connections_per_ip": 16, "rate_bytes_per_second": 1 << 20},
		"basic_auth": map[string]any{"realm": "staff", "users": []map[string]any{{"username": "alice", "password": "correct horse"}},
			"exclude_path_prefixes": []string{"/health"}},
		"maintenance": map[string]any{"status": 503, "content_type": "text/plain", "body": "back soon"},
	}
	response = siteRequest(t, client, http.MethodPut, path, settings, authA.AccessToken, "sa-1", `"1"`)
	decodeResponse(t, response, http.StatusOK, &state)
	if state.Version != 2 || state.Settings.BasicAuth == nil || state.Settings.BasicAuth.Users[0].Password != "" ||
		strings.Join(state.Settings.Compression.Types, ",") != "application/json,text/css" || state.UpdatedAt == nil {
		t.Fatalf("updated state = %+v", state)
	}
	// Replay returns the same result; the same key with another body conflicts.
	response = siteRequest(t, client, http.MethodPut, path, settings, authA.AccessToken, "sa-1", `"1"`)
	var replay siteaccess.State
	decodeResponse(t, response, http.StatusOK, &replay)
	if replay.Version != 2 {
		t.Fatalf("replay version = %d", replay.Version)
	}
	response = siteRequest(t, client, http.MethodPut, path, map[string]any{}, authA.AccessToken, "sa-1", `"2"`)
	assertErrorBody(t, response, http.StatusConflict, "idempotency_conflict")
	// Stale If-Match.
	response = siteRequest(t, client, http.MethodPut, path, map[string]any{}, authA.AccessToken, "sa-stale", `"1"`)
	assertErrorBody(t, response, http.StatusConflict, "version_conflict")

	// The stored document holds the digest, never the password.
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT settings FROM site_access_settings WHERE site_id=$1`, siteID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var published edgeconfig.SiteAccess
	if err := json.Unmarshal(stored, &published); err != nil || strings.Contains(string(stored), "correct horse") ||
		!published.BasicAuth.Users[0].Verify("correct horse") || len(published.BasicAuth.Users[0].Salt) != 32 {
		t.Fatalf("stored settings %s (%v)", stored, err)
	}
	// Keeping the user without a password keeps its secret.
	settings["basic_auth"] = map[string]any{"realm": "staff", "users": []map[string]any{{"username": "alice"}}}
	response = siteRequest(t, client, http.MethodPut, path, settings, authA.AccessToken, "sa-keep", `"2"`)
	decodeResponse(t, response, http.StatusOK, &state)
	keptUser := published.BasicAuth.Users[0]
	if err := pool.QueryRow(ctx, `SELECT settings FROM site_access_settings WHERE site_id=$1`, siteID).Scan(&stored); err != nil ||
		!strings.Contains(string(stored), keptUser.Salt) || !strings.Contains(string(stored), keptUser.SHA256) {
		t.Fatalf("kept secret lost: %s %v", stored, err)
	}
	// A market leaf writes a subscriber's salted hash as it
	// is (no password), and the stored hash checks the subscriber's password.
	carried := edgeconfig.BasicAuthUserWithSalt("bob", strings.Repeat("ab", 16), "subscriber pass")
	access := siteaccess.NewService(pool, nil)
	leafActor := siteaccess.Actor{UserID: tenantA.userID, ScopeID: tenantA.scopeID, ScopeKind: "tenant"}
	current, err := access.Get(ctx, leafActor, siteID)
	if err != nil {
		t.Fatal(err)
	}
	carriedSettings := current.Settings
	carriedSettings.BasicAuth = &siteaccess.BasicAuth{Realm: "staff", Users: []siteaccess.BasicAuthUser{{Username: "alice"}, {Username: "bob"}}}
	if _, err := access.Update(ctx, leafActor, siteaccess.UpdateRequest{SiteID: siteID, ExpectedRevision: current.Version,
		Settings: carriedSettings, HashedUsers: []edgeconfig.BasicAuthUser{carried}, IdempotencyKey: "sa-hashed", RequestID: "sa-hashed"}); err != nil {
		t.Fatalf("hashed write: %v", err)
	}
	if current, err = access.Get(ctx, leafActor, siteID); err != nil || len(current.BasicAuthUsers) != 2 ||
		current.BasicAuthUsers[1] != carried || !current.BasicAuthUsers[1].Verify("subscriber pass") || current.BasicAuthUsers[0] != keptUser {
		t.Fatalf("hashed users = %+v %v", current.BasicAuthUsers, err)
	}

	// Another tenant cannot read it.
	response = siteRequest(t, client, http.MethodGet, path, nil, authB.AccessToken, "", "")
	assertErrorBody(t, response, http.StatusNotFound, "site_not_found")
	// A locked site refuses the tenant.
	if _, err := pool.Exec(ctx, `UPDATE sites SET locked_at=now(),lock_reason='test',locked_by_user_id=$2 WHERE id=$1`,
		siteID, tenantA.userID); err != nil {
		t.Fatal(err)
	}
	response = siteRequest(t, client, http.MethodPut, path, map[string]any{}, authA.AccessToken, "sa-locked", `"4"`)
	assertErrorBody(t, response, http.StatusConflict, "site_locked")
	if _, err := pool.Exec(ctx, `UPDATE sites SET locked_at=NULL,lock_reason=NULL,locked_by_user_id=NULL WHERE id=$1`, siteID); err != nil {
		t.Fatal(err)
	}
	// Everything off deletes the row.
	response = siteRequest(t, client, http.MethodPut, path, map[string]any{}, authA.AccessToken, "sa-off", `"4"`)
	decodeResponse(t, response, http.StatusOK, &state)
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM site_access_settings WHERE site_id=$1`, siteID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rows after off = %d %v", rows, err)
	}

	// Audit: success events carry changes and no secret; the refusals are recorded.
	auditRows, err := pool.Query(ctx, `SELECT result,payload,changes FROM audit_events WHERE action=$1 AND resource_id=$2 ORDER BY stream_position`,
		siteaccess.AuditAction, siteID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer auditRows.Close()
	results := []string{}
	for auditRows.Next() {
		var result string
		var payload, changes []byte
		if err := auditRows.Scan(&result, &payload, &changes); err != nil {
			t.Fatal(err)
		}
		for _, raw := range [][]byte{payload, changes} {
			if strings.Contains(string(raw), "correct horse") || strings.Contains(string(raw), `"sha256"`) ||
				strings.Contains(string(raw), `"salt"`) {
				t.Fatalf("audit leaks a secret: %s", raw)
			}
		}
		// The first write turns settings on and the last turns them off; the
		// writes in between only keep or add a user (the market hashed write,
		// fix-mktsiteconf4) and may change no summary item.
		if result == "success" && (strings.Contains(string(payload), `"from_version": 1`) ||
			strings.Contains(string(payload), `"from_version": 4`)) && string(changes) == "[]" {
			t.Fatalf("success audit without changes: %s", payload)
		}
		results = append(results, result)
	}
	if got := strings.Join(results, ","); got != "denied,success,denied,denied,success,success,denied,success" {
		t.Fatalf("audit results = %s", got)
	}
	_ = uuid.Nil
	_ = domain
}
