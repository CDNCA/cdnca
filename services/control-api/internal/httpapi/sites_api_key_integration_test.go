//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSiteAPIKeyOpenOperations (plugapi-S1): a tenant API key reads and
// edits its own sites (GET/PATCH /v1/sites/{id}, origin-routing GET/PUT,
// origin-status), a sites.read key cannot write (403 permission_denied),
// another tenant's key reads the site as 404, and create / batch-action stay
// session-only (403 api_key_not_allowed).
func TestSiteAPIKeyOpenOperations(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-api-key-open-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "sitekey-admin",
		"Site Key Admin", passwordHash, "sitekey-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenantA := insertSiteTenant(t, pool, "sitekey-a", "sitekey-a-user", "Site Key A", passwordHash)
	tenantB := insertSiteTenant(t, pool, "sitekey-b", "sitekey-b-user", "Site Key B", passwordHash)
	grantSiteAPIKeySelf(t, pool, tenantA.scopeID)
	grantSiteAPIKeySelf(t, pool, tenantB.scopeID)
	tokens, err := identity.NewTokenManager("site-api-key-open-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x54}, 32), EntitlementTrust: trust}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	created := createSite(t, client, server.URL, authA.AccessToken, "sitekey-create",
		createSiteRequest{Basic: validSiteBasic("sitekey.example.test", "192.0.2.10")})
	newKey := func(auth testAuthResponse, idempotency string, scopes ...string) string {
		issued := createSelfAPIKey(t, client, server.URL, auth.AccessToken, idempotency, map[string]any{"name": idempotency, "scopes": scopes})
		return issued.Key.KeyID + "." + issued.Secret
	}
	manageIssued := createSelfAPIKey(t, client, server.URL, authA.AccessToken, "sitekey-manage",
		map[string]any{"name": "sitekey-manage", "scopes": []string{"sites.read", "sites.manage"}})
	manageKey := manageIssued.Key.KeyID + "." + manageIssued.Secret
	readKey := newKey(authA, "sitekey-read", "sites.read")
	otherKey := newKey(authB, "sitekey-other", "sites.read", "sites.manage")
	sitePath := server.URL + "/v1/sites/" + created.ID.String()
	routingPath := sitePath + "/origin-routing"
	call := func(method, path string, body any, credential, idempotency, ifMatch string) *http.Response {
		return apiKeyRequest(t, client, method, path, body, "", credential, idempotency, ifMatch, "")
	}
	ok := func(response *http.Response, status int, what string) {
		t.Helper()
		if response.StatusCode != status {
			t.Fatalf("%s: status %d, want %d: %s", what, response.StatusCode, status, readBody(response.Body))
		}
		response.Body.Close()
	}

	ok(call(http.MethodGet, server.URL+"/v1/sites", nil, readKey, "", ""), http.StatusOK, "list with sites.read key")
	ok(call(http.MethodGet, sitePath, nil, readKey, "", ""), http.StatusOK, "get with sites.read key")
	ok(call(http.MethodGet, routingPath, nil, readKey, "", ""), http.StatusOK, "origin-routing with sites.read key")
	ok(call(http.MethodGet, server.URL+"/v1/sites/"+created.ID.String()+"/origin-status", nil, readKey, "", ""), http.StatusOK,
		"origin-status with sites.read key")

	update := updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: validSiteBasic("sitekey2.example.test", "192.0.2.11")}
	denied := call(http.MethodPatch, sitePath, update, readKey, "sitekey-read-patch", "")
	assertError(t, denied, http.StatusForbidden, "permission_denied", "")
	denied.Body.Close()
	deniedRouting := call(http.MethodPut, routingPath, validHTTPConditionalOriginDocument(), readKey, "sitekey-read-put", `"1"`)
	assertError(t, deniedRouting, http.StatusForbidden, "permission_denied", "")
	deniedRouting.Body.Close()

	var updated siteDetailResponse
	decodeResponse(t, call(http.MethodPatch, sitePath, update, manageKey, "sitekey-patch", ""), http.StatusOK, &updated)
	if updated.Version != 2 || updated.Basic.Domains[0] != "sitekey2.example.test" {
		t.Fatalf("API key PATCH = %#v", updated)
	}
	// The PATCH above moved the site to version 2 (If-Match is the site version).
	ok(call(http.MethodPut, routingPath, validHTTPConditionalOriginDocument(), manageKey, "sitekey-put", `"2"`), http.StatusOK,
		"origin-routing PUT with sites.manage key")

	// Another tenant's key: the site does not exist for it.
	for _, request := range []struct{ method, path string }{{http.MethodGet, sitePath}, {http.MethodGet, routingPath}} {
		cross := call(request.method, request.path, nil, otherKey, "", "")
		assertError(t, cross, http.StatusNotFound, "site_not_found", "")
		cross.Body.Close()
	}
	crossPatch := call(http.MethodPatch, sitePath, updateSiteRequest{ExpectedVersion: 2, Section: "basic",
		Changes: validSiteBasic("evil.example.test", "192.0.2.66")}, otherKey, "sitekey-cross-patch", "")
	assertError(t, crossPatch, http.StatusNotFound, "site_not_found", "")
	crossPatch.Body.Close()

	// Session-only site operations.
	for _, request := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, server.URL + "/v1/sites", createSiteRequest{Basic: validSiteBasic("keycreate.example.test", "192.0.2.12")}},
		{http.MethodPost, server.URL + "/v1/sites/batch-action", map[string]any{"action": "set_protocols",
			"items": []map[string]any{{"id": created.ID, "expected_version": 2}}}},
		{http.MethodDelete, sitePath, nil},
	} {
		refused := call(request.method, request.path, request.body, manageKey, "sitekey-refused-"+uuid.NewString()[:8], `"2"`)
		assertError(t, refused, http.StatusForbidden, "api_key_not_allowed", "")
		refused.Body.Close()
	}
	// Both writes are audited in A's scope as the key owner, marked with the
	// key that acted (plugapi-S2: actor_ref api_key:<id>).
	for _, action := range []string{"site.update", "site.origin_route.update"} {
		var actor *uuid.UUID
		var kind, ref string
		if err := pool.QueryRow(context.Background(), `SELECT actor_user_id, actor_kind, actor_ref FROM audit_events
			WHERE scope_id=$1 AND resource_id=$2 AND action=$3 ORDER BY stream_position DESC LIMIT 1`,
			tenantA.scopeID, created.ID.String(), action).Scan(&actor, &kind, &ref); err != nil {
			t.Fatalf("%s audit: %v", action, err)
		}
		if actor == nil || *actor != tenantA.userID || kind != "user" || ref != "api_key:"+manageIssued.Key.ID.String() {
			t.Fatalf("%s audit = user %v kind %q ref %q, want key owner %s via api_key:%s",
				action, actor, kind, ref, tenantA.userID, manageIssued.Key.ID)
		}
	}
	// The owner's own session write carries no key reference.
	sessionUpdate := updateSiteRequest{ExpectedVersion: 3, Section: "basic", Changes: validSiteBasic("sitekey3.example.test", "192.0.2.13")}
	decodeResponse(t, apiKeyRequest(t, client, http.MethodPatch, sitePath, sessionUpdate, authA.AccessToken, "", "sitekey-session-patch", "", ""),
		http.StatusOK, &updated)
	var sessionRef string
	if err := pool.QueryRow(context.Background(), `SELECT actor_ref FROM audit_events WHERE scope_id=$1 AND resource_id=$2
		AND action='site.update' ORDER BY stream_position DESC LIMIT 1`, tenantA.scopeID, created.ID.String()).Scan(&sessionRef); err != nil {
		t.Fatal(err)
	}
	if sessionRef != "" {
		t.Fatalf("session site.update actor_ref = %q, want empty", sessionRef)
	}
}

// TestSitePluginIdentityAudit (plugapi-S2): site writes made with an API key
// bound to a plugin installation are audited as the plugin (actor_ref
// plugin:<id>, not api_key:<id>) and refused with 401 once it is disabled.
func TestSitePluginIdentityAudit(t *testing.T) {
	pool := isolatedTestPool(t)
	key := newSiteTestKey(t, "control-site-plugin-identity-key")
	trust := newSiteTestTrust(t, key)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{serial: 1, limit: 100, key: key})
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "siteplug-admin",
		"Site Plugin Admin", passwordHash, "siteplug-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "siteplug-a", "siteplug-a-user", "Site Plugin A", passwordHash)
	grantSiteAPIKeySelf(t, pool, tenant.scopeID)
	tokens, err := identity.NewTokenManager("site-plugin-identity-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x55}, 32), EntitlementTrust: trust}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	created := createSite(t, client, server.URL, auth.AccessToken, "siteplug-create",
		createSiteRequest{Basic: validSiteBasic("siteplug.example.test", "192.0.2.20")})

	const pluginID = "io.cdnca.cf-optimize"
	authorizationID, installationID := uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(pluginID))
	if _, err := pool.Exec(context.Background(), `INSERT INTO plugin_installation_heads(
		tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,plugin_version,manifest_sha256,
		configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,status,revision,
		identity_generation,created_at,updated_at,entrypoint_type
	) VALUES($1,$2,$3,$4,$5,'1.0.0',$6,$6,ARRAY['sites.manage'],ARRAY['sites.manage'],ARRAY[]::text[],
		'enabled',1,1,clock_timestamp(),clock_timestamp(),'external_https')`,
		tenant.scopeID, authorizationID, installationID, uuid.New(), pluginID, digest[:]); err != nil {
		t.Fatalf("seed plugin installation: %v", err)
	}
	issued := createSelfAPIKey(t, client, server.URL, auth.AccessToken, "siteplug-key", map[string]any{
		"name": "siteplug", "scopes": []string{"sites.read", "sites.manage"},
		"plugin_installation_authorization_id": authorizationID.String(),
	})
	credential := issued.Key.KeyID + "." + issued.Secret
	sitePath := server.URL + "/v1/sites/" + created.ID.String()
	update := updateSiteRequest{ExpectedVersion: 1, Section: "basic", Changes: validSiteBasic("siteplug2.example.test", "192.0.2.21")}
	var updated siteDetailResponse
	decodeResponse(t, apiKeyRequest(t, client, http.MethodPatch, sitePath, update, "", credential, "siteplug-patch", "", ""),
		http.StatusOK, &updated)
	routing := apiKeyRequest(t, client, http.MethodPut, sitePath+"/origin-routing", validHTTPConditionalOriginDocument(),
		"", credential, "siteplug-put", `"2"`, "")
	if routing.StatusCode != http.StatusOK {
		t.Fatalf("plugin origin-routing PUT status=%d body=%s", routing.StatusCode, readBody(routing.Body))
	}
	routing.Body.Close()
	for _, action := range []string{"site.update", "site.origin_route.update"} {
		var actor uuid.UUID
		var kind, ref, payloadPlugin, payloadInstallation, payloadKey string
		if err := pool.QueryRow(context.Background(), `SELECT actor_user_id, actor_kind, actor_ref, payload->>'plugin_id',
			payload->>'installation_id', payload->>'api_key_id' FROM audit_events
			WHERE scope_id=$1 AND resource_id=$2 AND action=$3 ORDER BY stream_position DESC LIMIT 1`,
			tenant.scopeID, created.ID.String(), action).Scan(&actor, &kind, &ref, &payloadPlugin, &payloadInstallation, &payloadKey); err != nil {
			t.Fatalf("%s audit: %v", action, err)
		}
		if actor != tenant.userID || kind != "plugin" || ref != "plugin:"+pluginID || payloadPlugin != pluginID ||
			payloadInstallation != installationID.String() || payloadKey != issued.Key.ID.String() {
			t.Fatalf("%s audit = user %s kind %q ref %q plugin %q installation %q key %q",
				action, actor, kind, ref, payloadPlugin, payloadInstallation, payloadKey)
		}
	}
	if _, err := pool.Exec(context.Background(), `UPDATE plugin_installation_heads SET status='disabled', revision=revision+1,
		identity_generation=identity_generation+1, updated_at=clock_timestamp()
		WHERE tenant_scope_id=$1 AND authorization_id=$2`, tenant.scopeID, authorizationID); err != nil {
		t.Fatal(err)
	}
	denied := apiKeyRequest(t, client, http.MethodPatch, sitePath, updateSiteRequest{ExpectedVersion: 3, Section: "basic",
		Changes: validSiteBasic("siteplug3.example.test", "192.0.2.22")}, "", credential, "siteplug-after-disable", "", "")
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("write after disable status=%d body=%s", denied.StatusCode, readBody(denied.Body))
	}
	denied.Body.Close()
}

// grantSiteAPIKeySelf lets the tenant_owner of the site fixture create its
// own API keys (the fixture roles carry sites.* only).
func grantSiteAPIKeySelf(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `WITH additions AS (
		INSERT INTO role_permissions(role_id,permission_name)
		SELECT id,'api_keys.self.manage' FROM roles WHERE scope_id=$1 AND name='tenant_owner' AND system_role
		ON CONFLICT DO NOTHING RETURNING role_id,permission_name
	)
	INSERT INTO custom_rbac_system_role_permission_additions(role_id,permission_name)
	SELECT role_id,permission_name FROM additions ON CONFLICT DO NOTHING`, scopeID); err != nil {
		t.Fatalf("grant api_keys.self.manage: %v", err)
	}
}
