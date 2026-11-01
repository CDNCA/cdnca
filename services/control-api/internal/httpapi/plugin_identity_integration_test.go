package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// TestPluginIdentityAPIKeyHTTPFlow (plugapi-S2, ADR 0007 §3.2): a tenant
// issues an API key bound to an enabled plugin installation; its writes are
// audited as actor_kind=plugin with plugin_id / installation_id, limited per
// installation (429 + Retry-After), and refused with 401 once the
// installation is disabled.
func TestPluginIdentityAPIKeyHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(ctx, "plugid-admin", "Plugin Identity Admin", adminHash, "plugid-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("plugin-identity-integration-access-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var currentNow time.Time
	if err := pool.QueryRow(ctx, `SELECT date_trunc('second',clock_timestamp())`).Scan(&currentNow); err != nil {
		t.Fatal(err)
	}
	currentNow = currentNow.UTC()
	api := New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: bytes.Repeat([]byte{0x42}, 32), Now: func() time.Time { return currentNow },
	})
	api.pluginWriteLimiter.limit = 2
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "plugid-admin", testPassword)
	createManagedUser(t, client, server.URL, admin.AccessToken, "plugid-create-alice", map[string]any{
		"username": "plugid-alice", "password": tenantPassword, "display_name": "Plugin Identity Alice",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	alice, _ := loginWithPassword(t, client, server.URL, "plugid-alice", tenantPassword)

	const pluginID = "io.cdnca.cf-optimize"
	authorizationID, installationID := uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte(pluginID))
	if _, err := pool.Exec(ctx, `INSERT INTO plugin_installation_heads(
		tenant_scope_id,authorization_id,installation_id,verification_id,plugin_id,plugin_version,manifest_sha256,
		configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,status,revision,
		identity_generation,created_at,updated_at,entrypoint_type
	) VALUES($1,$2,$3,$4,$5,'1.0.0',$6,$6,ARRAY['dns.records.manage'],ARRAY['dns.records.manage'],ARRAY[]::text[],
		'enabled',1,1,clock_timestamp(),clock_timestamp(),'external_https')`,
		alice.Principal.ScopeID, authorizationID, installationID, uuid.New(), pluginID, digest[:]); err != nil {
		t.Fatalf("seed plugin installation: %v", err)
	}

	t.Run("binding requires an enabled installation of this tenant", func(t *testing.T) {
		response := apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/account/api-keys", map[string]any{
			"name": "unknown installation", "scopes": []string{"security_policies.manage"},
			"plugin_installation_authorization_id": uuid.NewString(),
		}, alice.AccessToken, "", "plugid-unknown", `"0"`, "plugid-unknown")
		assertError(t, response, http.StatusConflict, "plugin_installation_unavailable", "plugid-unknown")
		response.Body.Close()
	})

	issued := createSelfAPIKey(t, client, server.URL, alice.AccessToken, "plugid-create", map[string]any{
		"name": "cf optimize", "scopes": []string{"security_policies.read", "security_policies.manage"},
		"plugin_installation_authorization_id": authorizationID.String(),
	})
	if issued.Key.PluginInstallationAuthorizationID == nil || *issued.Key.PluginInstallationAuthorizationID != authorizationID ||
		issued.Key.PluginInstallationID == nil || *issued.Key.PluginInstallationID != installationID ||
		issued.Key.PluginID == nil || *issued.Key.PluginID != pluginID {
		t.Fatalf("issued plugin key binding = %#v", issued.Key)
	}
	credential := issued.Key.KeyID + "." + issued.Secret
	createList := func(name string) *http.Response {
		return apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/security-ip-lists", map[string]any{
			"name": name, "description": "", "entries": []string{"198.51.100.0/24"},
		}, "", credential, name, "", name)
	}

	t.Run("plugin writes are audited as the plugin", func(t *testing.T) {
		response := createList("plugid-list-1")
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("plugin write status=%d body=%s", response.StatusCode, readBody(response.Body))
		}
		response.Body.Close()
		var kind, ref, payloadPlugin, payloadInstallation, payloadKey string
		var actorUser uuid.UUID
		if err := pool.QueryRow(ctx, `SELECT actor_kind, actor_ref, actor_user_id, payload->>'plugin_id',
			payload->>'installation_id', payload->>'api_key_id'
			FROM audit_events WHERE request_id='plugid-list-1' ORDER BY stream_position DESC LIMIT 1`).Scan(
			&kind, &ref, &actorUser, &payloadPlugin, &payloadInstallation, &payloadKey); err != nil {
			t.Fatalf("read plugin write audit: %v", err)
		}
		if kind != "plugin" || ref != "plugin:"+pluginID || actorUser != alice.Principal.UserID ||
			payloadPlugin != pluginID || payloadInstallation != installationID.String() || payloadKey != issued.Key.ID.String() {
			t.Fatalf("audit = kind %q ref %q user %s plugin %q installation %q key %q",
				kind, ref, actorUser, payloadPlugin, payloadInstallation, payloadKey)
		}
	})

	t.Run("writes over the per-installation limit get 429 with Retry-After", func(t *testing.T) {
		response := createList("plugid-list-2")
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("second write status=%d body=%s", response.StatusCode, readBody(response.Body))
		}
		response.Body.Close()
		for i := 3; i <= 4; i++ {
			limited := createList(fmt.Sprintf("plugid-list-%d", i))
			if limited.Header.Get("Retry-After") == "" {
				t.Fatalf("429 without Retry-After")
			}
			assertError(t, limited, http.StatusTooManyRequests, "plugin_rate_limited", fmt.Sprintf("plugid-list-%d", i))
			limited.Body.Close()
		}
		// Reads are not limited.
		read := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/security-ip-lists", nil, "", credential, "", "", "plugid-read")
		if read.StatusCode != http.StatusOK {
			t.Fatalf("plugin read status=%d body=%s", read.StatusCode, readBody(read.Body))
		}
		read.Body.Close()
		var refusals int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='plugin.api.rate_limited'
			AND actor_kind='plugin' AND resource_id=$1 AND result='denied'`, authorizationID.String()).Scan(&refusals); err != nil {
			t.Fatal(err)
		}
		if refusals != 1 {
			t.Fatalf("rate limit audit events = %d, want 1 per window", refusals)
		}
		currentNow = currentNow.Add(time.Minute)
	})

	t.Run("disabling the installation revokes the key at once", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='disabled', revision=revision+1,
			identity_generation=identity_generation+1, updated_at=clock_timestamp()
			WHERE tenant_scope_id=$1 AND authorization_id=$2`, alice.Principal.ScopeID, authorizationID); err != nil {
			t.Fatalf("disable installation: %v", err)
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			var response *http.Response
			if method == http.MethodGet {
				response = apiKeyRequest(t, client, method, server.URL+"/v1/security-ip-lists", nil, "", credential, "", "", "plugid-revoked")
			} else {
				response = createList("plugid-revoked")
			}
			assertError(t, response, http.StatusUnauthorized, "invalid_session", "plugid-revoked")
			response.Body.Close()
		}
	})
}
