package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnshubhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// pluginHubRemote is one tenant DNS account in memory (zone a.example.com).
type pluginHubRemote struct {
	mu      sync.Mutex
	records []dnsproviderremote.ZoneRecord
	next    int
}

func (remote *pluginHubRemote) HostedDomains(context.Context, string, map[string]string) ([]string, error) {
	return []string{"a.example.com"}, nil
}

func (remote *pluginHubRemote) ListHubRecords(_ context.Context, _ dnsproviderremote.ProviderConfig, owner string) ([]dnsproviderremote.ZoneRecord, int, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	var out []dnsproviderremote.ZoneRecord
	for _, record := range remote.records {
		if owner == "" || record.Name == owner {
			out = append(out, record)
		}
	}
	return out, 0, nil
}

func (remote *pluginHubRemote) Lookup(context.Context, dnsproviderremote.ProviderConfig, dnscheck.ProviderOperation) (dnsproviderremote.ReconcileLookup, error) {
	return dnsproviderremote.ReconcileLookup{}, nil
}

func (remote *pluginHubRemote) Mutate(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	remote.mu.Lock()
	defer remote.mu.Unlock()
	remote.next++
	id := "rec-" + strconv.Itoa(remote.next)
	remote.records = append(remote.records, dnsproviderremote.ZoneRecord{ID: id, Name: operation.Name,
		Type: operation.Type, Value: operation.Value, TTL: operation.TTL, Line: operation.Line, Weight: operation.Weight})
	return id, nil
}

// TestPluginIdentityDNSHubRecordWrite (plugapi-S2 on S1's dns.records.manage):
// a DNS hub record write made with an API key bound to a plugin installation
// is audited as the plugin (actor_ref plugin:<id>, not S1's api_key:<id>) and
// refused with 401 once the installation is uninstalled.
func TestPluginIdentityDNSHubRecordWrite(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(ctx, "plugdns-admin", "Plugin DNS Admin", adminHash, "plugdns-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("plugin-dnshub-integration-access-secret-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("plugdns-key", bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	remote := &pluginHubRemote{}
	hub, err := dnsproviderremotesource.NewHub(dnsproviderremotesource.New(pool, cipher), remote, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	pepper := bytes.Repeat([]byte{0x42}, 32)
	var api *Server
	hubHandler, err := dnshubhttp.NewHandler(hub, identityService.AuthenticateSession,
		func(ctx context.Context, raw string) (identity.Principal, uuid.UUID, error) {
			principal, keyID, _, err := api.apiKeys.AuthenticateWithKeyID(ctx, raw)
			return principal, keyID, err
		})
	if err != nil {
		t.Fatal(err)
	}
	api = New(pool, identityService, Config{
		CookieSecure: false, APIKeyPepper: pepper,
		DNSHubHandlerFactory: func() (http.Handler, error) { return hubHandler, nil },
	})
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "plugdns-admin", testPassword)
	createManagedUser(t, client, server.URL, admin.AccessToken, "plugdns-create-alice", map[string]any{
		"username": "plugdns-alice", "password": tenantPassword, "display_name": "Plugin DNS Alice",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	alice, _ := loginWithPassword(t, client, server.URL, "plugdns-alice", tenantPassword)
	if !contains(alice.Principal.Permissions, "dns.records.manage") {
		t.Fatalf("tenant owner lacks dns.records.manage: %v", alice.Principal.Permissions)
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, alice.Principal.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	credentialKey, ciphertext, err := cipher.EncryptCredential(dnsacme.CredentialBinding{
		TenantID: tenantID, ScopeID: alice.Principal.ScopeID, ProviderID: providerID,
	}, []byte(`{"dp_id":"1","dp_key":"key-a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,
		credential_ciphertext,status,created_by_user_id,updated_by_user_id) VALUES($1,$2,'plugdns','dnspod_cn',$3,$4,'verified',$5,$5)`,
		providerID, alice.Principal.ScopeID, credentialKey, ciphertext, alice.Principal.UserID); err != nil {
		t.Fatalf("seed DNS account: %v", err)
	}

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
	issued := createSelfAPIKey(t, client, server.URL, alice.AccessToken, "plugdns-key", map[string]any{
		"name": "cf optimize dns", "scopes": []string{"dns.read", "dns.records.manage"},
		"plugin_installation_authorization_id": authorizationID.String(),
	})
	credential := issued.Key.KeyID + "." + issued.Secret

	// The hub writes into domains it has listed: refresh once with the plugin key.
	refresh := apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/dns/hub/domains/refresh",
		map[string]any{"provider_id": providerID.String()}, "", credential, "plugdns-refresh", "", "plugdns-refresh")
	if refresh.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refresh.StatusCode, readBody(refresh.Body))
	}
	refresh.Body.Close()
	recordsURL := server.URL + "/v1/dns/hub/domains/" + providerID.String() + "/a.example.com/records"
	create := apiKeyRequest(t, client, http.MethodPost, recordsURL, map[string]any{
		"name": "www", "type": "A", "value": "198.51.100.7", "ttl": 600, "line": "电信",
	}, "", credential, "plugdns-create", "", "plugdns-create")
	if create.StatusCode != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", create.StatusCode, readBody(create.Body))
	}
	create.Body.Close()

	var kind, ref, payloadPlugin, payloadInstallation, payloadKey string
	var actorUser uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT actor_kind, actor_ref, actor_user_id, payload->>'plugin_id',
		payload->>'installation_id', payload->>'api_key_id'
		FROM audit_events WHERE request_id='plugdns-create' AND resource_type='dns_record'
		ORDER BY stream_position DESC LIMIT 1`).Scan(
		&kind, &ref, &actorUser, &payloadPlugin, &payloadInstallation, &payloadKey); err != nil {
		t.Fatalf("read DNS record audit: %v", err)
	}
	if kind != "plugin" || ref != "plugin:"+pluginID || actorUser != alice.Principal.UserID ||
		payloadPlugin != pluginID || payloadInstallation != installationID.String() || payloadKey != issued.Key.ID.String() {
		t.Fatalf("DNS record audit = kind %q ref %q user %s plugin %q installation %q key %q",
			kind, ref, actorUser, payloadPlugin, payloadInstallation, payloadKey)
	}

	if _, err := pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='uninstalled', revision=revision+1,
		identity_generation=identity_generation+1, updated_at=clock_timestamp()
		WHERE tenant_scope_id=$1 AND authorization_id=$2`, alice.Principal.ScopeID, authorizationID); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	writes := len(remote.records)
	denied := apiKeyRequest(t, client, http.MethodPost, recordsURL, map[string]any{
		"name": "www2", "type": "A", "value": "198.51.100.8", "ttl": 600, "line": "联通",
	}, "", credential, "plugdns-after-uninstall", "", "plugdns-after-uninstall")
	if denied.StatusCode != http.StatusUnauthorized {
		t.Fatalf("write after uninstall status=%d body=%s", denied.StatusCode, readBody(denied.Body))
	}
	denied.Body.Close()
	if len(remote.records) != writes {
		t.Fatal("a write after uninstall reached the provider")
	}
}
