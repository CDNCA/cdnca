package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsmaintenance"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type platformCredentialVerifier struct{ calls int }

func (v *platformCredentialVerifier) Verify(context.Context, string, string) error { return nil }

func (v *platformCredentialVerifier) VerifyCredentials(_ context.Context, providerType string, credentials map[string]string) error {
	v.calls++
	if providerType == "dnspod_cn" && credentials["dp_key"] == "rejected" {
		return dnsacme.ErrProviderCredentialsRejected
	}
	return nil
}

func TestPlatformDNSConfigHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(t.Context(), "dns-platform-admin", "DNS Platform Admin", passwordHash,
		"dns-platform-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenantA := insertDNSTenant(t, pool, "dns-platform-a", "dns-platform-user-a", passwordHash, []string{"dns.read", "dns.manage"})
	tenantB := insertDNSTenant(t, pool, "dns-platform-b", "dns-platform-user-b", passwordHash, []string{"dns.read", "dns.manage"})
	tokens, err := identity.NewTokenManager("dns-platform-integration-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-platform-v1", bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier := &platformCredentialVerifier{}
	provider := &platformFakeProvider{records: map[string]dnsproviderremote.ZoneRecord{}}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, DNSCredentialCipher: cipher, DNSProviderVerifier: verifier, DNSRecordLister: provider,
		// 迁移 473 起区的托管根域由解析器查，不注入就会用假凭据访问真实 provider
		DNSZoneApexResolver: hostedDomainsResolver{hosted: []string{"example.com"}},
		APIKeyPepper:        bytes.Repeat([]byte{0x42}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginOK(t, client, server.URL, "dns-platform-admin")
	tenantAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)

	get := func() dnsacme.PlatformConfig {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/dns/platform-config", nil, admin.AccessToken, "", "")
		var config dnsacme.PlatformConfig
		decodeResponse(t, response, http.StatusOK, &config)
		response.Body.Close()
		return config
	}
	config := get()
	if config.ProviderType != "" || config.TTL != 600 || config.Revision != 1 || config.LastError != nil {
		t.Fatalf("initial platform DNS config = %+v", config)
	}

	t.Run("tenant principals cannot use the platform configuration", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/dns/platform-config", nil, tenantAuth.AccessToken, "", "")
		assertError(t, response, http.StatusForbidden, "dns_platform_only", "")
		response.Body.Close()
	})

	zone := createPlatformZone(t, client, server.URL, admin.AccessToken, "zone-a", "CDN.Example.com", "主域名")
	if zone.Name != "cdn.example.com" || zone.DisplayID < 1 || zone.InUse {
		t.Fatalf("created platform zone = %+v", zone)
	}

	t.Run("rejected credentials are not saved", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
			"provider_type": "dnspod_cn", "credentials": map[string]string{"dp_id": "269638", "dp_key": "rejected"},
			"ttl": 600, "ip_weight": true,
		}, admin.AccessToken, "platform-config-rejected", `"1"`)
		assertError(t, response, http.StatusUnprocessableEntity, "provider_credentials_rejected", "")
		response.Body.Close()
		if after := get(); after.ProviderType != "" || after.Revision != 1 {
			t.Fatalf("rejected credentials changed the config: %+v", after)
		}
	})

	response := siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
		"provider_type": "dnspod_cn", "credentials": map[string]string{"dp_id": "269638", "dp_key": "secret-token"},
		"ttl": 300, "ip_weight": true,
	}, admin.AccessToken, "platform-config-save", `"1"`)
	decodeResponse(t, response, http.StatusOK, &config)
	body := readBody(response.Body)
	response.Body.Close()
	if config.ProviderType != "dnspod_cn" || config.Identifiers["dp_id"] != "269638" || !config.SecretSaved ||
		config.TTL != 300 || !config.IPWeight || !config.WeightSupported || config.Revision != 2 ||
		config.Sync.Tenants != 2 || config.Sync.Error != "" || bytes.Contains([]byte(body), []byte("secret-token")) {
		t.Fatalf("saved platform DNS config = %+v", config)
	}

	t.Run("every tenant receives a verified provider, the default zone and the TTL", func(t *testing.T) {
		for _, tenant := range []dnsTenantFixture{tenantA, tenantB} {
			var providerType, status, zoneName string
			var isDefault bool
			var ttl int
			var keyID string
			var ciphertext []byte
			var providerID uuid.UUID
			if err := pool.QueryRow(t.Context(), `SELECT provider.id, provider.provider_type, provider.status,
					provider.credential_key_id, provider.credential_ciphertext, zone.name, zone.is_default, settings.ttl
				FROM dns_providers provider
				JOIN dns_zones zone ON zone.scope_id=provider.scope_id AND zone.provider_id=provider.id
				JOIN dns_legacy_settings settings ON settings.scope_id=provider.scope_id
				WHERE provider.scope_id=$1`, tenant.scopeID).Scan(&providerID, &providerType, &status, &keyID, &ciphertext,
				&zoneName, &isDefault, &ttl); err != nil {
				t.Fatalf("tenant %s copy: %v", tenant.username, err)
			}
			if providerType != "dnspod_cn" || status != "verified" || zoneName != "cdn.example.com" || !isDefault ||
				ttl != 300 {
				t.Fatalf("tenant copy = %s %s %s default=%t ttl=%d", providerType, status, zoneName, isDefault, ttl)
			}
			var tenantID uuid.UUID
			if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
				t.Fatal(err)
			}
			plaintext, err := cipher.DecryptCredential(dnsacme.CredentialBinding{TenantID: tenantID, ScopeID: tenant.scopeID,
				ProviderID: providerID}, keyID, ciphertext)
			if err != nil || string(plaintext) != `{"dp_id":"269638","dp_key":"secret-token"}` {
				t.Fatalf("tenant credential = %q, %v", plaintext, err)
			}
		}
	})

	t.Run("saving without credentials keeps them and switching provider requires new ones", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
			"provider_type": "dnspod_cn", "ttl": 900, "ip_weight": false,
		}, admin.AccessToken, "platform-config-ttl", `"2"`)
		decodeResponse(t, response, http.StatusOK, &config)
		response.Body.Close()
		if config.TTL != 900 || config.IPWeight || !config.SecretSaved || verifier.calls != 2 {
			t.Fatalf("ttl-only save = %+v calls=%d", config, verifier.calls)
		}
		response = siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
			"provider_type": "cloudflare", "ttl": 900, "ip_weight": false,
		}, admin.AccessToken, "platform-config-switch", `"3"`)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	// 连接测试 verifies entered or saved credentials
	// and lists hosted CNAME domains without saving or writing anything.
	t.Run("connection test is read-only", func(t *testing.T) {
		before := get()
		calls := verifier.calls
		writes := len(provider.deleted)
		test := func(t *testing.T, body map[string]any) *http.Response {
			t.Helper()
			return siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/connection-test", body,
				admin.AccessToken, "", "")
		}
		var result dnsacme.PlatformConnection
		response := test(t, map[string]any{"provider_type": "dnspod_cn"})
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if result.ProviderType != "dnspod_cn" || len(result.Zones) != 1 || result.Zones[0].Name != "cdn.example.com" ||
			result.Zones[0].Status != dnsacme.PlatformZoneHosted || result.Zones[0].Apex != "example.com" {
			t.Fatalf("saved credentials connection = %+v", result)
		}
		response = test(t, map[string]any{"provider_type": "dnspod_cn",
			"credentials": map[string]string{"dp_id": "269638", "dp_key": "rejected"}})
		assertError(t, response, http.StatusUnprocessableEntity, "provider_credentials_rejected", "")
		response.Body.Close()
		response = test(t, map[string]any{"provider_type": "cloudflare"})
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/connection-test",
			map[string]any{"provider_type": "dnspod_cn"}, tenantAuth.AccessToken, "", "")
		assertError(t, response, http.StatusForbidden, "dns_platform_only", "")
		response.Body.Close()
		if after := get(); after.Revision != before.Revision || verifier.calls != calls+2 || len(provider.deleted) != writes {
			t.Fatalf("connection test changed state: revision %d->%d verify calls %d->%d writes %d->%d",
				before.Revision, after.Revision, calls, verifier.calls, writes, len(provider.deleted))
		}
	})

	t.Run("a domain with allocated sites cannot be renamed or deleted", func(t *testing.T) {
		markPlatformZoneInUse(t, pool, tenantA.scopeID, "cdn.example.com")
		page := listPlatformZones(t, client, server.URL, admin.AccessToken, "")
		if page.Total != 1 || !page.Items[0].InUse {
			t.Fatalf("zone page = %+v", page)
		}
		version := fmt.Sprintf(`"%d"`, page.Items[0].Revision)
		response := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/platform-zones/"+zone.ID.String(), nil,
			admin.AccessToken, "zone-delete-in-use", version)
		assertError(t, response, http.StatusConflict, "dns_zone_in_use", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/platform-zones/"+zone.ID.String(),
			map[string]string{"name": "other.example.com", "remark": ""}, admin.AccessToken, "zone-rename-in-use", version)
		assertError(t, response, http.StatusConflict, "dns_zone_in_use", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/platform-zones/"+zone.ID.String(),
			map[string]string{"name": "cdn.example.com", "remark": "新备注"}, admin.AccessToken, "zone-remark", version)
		var updated dnsacme.PlatformZone
		decodeResponse(t, response, http.StatusOK, &updated)
		response.Body.Close()
		if updated.Remark != "新备注" || !updated.InUse {
			t.Fatalf("remark update = %+v", updated)
		}
	})

	t.Run("an unused domain is deleted with its tenant copies", func(t *testing.T) {
		spare := createPlatformZone(t, client, server.URL, admin.AccessToken, "zone-spare", "spare.example.com", "")
		if page := listPlatformZones(t, client, server.URL, admin.AccessToken, "spare"); page.Total != 1 {
			t.Fatalf("search page = %+v", page)
		}
		response := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/platform-zones/"+spare.ID.String(), nil,
			admin.AccessToken, "zone-delete-spare", fmt.Sprintf(`"%d"`, spare.Revision))
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("delete spare status = %d %s", response.StatusCode, readBody(response.Body))
		}
		response.Body.Close()
		var copies int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_zones WHERE name='spare.example.com'`).Scan(&copies); err != nil || copies != 0 {
			t.Fatalf("spare tenant copies = %d, %v", copies, err)
		}
	})

	t.Run("repair without allocated CNAMEs queues one job with nothing to repair", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/repair", map[string]any{},
			admin.AccessToken, "platform-repair-1", "")
		var result platformDNSOperationResponse
		decodeResponse(t, response, http.StatusAccepted, &result)
		response.Body.Close()
		if len(result.Operations) != 1 || result.Replayed || result.Operations[0].Kind != "dns.repair.v1" ||
			result.Operations[0].Subject != "DNS记录修复" || result.Operations[0].Progress.Total != 1 {
			t.Fatalf("repair operations = %+v", result)
		}
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/repair", map[string]any{},
			admin.AccessToken, "platform-repair-1", "")
		decodeResponse(t, response, http.StatusAccepted, &result)
		response.Body.Close()
		if len(result.Operations) != 1 || !result.Replayed {
			t.Fatalf("replayed repair = %+v", result)
		}
	})

	t.Run("cleanup deletes only records that are no allocated CNAME", func(t *testing.T) {
		for _, record := range []dnsproviderremote.ZoneRecord{
			{ID: "apex", Name: "cdn.example.com.", Type: dnscheck.RecordA, Value: "198.51.100.1", TTL: 600},
			{ID: "site", Name: "site1.cdn.example.com.", Type: dnscheck.RecordA, Value: "192.0.2.1", TTL: 600},
			{ID: "old", Name: "old.cdn.example.com.", Type: dnscheck.RecordA, Value: "198.51.100.7", TTL: 600},
		} {
			provider.records[record.ID] = record
		}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/cleanup", map[string]any{},
			admin.AccessToken, "platform-cleanup-1", "")
		var result platformDNSOperationResponse
		decodeResponse(t, response, http.StatusAccepted, &result)
		response.Body.Close()
		if len(result.Operations) != 1 || result.Operations[0].Kind != "dns.cleanup.v1" || result.Operations[0].Progress.Total != 1 {
			t.Fatalf("cleanup operations = %+v", result)
		}
		var item string
		if err := pool.QueryRow(t.Context(), `SELECT item_id FROM background_job_items WHERE job_id=$1`,
			result.Operations[0].ID).Scan(&item); err != nil || !strings.HasPrefix(item, "删除记录 old.cdn.example.com A 198.51.100.7 #") {
			t.Fatalf("cleanup item = %q, %v", item, err)
		}
		jobs, err := jobstate.NewStore(pool, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		store, _ := dnsmaintenance.NewStore(pool)
		worker, err := dnsmaintenance.NewWorker(dnsmaintenance.WorkerConfig{WorkerID: "test-maintenance", PollInterval: time.Second,
			LeaseDuration: time.Minute, ItemTimeout: time.Second, TaskPoll: time.Millisecond},
			jobs, store, dnsacme.NewService(dnsacme.NewStore(pool), cipher), provider, unusedReconcile{})
		if err != nil {
			t.Fatal(err)
		}
		if err := worker.RunOnce(t.Context()); err != nil {
			t.Fatalf("maintenance RunOnce() error = %v", err)
		}
		var state string
		if err := pool.QueryRow(t.Context(), `SELECT state FROM background_jobs WHERE id=$1`, result.Operations[0].ID).Scan(&state); err != nil ||
			state != "succeeded" {
			t.Fatalf("cleanup job state = %q, %v", state, err)
		}
		if len(provider.deleted) != 1 || provider.deleted[0] != "old" {
			t.Fatalf("deleted = %v", provider.deleted)
		}
		config = get()
		if config.LastError != nil {
			t.Fatalf("last error after a successful cleanup = %+v", config.LastError)
		}
	})

	t.Run("a carrier line outside the DNS plan shows as the newest DNS error", func(t *testing.T) {
		siteID := uuid.New()
		if err := pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(context.Background(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id,display_id) VALUES($1,$2,$3,'line-plan.example.com',ARRAY['192.0.2.10:80'],
				ARRAY['192.0.2.10'],$3,$3,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
				siteID, tenantA.scopeID, tenantA.userID); err != nil {
				return err
			}
			if _, err := tx.Exec(context.Background(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
				return err
			}
			_, err := tx.Exec(context.Background(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, siteID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(context.Background(), `INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,
			publish_error,next_attempt_at,updated_at) VALUES($1,'overseas',repeat('a',64),'dns_line_not_in_plan',now(),now()+interval '1 hour')`,
			siteID); err != nil {
			t.Fatal(err)
		}
		config := get()
		if config.LastError == nil || config.LastError.Source != "cname_line" || config.LastError.Code != "dns_line_not_in_plan" ||
			config.LastError.Message != "overseas" {
			t.Fatalf("last error = %+v", config.LastError)
		}
	})
}

type platformFakeProvider struct {
	records map[string]dnsproviderremote.ZoneRecord
	deleted []string
}

func (provider *platformFakeProvider) ListZoneRecords(_ context.Context, config dnsproviderremote.ProviderConfig, owner string) ([]dnsproviderremote.ZoneRecord, error) {
	result := make([]dnsproviderremote.ZoneRecord, 0)
	for _, record := range provider.records {
		if (owner == "" || record.Name == owner) && strings.HasSuffix(record.Name, config.ZoneName+".") {
			result = append(result, record)
		}
	}
	return result, nil
}

func (provider *platformFakeProvider) Mutate(_ context.Context, _ dnsproviderremote.ProviderConfig, operation dnscheck.ProviderOperation) (string, error) {
	delete(provider.records, operation.RecordID)
	provider.deleted = append(provider.deleted, operation.RecordID)
	return operation.RecordID, nil
}

type unusedReconcile struct{}

func (unusedReconcile) Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, dnsreconcile.ErrUnavailable
}
func (unusedReconcile) Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, dnsreconcile.ErrUnavailable
}
func (unusedReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	return dnsreconcile.Task{}, dnsreconcile.ErrUnavailable
}

func createPlatformZone(t *testing.T, client *http.Client, baseURL, token, key, name, remark string) dnsacme.PlatformZone {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/dns/platform-zones",
		map[string]string{"name": name, "remark": remark}, token, key, "")
	var zone dnsacme.PlatformZone
	decodeResponse(t, response, http.StatusCreated, &zone)
	response.Body.Close()
	return zone
}

func listPlatformZones(t *testing.T, client *http.Client, baseURL, token, search string) dnsacme.PlatformZonePage {
	t.Helper()
	response := siteRequest(t, client, http.MethodGet, baseURL+"/v1/dns/platform-zones?page=1&limit=10&search="+search,
		nil, token, "", "")
	var page dnsacme.PlatformZonePage
	decodeResponse(t, response, http.StatusOK, &page)
	response.Body.Close()
	return page
}

// markPlatformZoneInUse records a CNAME hostname claim under the tenant copy
// of the zone. Allocation facts are not the subject here, so their referential
// triggers are bypassed for this one row (superuser test database).
func markPlatformZoneInUse(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, zoneName string) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO cname_hostname_claims(id, tenant_scope_id, allocation_id, generation,
			provider_id, zone_id, domain, hostname, explicit_hostname, hmac_key_id, created_at)
		SELECT gen_random_uuid(), zone.scope_id, gen_random_uuid(), 1, zone.provider_id, zone.id, zone.name,
			'site1.' || zone.name, false, 'test-key', now()
		FROM dns_zones zone WHERE zone.scope_id=$1 AND zone.name=$2`, scopeID, zoneName); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}
