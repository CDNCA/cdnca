package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDNSAndCertificateHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	platform, err := identityStore.BootstrapPlatformUser(
		context.Background(), "dnsadmin", "DNS Administrator", passwordHash, "dns-bootstrap",
	)
	if err != nil {
		t.Fatalf("BootstrapPlatformUser() error = %v", err)
	}
	tenantA := insertDNSTenant(t, pool, "dns-tenant-a", "dns-user-a", passwordHash, []string{
		"dns.read", "dns.manage", "certificates.read", "certificates.manage",
	})
	tenantB := insertDNSTenant(t, pool, "dns-tenant-b", "dns-user-b", passwordHash, []string{
		"dns.read", "dns.manage", "certificates.read", "certificates.manage",
	})
	reader := insertDNSTenant(t, pool, "dns-reader-tenant", "dns-reader", passwordHash, []string{
		"dns.read", "certificates.read",
	})

	tokens, err := identity.NewTokenManager("dns-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-test-v1", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher() error = %v", err)
	}
	// Certificate orders require a verified lease with certificates.issue.
	leaseKey := newSiteTestKey(t, "dns-acme-test-key")
	trust := newSiteTestTrust(t, leaseKey)
	installSiteTestEntitlement(t, pool, trust, time.Now(), siteTestLeaseOptions{
		serial: 1, limit: 100, key: leaseKey, extraFeatures: []string{entitlementguard.FeatureCertificatesIssue},
	})
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, EntitlementTrust: trust,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	readerAuth := loginForScope(t, client, server.URL, reader.username, reader.scopeID)

	t.Run("authentication and permission deny", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/dns/providers", nil, "", "", "")
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/providers", createDNSProviderRequest{
			Name: "denied", ProviderType: "cloudflare", Credentials: map[string]string{"token": "denied"},
		}, readerAuth.AccessToken, "reader-create", "")
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
	})

	secret := "low-entropy-test-secret"
	providerA := createDNSProvider(t, client, server.URL, tenantAAuth.AccessToken, "provider-a", createDNSProviderRequest{
		Name: "Tenant A Cloudflare", ProviderType: "cloudflare",
		Credentials: map[string]string{"api_token": secret},
	})
	if providerA.Status != dnsacme.ProviderStatusUnverified || !providerA.CredentialsConfigured {
		t.Fatalf("created provider = %#v", providerA)
	}

	t.Run("credential is ciphertext and never exposed", func(t *testing.T) {
		var keyID string
		var ciphertext []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT credential_key_id, credential_ciphertext FROM dns_providers WHERE id=$1`, providerA.ID,
		).Scan(&keyID, &ciphertext); err != nil {
			t.Fatalf("read stored credential: %v", err)
		}
		if keyID != "dns-test-v1" || bytes.Contains(ciphertext, []byte(secret)) {
			t.Fatalf("stored credential key=%q contains plaintext=%t", keyID, bytes.Contains(ciphertext, []byte(secret)))
		}
		// Provider credentials are envelope-bound to tenant/scope/provider; the
		// unbound Decrypt path must not open them.
		if _, err := cipher.Decrypt(keyID, ciphertext); err == nil {
			t.Fatal("unbound Decrypt opened a provider-bound credential envelope")
		}
		plaintext, err := cipher.DecryptCredential(dnsacme.CredentialBinding{
			TenantID: tenantA.tenantID, ScopeID: tenantA.scopeID, ProviderID: providerA.ID,
		}, keyID, ciphertext)
		if err != nil || string(plaintext) != `{"api_token":"low-entropy-test-secret"}` {
			t.Fatalf("decrypted credential = %q, error=%v", plaintext, err)
		}
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/dns/providers", nil, tenantAAuth.AccessToken, "", "")
		body := readBody(response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusOK || bytes.Contains([]byte(body), []byte(secret)) ||
			bytes.Contains([]byte(body), []byte("credential_hint")) {
			t.Fatalf("provider list status=%d body=%s", response.StatusCode, body)
		}
		var auditPayload []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT payload::text FROM audit_events
			WHERE action='dns.provider.create' AND resource_id=$1`, providerA.ID.String(),
		).Scan(&auditPayload); err != nil {
			t.Fatalf("read provider audit: %v", err)
		}
		if bytes.Contains(auditPayload, []byte(secret)) || bytes.Contains(auditPayload, []byte("credential_hint")) {
			t.Fatalf("audit leaked credential-derived data: %s", auditPayload)
		}
	})

	t.Run("idempotency replay and conflict", func(t *testing.T) {
		replayed := createDNSProvider(t, client, server.URL, tenantAAuth.AccessToken, "provider-a", createDNSProviderRequest{
			Name: "Tenant A Cloudflare", ProviderType: "cloudflare",
			Credentials: map[string]string{"api_token": secret},
		})
		if replayed.ID != providerA.ID {
			t.Fatalf("replayed provider ID=%s want=%s", replayed.ID, providerA.ID)
		}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/providers", createDNSProviderRequest{
			Name: "Changed", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": secret},
		}, tenantAAuth.AccessToken, "provider-a", "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()
	})

	providerB := createDNSProvider(t, client, server.URL, tenantBAuth.AccessToken, "provider-b", createDNSProviderRequest{
		Name: "Tenant B Aliyun", ProviderType: "aliyun", Credentials: map[string]string{
			"access_key_id": "tenant-b-id", "access_key_secret": "tenant-b-secret"},
	})

	t.Run("concurrent same key creates one provider", func(t *testing.T) {
		body := createDNSProviderRequest{
			Name: "Concurrent", ProviderType: "huawei", Credentials: map[string]string{
				"access_key": "concurrent-ak", "secret_key": "concurrent-secret",
				"region": "cn-north-4", "project_id": "0123456789abcdef0123456789abcdef"},
		}
		type outcome struct {
			status int
			id     uuid.UUID
			err    error
		}
		results := concurrentDNSRequests(2, func() outcome {
			response, err := performSiteRequest(client, http.MethodPost, server.URL+"/v1/dns/providers", body,
				tenantAAuth.AccessToken, "provider-concurrent", "")
			if err != nil {
				return outcome{err: err}
			}
			defer response.Body.Close()
			var provider dnsacme.Provider
			err = json.NewDecoder(response.Body).Decode(&provider)
			return outcome{status: response.StatusCode, id: provider.ID, err: err}
		})
		if results[0].err != nil || results[1].err != nil || results[0].status != http.StatusCreated ||
			results[1].status != http.StatusCreated || results[0].id != results[1].id {
			t.Fatalf("concurrent provider results = %#v", results)
		}
	})

	t.Run("cross tenant references are hidden", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/zones", createDNSZoneRequest{
			ProviderID: providerB.ID.String(), Name: "example.com",
		}, tenantAAuth.AccessToken, "cross-zone", "")
		assertError(t, response, http.StatusNotFound, "dns_resource_not_found", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/certificate-orders", createCertificateOrderRequest{
			DNSProviderID: providerB.ID.String(), Domains: []string{"example.com"}, ChallengeType: "dns-01", AutoRenew: true,
		}, tenantAAuth.AccessToken, "cross-order", "")
		assertError(t, response, http.StatusNotFound, "dns_resource_not_found", "")
		response.Body.Close()
	})

	zoneA := createDNSZone(t, client, server.URL, tenantAAuth.AccessToken, "zone-a", createDNSZoneRequest{
		ProviderID: providerA.ID.String(), Name: "Example.COM.",
	})
	recordA := createDNSRecord(t, client, server.URL, tenantAAuth.AccessToken, "record-a", createDNSRecordRequest{
		ZoneID: zoneA.ID.String(), Name: "www", Type: "A", Content: "192.0.2.10", TTL: 300,
	})
	if zoneA.Name != "example.com" || zoneA.Status != dnsacme.ResourceStatusDraft || recordA.Status != dnsacme.ResourceStatusDraft {
		t.Fatalf("zone=%#v record=%#v", zoneA, recordA)
	}

	t.Run("first zone of a scope becomes the default CNAME zone", func(t *testing.T) {
		second := createDNSZone(t, client, server.URL, tenantAAuth.AccessToken, "zone-a-second", createDNSZoneRequest{
			ProviderID: providerA.ID.String(), Name: "second.example.com",
		})
		var firstDefault, secondDefault bool
		if err := pool.QueryRow(context.Background(), `SELECT
			(SELECT is_default FROM dns_zones WHERE id=$1), (SELECT is_default FROM dns_zones WHERE id=$2)`,
			zoneA.ID, second.ID).Scan(&firstDefault, &secondDefault); err != nil {
			t.Fatal(err)
		}
		if !firstDefault || secondDefault {
			t.Fatalf("default zones: first=%v second=%v", firstDefault, secondDefault)
		}
	})

	t.Run("record validation and optimistic concurrency", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/records", createDNSRecordRequest{
			ZoneID: zoneA.ID.String(), Name: "www", Type: "A", Content: "2001:db8::1", TTL: 300,
		}, tenantAAuth.AccessToken, "invalid-record", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
		ipv6 := createDNSRecord(t, client, server.URL, tenantAAuth.AccessToken, "record-aaaa", createDNSRecordRequest{
			ZoneID: zoneA.ID.String(), Name: "ipv6", Type: "AAAA", Content: "2001:db8::10", TTL: 600,
		})
		if ipv6.Type != "AAAA" || ipv6.Content != "2001:db8::10" {
			t.Fatalf("IPv6 record = %#v", ipv6)
		}

		update := updateDNSRecordRequest{ExpectedVersion: 1, Name: "www", Type: "A", Content: "192.0.2.11", TTL: 600}
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/records/"+recordA.ID.String(),
			update, tenantAAuth.AccessToken, "record-update", "")
		var updated dnsacme.Record
		decodeResponse(t, response, http.StatusOK, &updated)
		response.Body.Close()
		if updated.Revision != 2 || updated.Content != "192.0.2.11" {
			t.Fatalf("updated record = %#v", updated)
		}
		response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/records/"+recordA.ID.String(),
			update, tenantAAuth.AccessToken, "record-stale", "")
		assertError(t, response, http.StatusConflict, "version_conflict", "")
		response.Body.Close()
	})

	t.Run("wildcard requires DNS challenge and orders remain pending", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/certificate-orders", createCertificateOrderRequest{
			Domains: []string{"*.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		}, tenantAAuth.AccessToken, "wildcard-http", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	orderA := createCertificateOrder(t, client, server.URL, tenantAAuth.AccessToken, "order-a", createCertificateOrderRequest{
		DNSProviderID: providerA.ID.String(), Domains: []string{"www.example.com", "*.example.com"},
		ChallengeType: "dns-01", AutoRenew: true,
	})
	if orderA.Status != dnsacme.OrderPending || orderA.NotAfter != nil {
		t.Fatalf("new order = %#v", orderA)
	}
	var outboxStatus string
	var outboxPayload []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT status, payload::text FROM dns_acme_outbox
		WHERE aggregate_type='certificate_order' AND aggregate_id=$1`, orderA.ID,
	).Scan(&outboxStatus, &outboxPayload); err != nil {
		t.Fatalf("read certificate order outbox: %v", err)
	}
	if outboxStatus != "pending" || !bytes.Contains(outboxPayload, []byte(orderA.ID.String())) || bytes.Contains(outboxPayload, []byte(secret)) {
		t.Fatalf("certificate outbox status=%q payload=%s", outboxStatus, outboxPayload)
	}

	// fix-acme2 (migration 531): the platform administrator orders a
	// certificate for a tenant (证书管理「重新申请」); the order keeps the real
	// actor and the audit says on whose behalf.
	t.Run("platform admin orders for a tenant", func(t *testing.T) {
		platformAuth := loginForScope(t, client, server.URL, "dnsadmin", platform.ScopeID)
		order := createCertificateOrder(t, client, server.URL, platformAuth.AccessToken, "platform-order", createCertificateOrderRequest{
			TargetScopeID: tenantA.scopeID.String(), Domains: []string{"admin.example.com"}, ChallengeType: "http-01", AutoRenew: true,
		})
		var createdBy uuid.UUID
		var onBehalfOf, actorScope string
		if err := pool.QueryRow(context.Background(), `SELECT certificate_order.created_by_user_id,
			event.payload->>'on_behalf_of',event.payload->>'actor_scope_id'
			FROM certificate_orders certificate_order
			JOIN audit_events event ON event.resource_id=certificate_order.id::text AND event.action='certificate.order.create'
			WHERE certificate_order.scope_id=$1 AND certificate_order.id=$2`, tenantA.scopeID, order.ID,
		).Scan(&createdBy, &onBehalfOf, &actorScope); err != nil {
			t.Fatalf("read platform order: %v", err)
		}
		if order.Status != dnsacme.OrderPending || createdBy != platform.UserID ||
			onBehalfOf != "tenant" || actorScope != platform.ScopeID.String() {
			t.Fatalf("platform order=%#v created_by=%s on_behalf_of=%q actor_scope=%q", order, createdBy, onBehalfOf, actorScope)
		}
	})

	// 048's shadowed parameter let a member of any active tenant pass the
	// actor check for every tenant; 531 refuses them at the database too.
	t.Run("member of another tenant cannot place an order for this tenant", func(t *testing.T) {
		_, err := pool.Exec(context.Background(), `INSERT INTO certificate_orders(
			id,scope_id,domains,challenge_type,auto_renew,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,ARRAY['cross.example.com'],'http-01',true,$3,$3)`, uuid.New(), tenantA.scopeID, tenantB.userID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("cross-tenant order error = %v, want P0001", err)
		}
	})

	t.Run("list isolation", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/certificate-orders", nil, tenantBAuth.AccessToken, "", "")
		var result struct {
			Items []dnsacme.CertificateOrder `json:"items"`
		}
		decodeResponse(t, response, http.StatusOK, &result)
		response.Body.Close()
		if len(result.Items) != 0 {
			t.Fatalf("tenant B orders = %#v", result.Items)
		}
	})

	t.Run("certificate mutations stay behind the dispatcher boundary", func(t *testing.T) {
		for _, request := range []struct {
			method string
			path   string
			status int
		}{
			{http.MethodPatch, "/v1/certificate-orders", http.StatusMethodNotAllowed},
			{http.MethodPost, "/v1/certificate-orders/" + orderA.ID.String() + "/renew", http.StatusNotFound},
		} {
			response := siteRequest(t, client, request.method, server.URL+request.path, map[string]any{
				"order_id": orderA.ID.String(),
			}, tenantAAuth.AccessToken, "direct-certificate-mutation", "")
			body := readBody(response.Body)
			response.Body.Close()
			if response.StatusCode != request.status {
				t.Fatalf("%s %s status=%d body=%s", request.method, request.path, response.StatusCode, body)
			}
		}

		service := dnsacme.NewService(dnsacme.NewStore(pool), cipher)
		actors := []struct {
			name  string
			actor dnsacme.Actor
		}{
			{"tenant", dnsacme.Actor{UserID: tenantA.userID, ScopeID: tenantA.scopeID, ScopeKind: "tenant"}},
			{"platform", dnsacme.Actor{UserID: platform.UserID, ScopeID: platform.ScopeID, ScopeKind: "platform"}},
		}
		for _, subject := range actors {
			t.Run(subject.name, func(t *testing.T) {
				if _, err := service.TransitionOrder(context.Background(), subject.actor, dnsacme.TransitionOrderRequest{
					ID: orderA.ID, ExpectedRevision: orderA.Revision,
					From: dnsacme.OrderPending, To: dnsacme.OrderValidating,
					IdempotencyKey: "direct-transition-" + subject.name,
					RequestID:      "direct-transition-" + subject.name,
				}); !errors.Is(err, dnsacme.ErrPermissionDenied) {
					t.Fatalf("TransitionOrder() error = %v, want %v", err, dnsacme.ErrPermissionDenied)
				}
				if _, err := service.CreateRenewal(context.Background(), subject.actor, dnsacme.CreateRenewalRequest{
					OrderID: orderA.ID, IdempotencyKey: "direct-renewal-" + subject.name,
					RequestID: "direct-renewal-" + subject.name,
				}); !errors.Is(err, dnsacme.ErrPermissionDenied) {
					t.Fatalf("CreateRenewal() error = %v, want %v", err, dnsacme.ErrPermissionDenied)
				}
			})
		}

		var status string
		var revision int64
		var renewalCount, outboxCount, mutationAuditCount int
		var notAfterIsNull bool
		if err := pool.QueryRow(context.Background(), `SELECT status, revision, not_after IS NULL
			FROM certificate_orders WHERE scope_id=$1 AND id=$2`, tenantA.scopeID, orderA.ID,
		).Scan(&status, &revision, &notAfterIsNull); err != nil {
			t.Fatalf("read fail-closed certificate order: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM certificate_orders
			WHERE scope_id=$1 AND renewal_of_order_id=$2`, tenantA.scopeID, orderA.ID,
		).Scan(&renewalCount); err != nil {
			t.Fatalf("count fail-closed renewals: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM dns_acme_outbox
			WHERE scope_id=$1 AND aggregate_type='certificate_order' AND aggregate_id=$2`,
			tenantA.scopeID, orderA.ID,
		).Scan(&outboxCount); err != nil {
			t.Fatalf("count fail-closed outbox events: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events
			WHERE scope_id=$1 AND resource_id=$2
			  AND action IN ('certificate.order.transition','certificate.order.finalize_issued','certificate.order.renew')`,
			tenantA.scopeID, orderA.ID.String(),
		).Scan(&mutationAuditCount); err != nil {
			t.Fatalf("count fail-closed mutation audits: %v", err)
		}
		if status != dnsacme.OrderPending || revision != orderA.Revision || !notAfterIsNull ||
			renewalCount != 0 || outboxCount != 1 || mutationAuditCount != 0 {
			t.Fatalf("fail-closed facts status=%q revision=%d not_after_null=%t renewals=%d outbox=%d audits=%d",
				status, revision, notAfterIsNull, renewalCount, outboxCount, mutationAuditCount)
		}
	})

	t.Run("referenced provider cannot be deleted", func(t *testing.T) {
		deleted := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/records/"+recordA.ID.String(), nil,
			tenantAAuth.AccessToken, "record-delete", `"2"`)
		if deleted.StatusCode != http.StatusNoContent {
			t.Fatalf("record delete status=%d body=%s", deleted.StatusCode, readBody(deleted.Body))
		}
		deleted.Body.Close()
		replay := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/records/"+recordA.ID.String(), nil,
			tenantAAuth.AccessToken, "record-delete", `"2"`)
		if replay.StatusCode != http.StatusNoContent {
			t.Fatalf("record delete replay status=%d body=%s", replay.StatusCode, readBody(replay.Body))
		}
		replay.Body.Close()
		conflictingReplay := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/records/"+recordA.ID.String(), nil,
			tenantAAuth.AccessToken, "record-delete", `"1"`)
		assertError(t, conflictingReplay, http.StatusConflict, "idempotency_conflict", "")
		conflictingReplay.Body.Close()

		response := siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/providers/"+providerA.ID.String(), nil,
			tenantAAuth.AccessToken, "provider-delete-referenced", `"1"`)
		assertError(t, response, http.StatusConflict, "dns_resource_conflict", "")
		response.Body.Close()
	})

	if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
		t.Fatalf("VerifyScope(tenant A) error = %v", err)
	}
}

func TestDNSCredentialCipherFailsClosed(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	tenant := insertDNSTenant(t, pool, "dns-no-key", "dns-no-key-user", passwordHash, []string{"dns.manage"})
	tokens, _ := identity.NewTokenManager("dns-no-key-secret-at-least-thirty-two-bytes", 5*time.Minute)
	identityService, _ := identity.NewService(identityStore, tokens, 24*time.Hour)
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CookieSecure: false}).Handler())
	t.Cleanup(server.Close)
	auth := loginForScope(t, server.Client(), server.URL, tenant.username, tenant.scopeID)
	response := siteRequest(t, server.Client(), http.MethodPost, server.URL+"/v1/dns/providers", createDNSProviderRequest{
		Name: "No Key", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "must-not-store"},
	}, auth.AccessToken, "no-key", "")
	assertError(t, response, http.StatusServiceUnavailable, "credential_encryption_unavailable", "")
	response.Body.Close()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM dns_providers`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("provider count after fail closed = %d, error=%v", count, err)
	}
}

type dnsTenantFixture struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
	username string
}

func insertDNSTenant(t *testing.T, pool *pgxpool.Pool, displayName, username, passwordHash string, permissions []string) dnsTenantFixture {
	t.Helper()
	tenantID, scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, tenantID, displayName); err != nil {
		t.Fatalf("insert DNS tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatalf("insert DNS scope: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, username, display_name, password_hash) VALUES ($1,$2,$3,$4)`,
		userID, username, displayName, passwordHash); err != nil {
		t.Fatalf("insert DNS user %q: %v", username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id, user_id) VALUES ($1,$2)`, scopeID, userID); err != nil {
		t.Fatalf("insert DNS membership %q: %v", username, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles (id, scope_id, name, system_role) VALUES ($1,$2,'tenant_owner',true)`,
		roleID, scopeID); err != nil {
		t.Fatalf("insert DNS system role %q: %v", username, err)
	}
	for _, permission := range permissions {
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_name) VALUES ($1,$2)`,
			roleID, permission); err != nil {
			t.Fatalf("grant DNS permission %q to %q: %v", permission, username, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id, user_id, role_id) VALUES ($1,$2,$3)`,
		scopeID, userID, roleID); err != nil {
		t.Fatalf("assign DNS system role %q: %v", username, err)
	}
	return dnsTenantFixture{tenantID: tenantID, scopeID: scopeID, userID: userID, username: username}
}

func createDNSProvider(t *testing.T, client *http.Client, baseURL, token, key string, body createDNSProviderRequest) dnsacme.Provider {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/dns/providers", body, token, key, "")
	var result dnsacme.Provider
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func createDNSZone(t *testing.T, client *http.Client, baseURL, token, key string, body createDNSZoneRequest) dnsacme.Zone {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/dns/zones", body, token, key, "")
	var result dnsacme.Zone
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func createDNSRecord(t *testing.T, client *http.Client, baseURL, token, key string, body createDNSRecordRequest) dnsacme.Record {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/dns/records", body, token, key, "")
	var result dnsacme.Record
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func createCertificateOrder(t *testing.T, client *http.Client, baseURL, token, key string, body createCertificateOrderRequest) dnsacme.CertificateOrder {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/certificate-orders", body, token, key, "")
	var result dnsacme.CertificateOrder
	decodeResponse(t, response, http.StatusAccepted, &result)
	response.Body.Close()
	return result
}

func concurrentDNSRequests[T any](count int, operation func() T) []T {
	results := make([]T, count)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index] = operation()
		}(index)
	}
	wait.Wait()
	return results
}
