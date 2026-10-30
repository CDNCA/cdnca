//go:build integration

package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type providerVerificationStub struct {
	mu        sync.Mutex
	calls     map[string]int
	transient map[string]bool
}

func newProviderVerificationStub() *providerVerificationStub {
	return &providerVerificationStub{calls: make(map[string]int), transient: make(map[string]bool)}
}

func (s *providerVerificationStub) Verify(ctx context.Context, providerType, token string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.calls[token]++
	firstTransient := !s.transient[token]
	if token == "transient-token" {
		s.transient[token] = true
	}
	s.mu.Unlock()
	if providerType != "cloudflare" {
		return dnsacme.ErrProviderVerificationUnsupported
	}
	switch token {
	case "inactive-token":
		return dnsacme.ErrProviderTokenInactive
	case "rejected-token":
		return dnsacme.ErrProviderCredentialsRejected
	case "transient-token":
		if firstTransient {
			return dnsacme.ErrProviderVerificationUnavailable
		}
	}
	return nil
}

func (s *providerVerificationStub) callCount(token string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[token]
}

func TestDNSProviderVerificationHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	identityStore := identity.NewStore(pool)
	tenantA := insertDNSTenant(t, pool, "verify-tenant-a", "verify-user-a", passwordHash, []string{"dns.read", "dns.manage"})
	tenantB := insertDNSTenant(t, pool, "verify-tenant-b", "verify-user-b", passwordHash, []string{"dns.read", "dns.manage"})
	reader := insertDNSTenant(t, pool, "verify-reader", "verify-reader-user", passwordHash, []string{"dns.read"})
	tokens, err := identity.NewTokenManager("dns-verification-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager() error = %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("identity.NewService() error = %v", err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("verify-test-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher() error = %v", err)
	}
	verifier := newProviderVerificationStub()
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, DNSProviderVerifier: verifier,
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	readerAuth := loginForScope(t, client, server.URL, reader.username, reader.scopeID)

	active := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-active-create", createDNSProviderRequest{
		Name: "Active Cloudflare", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "active-token"},
	})
	verifyURL := server.URL + "/v1/dns/providers/" + active.ID.String() + "/verify"

	t.Run("auth, permission, scope, headers, and empty body", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, verifyURL, nil, "", "unauthenticated", `"1"`)
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, verifyURL, nil, readerAuth.AccessToken, "reader", `"1"`)
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, verifyURL, nil, authB.AccessToken, "cross-scope", `"1"`)
		assertError(t, response, http.StatusNotFound, "dns_resource_not_found", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, verifyURL, nil, authA.AccessToken, "", `"1"`)
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, verifyURL, nil, authA.AccessToken, "missing-version", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, verifyURL, map[string]any{}, authA.AccessToken, "nonempty", `"1"`)
		assertError(t, response, http.StatusBadRequest, "invalid_request", "")
		response.Body.Close()
		if verifier.callCount("active-token") != 0 {
			t.Fatalf("invalid requests called verifier %d times", verifier.callCount("active-token"))
		}
	})

	unsupported := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-unsupported-create", createDNSProviderRequest{
		Name: "Unsupported Aliyun", ProviderType: "aliyun", Credentials: map[string]string{
			"access_key_id": "not-exposed-id", "access_key_secret": "not-exposed-secret"},
	})
	t.Run("unsupported denial is audited and replayed", func(t *testing.T) {
		url := server.URL + "/v1/dns/providers/" + unsupported.ID.String() + "/verify"
		response := siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "unsupported", `"1"`)
		assertError(t, response, http.StatusUnprocessableEntity, "provider_verification_unsupported", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "unsupported", `"1"`)
		assertError(t, response, http.StatusUnprocessableEntity, "provider_verification_unsupported", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "unsupported", `"2"`)
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()
		assertProviderVerificationAudit(t, pool, unsupported.ID, "denied", "provider_verification_unsupported", 1)
	})

	disabled := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-disabled-create", createDNSProviderRequest{
		Name: "Disabled Cloudflare", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "disabled-token"},
	})
	response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/providers/"+disabled.ID.String(), updateDNSProviderRequest{
		ExpectedVersion: 1, Name: disabled.Name, Status: dnsacme.ProviderStatusDisabled,
	}, authA.AccessToken, "verify-disable", "")
	var disabledResult dnsacme.Provider
	decodeResponse(t, response, http.StatusOK, &disabledResult)
	response.Body.Close()
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/providers/"+disabled.ID.String()+"/verify", nil,
		authA.AccessToken, "disabled", `"2"`)
	assertError(t, response, http.StatusConflict, "provider_disabled", "")
	response.Body.Close()
	if verifier.callCount("disabled-token") != 0 {
		t.Fatalf("disabled provider called verifier %d times", verifier.callCount("disabled-token"))
	}
	// DNS-UX-20261027-02: disabling revoked the credentials; enabling without
	// new ones is refused (the revoked credentials are never revived), the
	// re-authorization with new credentials enables it and verifies again.
	t.Run("revoked account needs re-authorization", func(t *testing.T) {
		url := server.URL + "/v1/dns/providers/" + disabled.ID.String()
		response := siteRequest(t, client, http.MethodPatch, url, updateDNSProviderRequest{
			ExpectedVersion: disabledResult.Revision, Name: disabled.Name, Status: dnsacme.ProviderStatusUnverified,
		}, authA.AccessToken, "verify-enable-revoked", "")
		assertError(t, response, http.StatusConflict, "dns_provider_reauthorization_required", "")
		response.Body.Close()
		response = siteRequest(t, client, http.MethodPatch, url, updateDNSProviderRequest{
			ExpectedVersion: disabledResult.Revision, Name: disabled.Name, Status: dnsacme.ProviderStatusUnverified,
			// Its own token: the active provider's verifier call count is asserted below.
			Credentials: map[string]string{"api_token": "reauthorized-token"},
		}, authA.AccessToken, "verify-reauthorize", "")
		var reauthorized dnsacme.Provider
		decodeResponse(t, response, http.StatusOK, &reauthorized)
		response.Body.Close()
		if reauthorized.Status != dnsacme.ProviderStatusUnverified || reauthorized.Revision != disabledResult.Revision+1 {
			t.Fatalf("re-authorized provider=%+v", reauthorized)
		}
		response = siteRequest(t, client, http.MethodPost, url+"/verify", nil, authA.AccessToken, "reauthorized", `"3"`)
		var verified dnsacme.Provider
		decodeResponse(t, response, http.StatusOK, &verified)
		response.Body.Close()
		if verified.Status != dnsacme.ProviderStatusVerified {
			t.Fatalf("re-authorized provider did not verify: %+v", verified)
		}
	})

	// Credentials outside the provider's exact schema are rejected when the
	// provider is created, so they are never stored or handed to a verifier.
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/providers", createDNSProviderRequest{
		Name: "Malformed Cloudflare", ProviderType: "cloudflare",
		Credentials: map[string]string{"api_token": "malformed-token", "extra": "must-be-rejected"},
	}, authA.AccessToken, "verify-malformed-create", "")
	assertError(t, response, http.StatusBadRequest, "validation_error", "")
	response.Body.Close()
	if verifier.callCount("malformed-token") != 0 {
		t.Fatalf("malformed credentials called verifier %d times", verifier.callCount("malformed-token"))
	}

	inactive := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-inactive-create", createDNSProviderRequest{
		Name: "Inactive Cloudflare", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "inactive-token"},
	})
	t.Run("inactive and rejected credentials do not leak", func(t *testing.T) {
		url := server.URL + "/v1/dns/providers/" + inactive.ID.String() + "/verify"
		for range 2 {
			response := siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "inactive", `"1"`)
			body := readBody(response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusUnprocessableEntity || !bytes.Contains([]byte(body), []byte("provider_token_inactive")) ||
				bytes.Contains([]byte(body), []byte("inactive-token")) {
				t.Fatalf("inactive response status=%d body=%s", response.StatusCode, body)
			}
		}
		if verifier.callCount("inactive-token") != 1 {
			t.Fatalf("inactive verifier calls = %d", verifier.callCount("inactive-token"))
		}
		assertProviderVerificationAudit(t, pool, inactive.ID, "denied", "provider_token_inactive", 1)

		rejected := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-rejected-create", createDNSProviderRequest{
			Name: "Rejected Cloudflare", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "rejected-token"},
		})
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/providers/"+rejected.ID.String()+"/verify", nil,
			authA.AccessToken, "rejected", `"1"`)
		assertError(t, response, http.StatusUnprocessableEntity, "provider_credentials_rejected", "")
		response.Body.Close()
		assertProviderVerificationAudit(t, pool, rejected.ID, "denied", "provider_credentials_rejected", 1)
	})

	t.Run("success updates revision, ETag, audit, and replay", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, verifyURL, nil, authA.AccessToken, "active", `"1"`)
		var verified dnsacme.Provider
		decodeResponse(t, response, http.StatusOK, &verified)
		if response.Header.Get("ETag") != `"2"` {
			t.Fatalf("ETag = %q", response.Header.Get("ETag"))
		}
		response.Body.Close()
		if verified.Status != dnsacme.ProviderStatusVerified || verified.Revision != 2 {
			t.Fatalf("verified provider = %#v", verified)
		}
		response = siteRequest(t, client, http.MethodPost, verifyURL, nil, authA.AccessToken, "active", `"1"`)
		var replay dnsacme.Provider
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if replay != verified || verifier.callCount("active-token") != 1 {
			t.Fatalf("replay=%#v verifier calls=%d", replay, verifier.callCount("active-token"))
		}
		assertProviderVerificationAudit(t, pool, active.ID, "success", "active", 1)
	})

	t.Run("concurrent same key has one audit", func(t *testing.T) {
		provider := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-same-key-create", createDNSProviderRequest{
			Name: "Same Key", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "same-key-token"},
		})
		url := server.URL + "/v1/dns/providers/" + provider.ID.String() + "/verify"
		results := concurrentDNSRequests(2, func() int {
			response, requestErr := performSiteRequest(client, http.MethodPost, url, nil, authA.AccessToken, "same-key", `"1"`)
			if requestErr != nil {
				return 0
			}
			defer response.Body.Close()
			return response.StatusCode
		})
		if results[0] != http.StatusOK || results[1] != http.StatusOK {
			t.Fatalf("same-key statuses = %v", results)
		}
		assertProviderVerificationAudit(t, pool, provider.ID, "success", "active", 1)
	})

	t.Run("different keys with same revision have one winner", func(t *testing.T) {
		provider := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-race-create", createDNSProviderRequest{
			Name: "Revision Race", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "race-token"},
		})
		url := server.URL + "/v1/dns/providers/" + provider.ID.String() + "/verify"
		keys := make(chan string, 2)
		keys <- "race-a"
		keys <- "race-b"
		statuses := concurrentDNSRequests(2, func() int {
			key := <-keys
			response, requestErr := performSiteRequest(client, http.MethodPost, url, nil, authA.AccessToken, key, `"1"`)
			if requestErr != nil {
				return 0
			}
			defer response.Body.Close()
			return response.StatusCode
		})
		sort.Ints(statuses)
		if statuses[0] != http.StatusOK || statuses[1] != http.StatusConflict {
			t.Fatalf("different-key statuses = %v", statuses)
		}
		assertProviderVerificationAudit(t, pool, provider.ID, "success", "active", 1)
	})

	t.Run("transient failure leaves key retryable", func(t *testing.T) {
		provider := createDNSProvider(t, client, server.URL, authA.AccessToken, "verify-transient-create", createDNSProviderRequest{
			Name: "Transient", ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "transient-token"},
		})
		url := server.URL + "/v1/dns/providers/" + provider.ID.String() + "/verify"
		response := siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "transient", `"1"`)
		assertError(t, response, http.StatusServiceUnavailable, "provider_verification_unavailable", "")
		response.Body.Close()
		var writes, audits int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM dns_acme_write_requests WHERE operation='dns.provider.verify' AND resource_id=$1`, provider.ID).Scan(&writes); err != nil {
			t.Fatalf("count transient writes: %v", err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE action='dns.provider.verify' AND resource_id=$1`, provider.ID.String()).Scan(&audits); err != nil {
			t.Fatalf("count transient audits: %v", err)
		}
		if writes != 0 || audits != 0 {
			t.Fatalf("transient failure writes=%d audits=%d", writes, audits)
		}
		response = siteRequest(t, client, http.MethodPost, url, nil, authA.AccessToken, "transient", `"1"`)
		var verified dnsacme.Provider
		decodeResponse(t, response, http.StatusOK, &verified)
		response.Body.Close()
		if verified.Status != dnsacme.ProviderStatusVerified || verifier.callCount("transient-token") != 2 {
			t.Fatalf("transient retry provider=%#v calls=%d", verified, verifier.callCount("transient-token"))
		}
	})

	if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
		t.Fatalf("VerifyScope() error = %v", err)
	}
}

func TestDNSProviderVerificationMigrationDownFailsClosed(t *testing.T) {
	// Only 1..024: rolling the release head back crosses migration 268's
	// one-way down gate (P2682).
	pool := migrationRoundTripPool(t, 24)
	assertDNSMigrationVersion(t, pool, 24)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	tenant := insertDNSTenant(t, pool, "verify-migration", "verify-migration-user", passwordHash, []string{"dns.manage"})
	cipher, err := dnsacme.NewAESGCMCredentialCipher("migration-v1", bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher() error = %v", err)
	}
	keyID, ciphertext, err := cipher.Encrypt([]byte(`{"api_token":"migration-token"}`))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	providerID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO dns_providers (
			id, scope_id, name, provider_type, credential_key_id, credential_ciphertext,
			status, created_by_user_id, updated_by_user_id
		) VALUES ($1,$2,'Migration Cloudflare','cloudflare',$3,$4,'verified',$5,$5)`,
		providerID, tenant.scopeID, keyID, ciphertext, tenant.userID,
	); err != nil {
		t.Fatalf("insert verified provider: %v", err)
	}
	if err := database.Migrate(context.Background(), pool, "down"); err == nil {
		t.Fatal("migration 024 down succeeded with a verified provider")
	}
	assertDNSMigrationVersion(t, pool, 24)
	if _, err := pool.Exec(context.Background(), `UPDATE dns_providers SET status='unverified' WHERE id=$1`, providerID); err != nil {
		t.Fatalf("reset provider status: %v", err)
	}
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("migration 024 down error = %v", err)
	}
	assertDNSMigrationVersion(t, pool, 23)
	if _, err := pool.Exec(context.Background(), `UPDATE dns_providers SET status='verified' WHERE id=$1`, providerID); err == nil {
		t.Fatal("migration 023 schema accepted verified status")
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 24); err != nil {
		t.Fatalf("migration 024 reapply error = %v", err)
	}
	assertDNSMigrationVersion(t, pool, 24)
	if _, err := pool.Exec(context.Background(), `UPDATE dns_providers SET status='verified' WHERE id=$1`, providerID); err != nil {
		t.Fatalf("migration 024 schema rejected verified status: %v", err)
	}
}

func assertProviderVerificationAudit(
	t *testing.T,
	pool *pgxpool.Pool,
	providerID uuid.UUID,
	result string,
	reasonCode string,
	wantCount int,
) {
	t.Helper()
	var count int
	var payload []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*), COALESCE(max(payload::text), '{}')
		FROM audit_events
		WHERE action='dns.provider.verify' AND resource_id=$1 AND result=$2`,
		providerID.String(), result,
	).Scan(&count, &payload); err != nil {
		t.Fatalf("read verification audit: %v", err)
	}
	if count != wantCount || !bytes.Contains(payload, []byte(reasonCode)) {
		t.Fatalf("verification audit count=%d payload=%s", count, payload)
	}
	for _, forbidden := range [][]byte{[]byte("api_token"), []byte("credential_key"), []byte("ciphertext"), []byte("Authorization")} {
		if bytes.Contains(bytes.ToLower(payload), bytes.ToLower(forbidden)) {
			t.Fatalf("verification audit leaked sensitive field: %s", payload)
		}
	}
}

func assertDNSMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	if got := dnsMigrationVersion(t, pool); got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func dnsMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var got int64
	if err := pool.QueryRow(context.Background(), `SELECT max(version) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	return got
}

var _ dnsacme.ProviderVerifier = (*providerVerificationStub)(nil)
