package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestAPIKeyHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	adminHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(context.Background(), "apikey-admin", "API Key Admin", adminHash, "apikey-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("api-key-integration-access-secret-more-than-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The api_keys guards (117) judge expiry with transaction_timestamp(); a
	// fixed calendar clock falls behind the database clock and every
	// expires_at written from it is already past for the trigger.
	var currentNow time.Time
	if err := pool.QueryRow(context.Background(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&currentNow); err != nil {
		t.Fatal(err)
	}
	currentNow = currentNow.UTC()
	pepper := bytes.Repeat([]byte{0x42}, 32)
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false,
		APIKeyPepper: pepper,
		Now:          func() time.Time { return currentNow },
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginWithPassword(t, client, server.URL, "apikey-admin", testPassword)
	alice := createManagedUser(t, client, server.URL, admin.AccessToken, "apikey-create-alice", map[string]any{
		"username": "apikey-alice", "password": tenantPassword, "display_name": "API Key Alice",
		"email": nil, "phone": nil, "role": identity.UserRoleOwner,
	})
	aliceAuth, _ := loginWithPassword(t, client, server.URL, "apikey-alice", tenantPassword)
	if !contains(aliceAuth.Principal.Permissions, "api_keys.self.manage") {
		t.Fatalf("tenant API key permission missing: %v", aliceAuth.Principal.Permissions)
	}

	issued := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "self-create-one", map[string]any{
		"name": "deployment reader", "scopes": []string{"sites.read"},
		"expires_at": currentNow.Add(24 * time.Hour).Format(time.RFC3339),
	})
	if issued.Key.Status != apikey.StatusActive || issued.Key.Revision != 1 || issued.Secret == "" ||
		issued.Key.UserID != alice.ID || !strings.HasPrefix(issued.Key.KeyPrefix, "cfk_") {
		t.Fatalf("issued API key = %#v", issued)
	}

	t.Run("secret is never persisted and exact replay is stable", func(t *testing.T) {
		var digest, response []byte
		if err := pool.QueryRow(context.Background(), `
			SELECT k.secret_digest, w.response_body::text::bytea
			FROM api_keys k JOIN api_key_write_requests w ON w.resource_id=k.id
			WHERE k.id=$1 AND w.operation='api_key.self.create'`, issued.Key.ID).Scan(&digest, &response); err != nil {
			t.Fatal(err)
		}
		if len(digest) != 32 || bytes.Contains(digest, []byte(issued.Secret)) || bytes.Contains(response, []byte(issued.Secret)) {
			t.Fatalf("persisted API key material leaked secret: digest=%d response=%s", len(digest), response)
		}
		replay := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "self-create-one", map[string]any{
			"name": "deployment reader", "scopes": []string{"sites.read"},
			"expires_at": currentNow.Add(24 * time.Hour).Format(time.RFC3339),
		})
		if replay.Key.ID != issued.Key.ID || replay.Secret != issued.Secret {
			t.Fatalf("replayed API key = %#v, original = %#v", replay, issued)
		}
		conflict := apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/account/api-keys", map[string]any{
			"name": "different", "scopes": []string{"sites.read"},
		}, aliceAuth.AccessToken, "", "self-create-one", `"0"`, "apikey-idempotency-conflict")
		assertError(t, conflict, http.StatusConflict, "idempotency_conflict", "apikey-idempotency-conflict")
		conflict.Body.Close()
	})

	t.Run("CdncaKey authenticates only with database-derived tenant scopes", func(t *testing.T) {
		credential := issued.Key.KeyID + "." + issued.Secret
		response := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", credential, "", "", "apikey-sites-read")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("API key site read status=%d body=%s", response.StatusCode, readBody(response.Body))
		}
		response.Body.Close()

		denied := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/account/balance", nil, "", credential, "", "", "apikey-scope-denied")
		assertError(t, denied, http.StatusForbidden, "permission_denied", "apikey-scope-denied")
		denied.Body.Close()

		bad := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", issued.Key.KeyID+"."+strings.Repeat("A", 43), "", "", "apikey-bad-secret")
		assertError(t, bad, http.StatusUnauthorized, "invalid_session", "apikey-bad-secret")
		bad.Body.Close()

		for _, path := range []string{"/v1/auth/me", "/v1/account/api-keys"} {
			blocked := apiKeyRequest(t, client, http.MethodGet, server.URL+path, nil, "", credential, "", "", "apikey-session-boundary")
			assertError(t, blocked, http.StatusUnauthorized, "invalid_session", "apikey-session-boundary")
			blocked.Body.Close()
		}
		password := apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/account/password", map[string]any{
			"current_password": tenantPassword, "new_password": newTenantPassword,
		}, "", credential, "", "", "apikey-password-boundary")
		assertError(t, password, http.StatusUnauthorized, "invalid_session", "apikey-password-boundary")
		password.Body.Close()
	})

	t.Run("rotate invalidates the previous secret and revoke is immediate", func(t *testing.T) {
		response := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/rotate", map[string]any{},
			aliceAuth.AccessToken, "", "rotate-one", `"1"`, "apikey-rotate")
		var rotated apikey.IssuedKey
		decodeResponse(t, response, http.StatusOK, &rotated)
		response.Body.Close()
		if rotated.Secret == issued.Secret || rotated.Key.Revision != 2 {
			t.Fatalf("rotated API key = %#v", rotated)
		}
		oldAuth := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", issued.Key.KeyID+"."+issued.Secret, "", "", "old-secret")
		assertError(t, oldAuth, http.StatusUnauthorized, "invalid_session", "old-secret")
		oldAuth.Body.Close()
		newAuth := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", rotated.Key.KeyID+"."+rotated.Secret, "", "", "new-secret")
		if newAuth.StatusCode != http.StatusOK {
			t.Fatalf("rotated API key auth status=%d body=%s", newAuth.StatusCode, readBody(newAuth.Body))
		}
		newAuth.Body.Close()

		revoke := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+issued.Key.ID.String()+"/revoke", map[string]any{},
			aliceAuth.AccessToken, "", "revoke-one", `"2"`, "apikey-revoke")
		var revoked apikey.Key
		decodeResponse(t, revoke, http.StatusOK, &revoked)
		revoke.Body.Close()
		if revoked.Status != apikey.StatusRevoked || revoked.Revision != 3 {
			t.Fatalf("revoked key = %#v", revoked)
		}
		revokedAuth := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", rotated.Key.KeyID+"."+rotated.Secret, "", "", "revoked-secret")
		assertError(t, revokedAuth, http.StatusUnauthorized, "invalid_session", "revoked-secret")
		revokedAuth.Body.Close()
	})

	var pending apikey.Key
	t.Run("administrator creates metadata-only pending activation", func(t *testing.T) {
		missingScope := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/admin/users/"+alice.ID.String()+"/api-keys", map[string]any{
				"name": "missing tenant scope", "scopes": []string{"sites.read"}, "pending_ttl_seconds": 3600,
			}, admin.AccessToken, "", "admin-missing-scope", `"0"`, "apikey-admin-missing-scope")
		assertError(t, missingScope, http.StatusBadRequest, "validation_error", "apikey-admin-missing-scope")
		missingScope.Body.Close()

		response := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/admin/users/"+alice.ID.String()+"/api-keys?tenant_scope_id="+alice.ScopeID.String(), map[string]any{
				"name": "admin invitation", "scopes": []string{"sites.read"}, "pending_ttl_seconds": 3600,
			}, admin.AccessToken, "", "admin-pending", `"0"`, "apikey-admin-pending")
		raw, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusCreated {
			t.Fatalf("admin pending status/error/body=%d/%v/%s", response.StatusCode, err, raw)
		}
		if bytes.Contains(bytes.ToLower(raw), []byte("secret")) {
			t.Fatalf("admin response exposed a secret field: %s", raw)
		}
		if err := json.Unmarshal(raw, &pending); err != nil {
			t.Fatal(err)
		}
		if pending.Status != apikey.StatusPendingActivation || pending.PendingExpiresAt == nil {
			t.Fatalf("pending API key = %#v", pending)
		}

		adminActivate := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+pending.ID.String()+"/activate", map[string]any{},
			admin.AccessToken, "", "admin-cannot-activate", `"1"`, "admin-cannot-activate")
		assertError(t, adminActivate, http.StatusForbidden, "permission_denied", "admin-cannot-activate")
		adminActivate.Body.Close()
		tenantAdminProbe := apiKeyRequest(t, client, http.MethodGet,
			server.URL+"/v1/admin/users/"+alice.ID.String()+"/api-keys?tenant_scope_id="+alice.ScopeID.String(), nil,
			aliceAuth.AccessToken, "", "", "", "tenant-admin-probe")
		assertError(t, tenantAdminProbe, http.StatusForbidden, "permission_denied", "tenant-admin-probe")
		tenantAdminProbe.Body.Close()
	})

	t.Run("expired pending key cannot issue a secret", func(t *testing.T) {
		response := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/admin/users/"+alice.ID.String()+"/api-keys?tenant_scope_id="+alice.ScopeID.String(), map[string]any{
				"name": "expires before activation", "scopes": []string{"sites.read"},
				"expires_at": currentNow.Add(30 * time.Minute).Format(time.RFC3339), "pending_ttl_seconds": 3600,
			}, admin.AccessToken, "", "admin-expiring-pending", `"0"`, "apikey-admin-expiring-pending")
		var expiringPending apikey.Key
		decodeResponse(t, response, http.StatusCreated, &expiringPending)
		response.Body.Close()

		currentNow = currentNow.Add(31 * time.Minute)
		activate := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+expiringPending.ID.String()+"/activate", map[string]any{},
			aliceAuth.AccessToken, "", "activate-expired-pending", `"1"`, "activate-expired-pending")
		assertError(t, activate, http.StatusConflict, "api_key_state_conflict", "activate-expired-pending")
		activate.Body.Close()
		currentNow = currentNow.Add(-31 * time.Minute)

		var status string
		var digest []byte
		if err := pool.QueryRow(context.Background(), `SELECT status, secret_digest FROM api_keys WHERE id=$1`, expiringPending.ID).
			Scan(&status, &digest); err != nil {
			t.Fatal(err)
		}
		if status != apikey.StatusPendingActivation || digest != nil {
			t.Fatalf("expired pending key changed to status=%q digest_bytes=%d", status, len(digest))
		}
	})

	t.Run("target user activates pending key and administrator can only revoke", func(t *testing.T) {
		activate := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/account/api-keys/"+pending.ID.String()+"/activate", map[string]any{},
			aliceAuth.AccessToken, "", "activate-pending", `"1"`, "activate-pending")
		var activated apikey.IssuedKey
		decodeResponse(t, activate, http.StatusOK, &activated)
		activate.Body.Close()
		if activated.Key.Status != apikey.StatusActive || activated.Secret == "" || activated.Key.Revision != 2 {
			t.Fatalf("activated API key = %#v", activated)
		}
		revoke := apiKeyRequest(t, client, http.MethodPost,
			server.URL+"/v1/admin/users/"+alice.ID.String()+"/api-keys/"+pending.ID.String()+"/revoke?tenant_scope_id="+alice.ScopeID.String(), map[string]any{},
			admin.AccessToken, "", "admin-revoke", `"2"`, "admin-revoke")
		var revoked apikey.Key
		decodeResponse(t, revoke, http.StatusOK, &revoked)
		revoke.Body.Close()
		if revoked.Status != apikey.StatusRevoked {
			t.Fatalf("admin revoked API key = %#v", revoked)
		}
	})

	t.Run("expiration is checked on every authentication", func(t *testing.T) {
		expiring := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "expiring-create", map[string]any{
			"name": "short lived", "scopes": []string{"sites.read"},
			"expires_at": currentNow.Add(time.Hour).Format(time.RFC3339),
		})
		currentNow = currentNow.Add(2 * time.Hour)
		response := apiKeyRequest(t, client, http.MethodGet, server.URL+"/v1/sites", nil, "", expiring.Key.KeyID+"."+expiring.Secret, "", "", "expired-key")
		assertError(t, response, http.StatusUnauthorized, "invalid_session", "expired-key")
		response.Body.Close()
		currentNow = currentNow.Add(-2 * time.Hour)
	})

	t.Run("concurrent rotations have one revision winner", func(t *testing.T) {
		key := createSelfAPIKey(t, client, server.URL, aliceAuth.AccessToken, "concurrent-create", map[string]any{
			"name": "concurrent", "scopes": []string{"sites.read"},
		})
		type result struct {
			status int
			err    error
		}
		results := make(chan result, 2)
		var wait sync.WaitGroup
		for index := 0; index < 2; index++ {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				request, err := http.NewRequest(http.MethodPost,
					server.URL+"/v1/account/api-keys/"+key.Key.ID.String()+"/rotate", strings.NewReader("{}"))
				if err != nil {
					results <- result{err: err}
					return
				}
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Authorization", "Bearer "+aliceAuth.AccessToken)
				request.Header.Set("Idempotency-Key", fmt.Sprintf("concurrent-rotate-%d", index))
				request.Header.Set("If-Match", `"1"`)
				request.Header.Set("X-Request-ID", fmt.Sprintf("concurrent-%d", index))
				response, err := client.Do(request)
				if err != nil {
					results <- result{err: err}
					return
				}
				results <- result{status: response.StatusCode}
				response.Body.Close()
			}(index)
		}
		wait.Wait()
		close(results)
		counts := map[int]int{}
		for result := range results {
			if result.err != nil {
				t.Fatalf("concurrent rotation request failed: %v", result.err)
			}
			counts[result.status]++
		}
		if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
			t.Fatalf("concurrent rotation statuses = %v", counts)
		}
	})

	t.Run("audit failure rolls back key and idempotency state", func(t *testing.T) {
		if _, err := pool.Exec(context.Background(), `
			CREATE FUNCTION fail_apikey_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.request_id = 'apikey-audit-failure' THEN
					RAISE EXCEPTION 'injected API key audit failure';
				END IF;
				RETURN NEW;
			END;
			$$;
			CREATE TRIGGER fail_apikey_audit_trigger BEFORE INSERT ON audit_events
			FOR EACH ROW EXECUTE FUNCTION fail_apikey_audit()`); err != nil {
			t.Fatal(err)
		}
		response := apiKeyRequest(t, client, http.MethodPost, server.URL+"/v1/account/api-keys", map[string]any{
			"name": "must rollback", "scopes": []string{"sites.read"},
		}, aliceAuth.AccessToken, "", "audit-failure", `"0"`, "apikey-audit-failure")
		assertError(t, response, http.StatusInternalServerError, "internal_error", "apikey-audit-failure")
		response.Body.Close()
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER fail_apikey_audit_trigger ON audit_events; DROP FUNCTION fail_apikey_audit()`); err != nil {
			t.Fatal(err)
		}
		var keys, writes int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM api_keys WHERE name='must rollback'`).Scan(&keys); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM api_key_write_requests WHERE idempotency_key='audit-failure'`).Scan(&writes); err != nil {
			t.Fatal(err)
		}
		if keys != 0 || writes != 0 {
			t.Fatalf("audit rollback left keys/writes = %d/%d", keys, writes)
		}
	})

	if err := audit.New(pool).VerifyScope(context.Background(), alice.ScopeID); err != nil {
		t.Fatalf("tenant API key audit chain invalid: %v", err)
	}
	if bootstrap.ScopeID == alice.ScopeID {
		t.Fatal("platform and tenant trust scopes unexpectedly match")
	}
}

func TestAPIKeyMigrationRoundTrip(t *testing.T) {
	pool := migrationRoundTripPool(t, 25)
	ctx := context.Background()
	for {
		var latest int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&latest); err != nil {
			t.Fatal(err)
		}
		if latest <= 25 {
			if latest != 25 {
				t.Fatalf("API key migration version = %d, want 25", latest)
			}
			break
		}
		if err := database.Migrate(ctx, pool, "down"); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Migrate(ctx, pool, "down"); err != nil {
		t.Fatalf("Migrate(down 025) error = %v", err)
	}
	var relation *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_keys')::text`).Scan(&relation); err != nil {
		t.Fatal(err)
	}
	if relation != nil {
		t.Fatalf("api_keys still exists after rollback: %s", *relation)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("Migrate(up) after 025 rollback error = %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_keys')::text`).Scan(&relation); err != nil || relation == nil {
		t.Fatalf("api_keys missing after reapply: relation=%v err=%v", relation, err)
	}
}

func createSelfAPIKey(
	t *testing.T,
	client *http.Client,
	baseURL string,
	accessToken string,
	idempotencyKey string,
	body any,
) apikey.IssuedKey {
	t.Helper()
	response := apiKeyRequest(t, client, http.MethodPost, baseURL+"/v1/account/api-keys", body,
		accessToken, "", idempotencyKey, `"0"`, idempotencyKey+"-request")
	var result apikey.IssuedKey
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func apiKeyRequest(
	t *testing.T,
	client *http.Client,
	method string,
	rawURL string,
	body any,
	accessToken string,
	apiCredential string,
	idempotencyKey string,
	ifMatch string,
	requestID string,
) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		request.Header.Set("Authorization", "Bearer "+accessToken)
	}
	if apiCredential != "" {
		request.Header.Set("Authorization", "CdncaKey "+apiCredential)
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	if requestID != "" {
		request.Header.Set("X-Request-ID", requestID)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
