package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/urlauthpolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestURLAuthPolicyHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "urlauthadmin", "URL Auth Admin", passwordHash, "url-auth-bootstrap"); err != nil {
		t.Fatalf("BootstrapPlatformUser: %v", err)
	}
	tenantA := insertURLAuthTenant(t, pool, "URL Auth Tenant A", "urlauth-a", passwordHash)
	tenantB := insertURLAuthTenant(t, pool, "URL Auth Tenant B", "urlauth-b", passwordHash)
	readerID := insertSiteScopeUser(t, pool, tenantA.scopeID, "urlauth-reader", "URL Auth Reader", passwordHash, []string{"url_auth_policies.read"})
	if readerID == uuid.Nil {
		t.Fatal("reader was not created")
	}
	siteA := insertURLAuthSite(t, pool, tenantA, "auth-a.example")
	siteB := insertURLAuthSite(t, pool, tenantB, "auth-b.example")

	tokens, err := identity.NewTokenManager("url-auth-integration-secret-32bytes", 5*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenManager: %v", err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("url-auth-kek-v1", bytes.Repeat([]byte{17}, 32))
	if err != nil {
		t.Fatalf("NewAESGCMCredentialCipher: %v", err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), DNSCredentialCipher: cipher}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	platformAuth, _ := loginOK(t, client, server.URL, "urlauthadmin")
	tenantAAuth := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	tenantBAuth := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
	readerAuth := loginForScope(t, client, server.URL, "urlauth-reader", tenantA.scopeID)

	createBody := createURLAuthPolicyRequest{TargetScopeID: tenantA.scopeID.String(), OwnerID: tenantA.userID.String(), PolicyFields: validURLAuthFields(siteA, "Protected downloads")}
	createdResult := createURLAuthPolicy(t, client, server.URL, platformAuth.AccessToken, "url-auth-create", createBody)
	created := createdResult.Policy
	if created.Revision != 1 || len(createdResult.Secret) != 43 || created.CurrentKey.KeyID == "" || created.PreviousKey != nil || created.Owner == nil {
		t.Fatalf("created result = %#v", createdResult)
	}
	firstSecret := createdResult.Secret
	firstKeyID := created.CurrentKey.KeyID
	var kekKeyID string
	var encryptedSecret []byte
	if err := pool.QueryRow(context.Background(), `SELECT kek_key_id,ciphertext FROM url_auth_policy_keys WHERE policy_id=$1 AND role='current'`, created.ID).Scan(&kekKeyID, &encryptedSecret); err != nil {
		t.Fatalf("read encrypted key: %v", err)
	}
	plaintext, err := cipher.Decrypt(kekKeyID, encryptedSecret)
	if err != nil || string(plaintext) != firstSecret {
		t.Fatalf("decrypt stored key: plaintext match=%t error=%v", string(plaintext) == firstSecret, err)
	}

	t.Run("one-time secret and idempotency conflict", func(t *testing.T) {
		replayed := createURLAuthPolicy(t, client, server.URL, platformAuth.AccessToken, "url-auth-create", createBody)
		if replayed.Policy.ID != created.ID || replayed.Secret != "" || !replayed.Replayed {
			t.Fatalf("replay = %#v", replayed)
		}
		conflict := createBody
		conflict.Name = "Different"
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies", conflict, platformAuth.AccessToken, "url-auth-create", "")
		assertError(t, response, http.StatusConflict, "idempotency_conflict", "")
		response.Body.Close()
		weak := createBody
		weak.Name = "Weak"
		weak.Algorithm = "md5"
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies", weak, platformAuth.AccessToken, "url-auth-weak", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
		assertURLAuthSecretAbsent(t, pool, created.ID, firstSecret)
	})

	t.Run("tenant isolation and RBAC", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/url-auth-policies?page=1&limit=20", nil, tenantAAuth.AccessToken, "", "")
		var page urlauthpolicy.ListResult
		decodeResponse(t, response, http.StatusOK, &page)
		response.Body.Close()
		if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != created.ID || page.Items[0].Owner != nil {
			t.Fatalf("tenant page = %#v", page)
		}
		encoded, _ := json.Marshal(page)
		if bytes.Contains(encoded, []byte(firstSecret)) || bytes.Contains(encoded, []byte("ciphertext")) {
			t.Fatalf("list leaked secret material: %s", encoded)
		}
		other := siteRequest(t, client, http.MethodGet, server.URL+"/v1/url-auth-policies/"+created.ID.String(), nil, tenantBAuth.AccessToken, "", "")
		assertError(t, other, http.StatusNotFound, "url_auth_policy_not_found", "")
		other.Body.Close()
		denied := siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/rotate", map[string]any{}, readerAuth.AccessToken, "reader-rotate", `"1"`)
		assertError(t, denied, http.StatusForbidden, "permission_denied", "")
		denied.Body.Close()
		wrongSite := createURLAuthPolicyRequest{PolicyFields: validURLAuthFields(siteB, "Cross tenant")}
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies", wrongSite, tenantAAuth.AccessToken, "url-auth-cross-site", "")
		assertError(t, response, http.StatusBadRequest, "validation_error", "")
		response.Body.Close()
	})

	t.Run("rotate replay and deterministic snapshot", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/rotate", map[string]any{}, platformAuth.AccessToken, "url-auth-rotate", `"1"`)
		var rotated urlauthpolicy.SecretWriteResult
		decodeResponse(t, response, http.StatusOK, &rotated)
		response.Body.Close()
		if len(rotated.Secret) != 43 || rotated.Policy.Revision != 2 || rotated.Policy.PreviousKey == nil || rotated.Policy.PreviousKey.KeyID != firstKeyID {
			t.Fatalf("rotated = %#v", rotated)
		}
		rotatedSecret := rotated.Secret
		created = rotated.Policy
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/rotate", map[string]any{}, platformAuth.AccessToken, "url-auth-rotate", `"1"`)
		var replayed urlauthpolicy.SecretWriteResult
		decodeResponse(t, response, http.StatusOK, &replayed)
		response.Body.Close()
		if replayed.Secret != "" || !replayed.Replayed || replayed.Policy.CurrentKey.KeyID != created.CurrentKey.KeyID {
			t.Fatalf("rotate replay = %#v", replayed)
		}
		assertURLAuthSecretAbsent(t, pool, created.ID, rotatedSecret)
		response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/edge-snapshot", nil, tenantAAuth.AccessToken, "", "")
		var snapshot urlauthpolicy.SnapshotResult
		decodeResponse(t, response, http.StatusOK, &snapshot)
		response.Body.Close()
		raw, _ := json.Marshal(snapshot.Document)
		raw = append(raw, '\n')
		digest := sha256.Sum256(raw)
		if snapshot.Revision != 2 || snapshot.SHA256 != hex.EncodeToString(digest[:]) || snapshot.Document.SchemaVersion != urlauthpolicy.SchemaVersion || snapshot.Document.PreviousKey == nil {
			t.Fatalf("snapshot = %#v", snapshot)
		}
	})

	t.Run("concurrent revision has one winner", func(t *testing.T) {
		fields := policyFields(created)
		bodies := []urlauthpolicy.PolicyFields{fields, fields}
		bodies[0].Name = "Winner A"
		bodies[1].Name = "Winner B"
		statuses := make([]int, 2)
		codes := make([]string, 2)
		updated := make([]urlauthpolicy.Policy, 2)
		var group sync.WaitGroup
		for index := range bodies {
			group.Add(1)
			go func(index int) {
				defer group.Done()
				response, requestErr := performSiteRequest(client, http.MethodPatch, server.URL+"/v1/url-auth-policies/"+created.ID.String(), bodies[index], platformAuth.AccessToken, fmt.Sprintf("url-auth-race-%d", index), `"2"`)
				if requestErr != nil {
					codes[index] = requestErr.Error()
					return
				}
				defer response.Body.Close()
				statuses[index] = response.StatusCode
				if response.StatusCode == http.StatusOK {
					var result urlauthpolicy.WriteResult
					_ = decodeJSONResponse(response, &result)
					updated[index] = result.Policy
				} else {
					var envelope testErrorEnvelope
					_ = decodeJSONResponse(response, &envelope)
					codes[index] = envelope.Error.Code
				}
			}(index)
		}
		group.Wait()
		sort.Ints(statuses)
		if statuses[0] != http.StatusOK || statuses[1] != http.StatusConflict {
			t.Fatalf("race statuses=%v codes=%v", statuses, codes)
		}
		for _, item := range updated {
			if item.ID != uuid.Nil {
				created = item
			}
		}
		if created.Revision != 3 {
			t.Fatalf("winner=%#v", created)
		}
	})

	t.Run("revoke previous key", func(t *testing.T) {
		if created.PreviousKey == nil {
			t.Fatal("previous key missing before revoke")
		}
		body := revokeURLAuthKeyRequest{KeyID: created.PreviousKey.KeyID}
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/revoke", body, platformAuth.AccessToken, "url-auth-revoke", quoteVersion(created.Revision))
		var revoked urlauthpolicy.WriteResult
		decodeResponse(t, response, http.StatusOK, &revoked)
		response.Body.Close()
		if revoked.Policy.PreviousKey != nil || revoked.Policy.Revision != 4 {
			t.Fatalf("revoked=%#v", revoked)
		}
		created = revoked.Policy
		response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies/"+created.ID.String()+"/revoke", revokeURLAuthKeyRequest{KeyID: created.CurrentKey.KeyID}, platformAuth.AccessToken, "url-auth-revoke-current", quoteVersion(created.Revision))
		assertError(t, response, http.StatusConflict, "url_auth_key_not_revocable", "")
		response.Body.Close()
	})

	t.Run("audit failure rolls back resource and idempotency", func(t *testing.T) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `CREATE FUNCTION fail_url_auth_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='url_auth_policy.create' AND NEW.request_id='url-auth-audit-fail' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$`); err != nil {
			t.Fatalf("create trigger function: %v", err)
		}
		if _, err := pool.Exec(ctx, `CREATE TRIGGER fail_url_auth_policy_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_url_auth_policy_audit()`); err != nil {
			t.Fatalf("create trigger: %v", err)
		}
		secondSite := insertURLAuthSite(t, pool, tenantA, "rollback.example")
		body := createBody
		body.Name = "Must Roll Back"
		body.SiteID = secondSite
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/url-auth-policies", body, platformAuth.AccessToken, "url-auth-audit-rollback", "", "url-auth-audit-fail")
		assertError(t, response, http.StatusInternalServerError, "internal_error", "url-auth-audit-fail")
		response.Body.Close()
		if _, err := pool.Exec(ctx, `DROP TRIGGER fail_url_auth_policy_audit ON audit_events; DROP FUNCTION fail_url_auth_policy_audit()`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
		var policies, writes int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM url_auth_policies WHERE name='Must Roll Back'`).Scan(&policies); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM url_auth_policy_write_requests WHERE idempotency_key='url-auth-audit-rollback'`).Scan(&writes); err != nil {
			t.Fatal(err)
		}
		if policies != 0 || writes != 0 {
			t.Fatalf("rollback policies=%d writes=%d", policies, writes)
		}
	})

	if _, err := pool.Exec(context.Background(), `UPDATE url_auth_policies SET migration_marker=$2 WHERE id=$1`, created.ID, urlauthpolicy.LegacyTypeA); err != nil {
		t.Fatalf("set migration marker: %v", err)
	}
	response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/url-auth-policies/"+created.ID.String(), nil, platformAuth.AccessToken, "", "")
	var marked urlauthpolicy.Policy
	decodeResponse(t, response, http.StatusOK, &marked)
	response.Body.Close()
	if marked.MigrationMarker == nil || *marked.MigrationMarker != urlauthpolicy.LegacyTypeA {
		t.Fatalf("migration marker=%v", marked.MigrationMarker)
	}
	if err := audit.New(pool).VerifyScope(context.Background(), tenantA.scopeID); err != nil {
		t.Fatalf("VerifyScope: %v", err)
	}
}

func TestURLAuthPolicyMigrationDownUp(t *testing.T) {
	// Only 1..030: rolling the release head back crosses migration 268's
	// one-way down gate (P2682).
	pool := migrationRoundTripPool(t, 30)
	if migrationVersion(t, pool) != 30 {
		t.Fatalf("migration version=%d want 30", migrationVersion(t, pool))
	}
	if err := database.Migrate(context.Background(), pool, "down"); err != nil {
		t.Fatalf("migrate 030 down: %v", err)
	}
	if relationExists(t, pool, "url_auth_policies") {
		t.Fatal("migration 030 rollback retained URL auth tables")
	}
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 30); err != nil {
		t.Fatalf("migrate 030 up: %v", err)
	}
	if migrationVersion(t, pool) != 30 || !relationExists(t, pool, "url_auth_policies") {
		t.Fatal("migration 030 reapply did not restore URL auth tables")
	}
}

type urlAuthTenantFixture struct {
	scopeID, userID uuid.UUID
	username        string
}

func insertURLAuthTenant(t *testing.T, pool *pgxpool.Pool, displayName, username, passwordHash string) urlAuthTenantFixture {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, displayName); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatalf("insert scope: %v", err)
	}
	ownerRoleID, viewerRoleID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,system_role) VALUES
		($1,$3,'tenant_owner',true),($2,$3,'tenant_viewer',true)`, ownerRoleID, viewerRoleID, scopeID); err != nil {
		t.Fatalf("insert url auth tenant roles: %v", err)
	}
	if _, err := pool.Exec(ctx, `WITH additions AS (
		INSERT INTO role_permissions(role_id,permission_name) VALUES
			($1,'url_auth_policies.read'),($1,'url_auth_policies.manage'),($2,'url_auth_policies.read')
		ON CONFLICT DO NOTHING RETURNING role_id,permission_name
	)
	INSERT INTO custom_rbac_system_role_permission_additions(role_id,permission_name)
	SELECT role_id,permission_name FROM additions ON CONFLICT DO NOTHING`, ownerRoleID, viewerRoleID); err != nil {
		t.Fatalf("project url auth tenant role permissions: %v", err)
	}
	userID := insertSiteScopeUser(t, pool, scopeID, username, displayName+" Owner", passwordHash, []string{"url_auth_policies.read", "url_auth_policies.manage"})
	return urlAuthTenantFixture{scopeID: scopeID, userID: userID, username: username}
}

func insertURLAuthSite(t *testing.T, pool *pgxpool.Pool, tenant urlAuthTenantFixture, domain string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin site fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id) VALUES($1,$2,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`, id, tenant.scopeID, tenant.userID, domain); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, id); err != nil {
		t.Fatalf("insert origin pool: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, id); err != nil {
		t.Fatalf("insert origin: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit site fixture: %v", err)
	}
	return id
}

func validURLAuthFields(siteID uuid.UUID, name string) urlauthpolicy.PolicyFields {
	return urlauthpolicy.PolicyFields{SiteID: siteID, Name: name, Enabled: true, Algorithm: urlauthpolicy.AlgorithmHMACSHA256, SignatureParameter: "sig", ExpirationParameter: "exp", KeyIDParameter: "kid", BindClientIP: true, MaxClockSkewSeconds: 30, MaxValiditySeconds: 600, MaxSignatureUses: 1, ExcludedQueryParameters: []string{"utm_source", "utm_campaign"}, TrustedProxyCIDRs: []string{"2001:db8::/32", "10.0.0.0/8"}}
}

func policyFields(item urlauthpolicy.Policy) urlauthpolicy.PolicyFields {
	return urlauthpolicy.PolicyFields{SiteID: item.Site.ID, Name: item.Name, Enabled: item.Enabled, Algorithm: item.Algorithm, SignatureParameter: item.SignatureParameter, ExpirationParameter: item.ExpirationParameter, KeyIDParameter: item.KeyIDParameter, BindClientIP: item.BindClientIP, MaxClockSkewSeconds: item.MaxClockSkewSeconds, MaxValiditySeconds: item.MaxValiditySeconds, MaxSignatureUses: item.MaxSignatureUses, ExcludedQueryParameters: item.ExcludedQueryParameters, TrustedProxyCIDRs: item.TrustedProxyCIDRs}
}

func createURLAuthPolicy(t *testing.T, client *http.Client, baseURL, token, key string, body createURLAuthPolicyRequest) urlauthpolicy.SecretWriteResult {
	t.Helper()
	response := siteRequest(t, client, http.MethodPost, baseURL+"/v1/url-auth-policies", body, token, key, "")
	var result urlauthpolicy.SecretWriteResult
	decodeResponse(t, response, http.StatusCreated, &result)
	response.Body.Close()
	return result
}

func assertURLAuthSecretAbsent(t *testing.T, pool *pgxpool.Pool, policyID uuid.UUID, secret string) {
	t.Helper()
	ctx := context.Background()
	rows, err := pool.Query(ctx, `SELECT ciphertext FROM url_auth_policy_keys WHERE policy_id=$1`, policyID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var ciphertext []byte
		if err := rows.Scan(&ciphertext); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte(secret)) {
			rows.Close()
			t.Fatal("ciphertext contains plaintext secret")
		}
	}
	rows.Close()
	checks := map[string]string{
		"write": `SELECT COALESCE(string_agg(response_body::text,''),'') FROM url_auth_policy_write_requests WHERE resource_id=$1`,
		"audit": `SELECT COALESCE(string_agg(payload::text,''),'') FROM audit_events WHERE resource_id=$1`,
	}
	for label, query := range checks {
		var value string
		argument := any(policyID)
		if label == "audit" {
			argument = policyID.String()
		}
		if err := pool.QueryRow(ctx, query, argument).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(value, secret) || strings.Contains(value, "ciphertext") {
			t.Fatalf("%s leaked secret material: %s", label, value)
		}
	}
}
