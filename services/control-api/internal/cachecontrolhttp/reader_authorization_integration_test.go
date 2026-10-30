//go:build integration

package cachecontrolhttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard/guardtest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCacheControlReaderRechecksLiveAuthorityAndPlatformWildcard(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	store, err := cachecontrol.NewStore(pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, reader, bytes.Repeat([]byte{0x6c}, 32))
	if err != nil {
		t.Fatal(err)
	}

	assertReads := func(t *testing.T, handler http.Handler, credential string, wantStatus int, admin bool) {
		t.Helper()
		prefix := "/v1"
		query := ""
		if admin {
			prefix = "/v1/admin"
			query = "?scope_id=" + fixture.scopeA.String()
		}
		response := serve(t, handler, http.MethodGet, prefix+"/cache-operations"+query, nil, credential, "")
		if response.Code != wantStatus {
			t.Fatalf("operation list status = %d, want %d: %s", response.Code, wantStatus, response.Body.String())
		}
		separator := "?"
		if query != "" {
			separator = "&"
		}
		response = serve(t, handler, http.MethodGet,
			prefix+"/cache-policies/"+fixture.siteA.String()+"/revisions"+query+separator+"limit=10",
			nil, credential, "")
		if response.Code != wantStatus {
			t.Fatalf("policy history status = %d, want %d: %s", response.Code, wantStatus, response.Body.String())
		}
	}

	tenantHandler, err := NewHandler(service, fixture.authenticate)
	if err != nil {
		t.Fatal(err)
	}
	assertReads(t, tenantHandler, "tenant-a", http.StatusOK, false)

	if _, err := pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, fixture.userA); err != nil {
		t.Fatal(err)
	}
	assertReads(t, tenantHandler, "tenant-a", http.StatusNotFound, false)
	if _, err := pool.Exec(t.Context(), `UPDATE users SET status='active' WHERE id=$1`, fixture.userA); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, fixture.scopeA, fixture.userA); err != nil {
		t.Fatal(err)
	}
	assertReads(t, tenantHandler, "tenant-a", http.StatusNotFound, false)
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		SELECT $1,$2,id FROM roles WHERE scope_id=$1`, fixture.scopeA, fixture.userA); err != nil {
		t.Fatal(err)
	}

	platformRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'Cache reader platform wildcard',true)`, platformRoleID, fixture.platformScope,
		"cache-reader-platform-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin')`, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
		fixture.platformScope, fixture.platformUser, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		fixture.scopeA, fixture.platformUser); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM memberships WHERE scope_id=$1 AND user_id=$2`,
		fixture.scopeA, fixture.platformUser); err != nil {
		t.Fatal(err)
	}
	platformHandler, err := NewHandler(service, func(*http.Request) (identity.Principal, error) {
		return principal(fixture.platformUser, fixture.platformScope, "platform", "platform.admin"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertReads(t, platformHandler, "platform-admin", http.StatusOK, true)

	tenantWildcardHandler, err := NewHandler(service, func(*http.Request) (identity.Principal, error) {
		return principal(fixture.userA, fixture.scopeA, "tenant", "platform.admin"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertReads(t, tenantWildcardHandler, "tenant-wildcard", http.StatusForbidden, false)
}

func TestCacheControlProductionHandlerAuthenticatesFormalSessions(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	tokens, err := identity.NewTokenManager(strings.Repeat("c", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x53}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := entitlementguard.NewTrustStore([]entitlementguard.VerificationKey{{
		KeyID: "cache-control-http-test-key", PublicKey: publicKey,
	}})
	if err != nil {
		t.Fatal(err)
	}
	installCacheControlHTTPLease(t, pool, trust, privateKey, now)
	handler, err := NewProductionHandler(ProductionConfig{
		CursorKey: bytes.Repeat([]byte{0x63}, 32),
		Clock:     func() time.Time { return now },
	}, ProductionDependencies{
		Pool:        pool,
		Entitlement: entitlementguard.NewGuard(pool, func() time.Time { return now }, trust),
		Identity:    identityService,
		IAM:         authorizer,
		Authenticate: func(request *http.Request) (identity.Principal, error) {
			return identityService.Authenticate(request.Context(),
				strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	sessionID := uuid.New()
	rawToken, _, err := tokens.Mint(fixture.userA, fixture.scopeA, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	refreshHash := sha256.Sum256([]byte("cache-control-runtime-" + sessionID.String()))
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.userA, fixture.scopeA,
		refreshHash[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	unknownOperationPath := "/v1/cache-operations/" + uuid.NewString()
	t.Run("valid session reaches route", func(t *testing.T) {
		response := serve(t, handler, http.MethodGet, unknownOperationPath, nil, "Bearer "+rawToken, "")
		if response.Code != http.StatusNotFound {
			t.Errorf("valid formal session status = %d, want 404 route result: %s",
				response.Code, response.Body.String())
		}
	})
	t.Run("reader rejects missing or forged actor scope", func(t *testing.T) {
		reader, err := newProductionPostgresReader(pool, authorizer)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		ctx := context.WithValue(t.Context(), runtimeSessionKey{}, runtimeSessionResult{
			session: runtimeSession{
				principal: principal(fixture.userA, fixture.scopeA, "tenant"),
				sessionID: sessionID,
				rawToken:  rawToken,
			},
		})
		for _, actorScopeID := range []uuid.UUID{uuid.Nil, uuid.New()} {
			actor := cachecontrol.Actor{
				UserID: fixture.userA, ScopeID: fixture.scopeA, ActorScopeID: actorScopeID,
			}
			if err := reader.authorize(ctx, tx, actor, PermissionOperationsRead); !errors.Is(err, ErrNotFound) {
				t.Fatalf("authorize(actor scope %s) error = %v, want not found", actorScopeID, err)
			}
		}
	})
	t.Run("tenant write carries authenticated actor scope", func(t *testing.T) {
		response := serve(t, handler, http.MethodPost, "/v1/cache-operations",
			integrationOperationBody(fixture.siteA, fixture.nodeA,
				"http://a.cache.example/formal-tenant", 0),
			"Bearer "+rawToken, "formal-shared-operation")
		if response.Code != http.StatusAccepted {
			t.Fatalf("tenant formal write status = %d: %s", response.Code, response.Body.String())
		}
		operationID := decodeOperation(t, response).ID
		var targetScopeID, actorScopeID, actorUserID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT scope_id,actor_scope_id,actor_user_id
			FROM cache_operations WHERE id=$1`, operationID).Scan(
			&targetScopeID, &actorScopeID, &actorUserID); err != nil {
			t.Fatal(err)
		}
		if targetScopeID != fixture.scopeA || actorScopeID != fixture.scopeA || actorUserID != fixture.userA {
			t.Fatalf("tenant operation provenance target=%s actor_scope=%s actor=%s",
				targetScopeID, actorScopeID, actorUserID)
		}
	})
	t.Run("reader linearizes permission revocation before business queries", func(t *testing.T) {
		var roleID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT role_id FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2`, fixture.scopeA, fixture.userA).Scan(&roleID); err != nil {
			t.Fatal(err)
		}
		holder, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = holder.Rollback(context.Background()) }()
		if err := iamlock.AcquireExclusive(t.Context(), holder); err != nil {
			t.Fatal(err)
		}
		if _, err := iamlock.AcquireScopes(t.Context(), holder, []uuid.UUID{fixture.scopeA}); err != nil {
			t.Fatal(err)
		}

		responseChannel := make(chan int, 1)
		go func() {
			responseChannel <- serve(t, handler, http.MethodGet, "/v1/cache-operations",
				nil, "Bearer "+rawToken, "").Code
		}()
		waitForCacheHTTPSharedIAMWait(t, pool)
		deleted, err := holder.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.scopeA, fixture.userA, roleID)
		if err != nil {
			t.Fatal(err)
		}
		if deleted.RowsAffected() != 1 {
			t.Fatalf("revoked tenant read assignments = %d, want 1", deleted.RowsAffected())
		}
		if err := holder.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case status := <-responseChannel:
			if status != http.StatusNotFound {
				t.Fatalf("read after linearized permission revocation status = %d, want 404", status)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cache reader did not finish after permission revocation")
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if err := iamlock.AcquireExclusive(t.Context(), tx); err != nil {
				return err
			}
			if _, err := iamlock.AcquireScopes(t.Context(), tx, []uuid.UUID{fixture.scopeA}); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3)`, fixture.scopeA, fixture.userA, roleID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("platform write and reads retain separate actor scope", func(t *testing.T) {
		platformRoleID := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,$3,'Cache HTTP formal platform role',true)`, platformRoleID,
			fixture.platformScope, "cache-http-formal-platform-"+uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'platform.admin')`, platformRoleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, fixture.platformScope, fixture.platformUser, platformRoleID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2`, fixture.scopeA, fixture.platformUser); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `DELETE FROM memberships
			WHERE scope_id=$1 AND user_id=$2`, fixture.scopeA, fixture.platformUser); err != nil {
			t.Fatal(err)
		}

		platformSessionID := uuid.New()
		platformToken, _, err := tokens.Mint(fixture.platformUser, fixture.platformScope, platformSessionID)
		if err != nil {
			t.Fatal(err)
		}
		platformRefreshHash := sha256.Sum256([]byte("cache-control-runtime-" + platformSessionID.String()))
		if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
			id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, platformSessionID, uuid.New(), fixture.platformUser,
			fixture.platformScope, platformRefreshHash[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}

		scopeQuery := "?scope_id=" + fixture.scopeA.String()
		// fix-cachequota2: the tenant's usage before the platform submission.
		quotaPath := "/v1/admin/cache-operations/daily-usage" + scopeQuery
		readUsage := func(label string) cachecontrol.DailyUsage {
			t.Helper()
			response := serve(t, handler, http.MethodGet, quotaPath, nil, "Bearer "+platformToken, "")
			var usage cachecontrol.DailyUsage
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &usage) != nil {
				t.Fatalf("%s quota read status = %d: %s", label, response.Code, response.Body.String())
			}
			return usage
		}
		before := readUsage("baseline")
		response := serve(t, handler, http.MethodPost, "/v1/admin/cache-operations"+scopeQuery,
			integrationOperationBody(fixture.siteA, fixture.nodeA,
				"http://a.cache.example/formal-platform", 0),
			"Bearer "+platformToken, "formal-shared-operation")
		if response.Code != http.StatusAccepted {
			t.Fatalf("platform formal write status = %d: %s", response.Code, response.Body.String())
		}
		operationID := decodeOperation(t, response).ID
		var targetScopeID, actorScopeID, actorUserID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT scope_id,actor_scope_id,actor_user_id
			FROM cache_operations WHERE id=$1`, operationID).Scan(
			&targetScopeID, &actorScopeID, &actorUserID); err != nil {
			t.Fatal(err)
		}
		if targetScopeID != fixture.scopeA || actorScopeID != fixture.platformScope ||
			actorUserID != fixture.platformUser {
			t.Fatalf("platform operation provenance target=%s actor_scope=%s actor=%s",
				targetScopeID, actorScopeID, actorUserID)
		}
		response = serve(t, handler, http.MethodGet, "/v1/admin/cache-operations"+scopeQuery,
			nil, "Bearer "+platformToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("platform formal list status = %d: %s", response.Code, response.Body.String())
		}
		response = serve(t, handler, http.MethodGet,
			"/v1/admin/cache-policies/"+fixture.siteA.String()+"/revisions"+scopeQuery,
			nil, "Bearer "+platformToken, "")
		if response.Code != http.StatusOK {
			t.Fatalf("platform formal history status = %d: %s", response.Code, response.Body.String())
		}
		// fix-cachequota2: the platform submission on the tenant's behalf is not
		// counted against the tenant; the administrator sets its own limits
		// (audited, revision-checked).
		usage := readUsage("after platform write")
		if usage.URLPurge.Used != before.URLPurge.Used || usage.Revision != 0 {
			t.Fatalf("platform submission counted: before=%d after=%+v", before.URLPurge.Used, usage)
		}
		limit := usage.URLPurge.Used + 2
		response = serveRaw(t, handler, http.MethodPut, quotaPath,
			fmt.Sprintf(`{"expected_revision":0,"url_purge_limit":%d,"directory_purge_limit":null,"prewarm_limit":0}`, limit),
			"Bearer "+platformToken, "")
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &usage) != nil ||
			usage.Revision != 1 || usage.URLPurge.Limit != limit || usage.URLPurge.Remaining != 2 || usage.Prewarm.Limit != 0 {
			t.Fatalf("platform quota write status = %d: %s", response.Code, response.Body.String())
		}
		var audited int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE scope_id=$1
			AND action='cache.account_quota.update' AND actor_user_id=$2 AND result='success'`,
			fixture.scopeA, fixture.platformUser).Scan(&audited); err != nil || audited != 1 {
			t.Fatalf("quota audit events = %d, %v", audited, err)
		}
		response = serveRaw(t, handler, http.MethodPut, quotaPath,
			`{"expected_revision":0,"url_purge_limit":null,"directory_purge_limit":null,"prewarm_limit":null}`,
			"Bearer "+platformToken, "")
		assertAPIError(t, response, http.StatusPreconditionFailed, "revision_conflict")
		// The tenant uses up its limit; its next create is 429 with details.
		for index, key := range []string{"formal-quota-ok", "formal-quota-ok-2"} {
			response = serve(t, handler, http.MethodPost, "/v1/cache-operations",
				integrationOperationBody(fixture.siteA, fixture.nodeA, fmt.Sprintf("http://a.cache.example/over-%d", index+1), 0),
				"Bearer "+rawToken, key)
			if response.Code != http.StatusAccepted {
				t.Fatalf("tenant within the account limit (%s) status = %d: %s", key, response.Code, response.Body.String())
			}
		}
		response = serve(t, handler, http.MethodPost, "/v1/cache-operations",
			integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/over-3", 0),
			"Bearer "+rawToken, "formal-quota-over")
		assertAPIError(t, response, http.StatusTooManyRequests, "daily_limit_exceeded")
		// The platform administrator still submits for the full tenant; the
		// tenant's usage stays at its limit and the audit names the administrator.
		response = serve(t, handler, http.MethodPost, "/v1/admin/cache-operations"+scopeQuery,
			integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/platform-over", 0),
			"Bearer "+platformToken, "formal-platform-over")
		if response.Code != http.StatusAccepted {
			t.Fatalf("platform submission at the tenant's limit status = %d: %s", response.Code, response.Body.String())
		}
		platformOverID := decodeOperation(t, response).ID
		if usage = readUsage("after full"); usage.URLPurge.Used != limit || usage.URLPurge.Remaining != 0 {
			t.Fatalf("usage after platform submission at the limit = %+v", usage.URLPurge)
		}
		var createdBy uuid.UUID
		var createdActorScope string
		if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,payload->>'actor_scope_id' FROM audit_events
			WHERE scope_id=$1 AND action='cache.operation.create' AND resource_id=$2`,
			fixture.scopeA, platformOverID.String()).Scan(&createdBy, &createdActorScope); err != nil ||
			createdBy != fixture.platformUser || createdActorScope != fixture.platformScope.String() {
			t.Fatalf("platform create audit actor=%s actor_scope=%s err=%v", createdBy, createdActorScope, err)
		}
	})
	t.Run("invalid session is unauthorized", func(t *testing.T) {
		response := serve(t, handler, http.MethodGet, unknownOperationPath, nil,
			"Bearer invalid-formal-session", "")
		assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	})
	t.Run("revoked session is unauthorized", func(t *testing.T) {
		if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions
			SET revoked_at=$2,revocation_reason='cache-runtime-test' WHERE id=$1`, sessionID, now); err != nil {
			t.Fatal(err)
		}
		response := serve(t, handler, http.MethodGet, unknownOperationPath, nil, "Bearer "+rawToken, "")
		assertAPIError(t, response, http.StatusUnauthorized, "authentication_required")
	})
}

type cacheControlHTTPLeaseSigner struct {
	privateKey ed25519.PrivateKey
}

func (cacheControlHTTPLeaseSigner) KeyID() string { return "cache-control-http-test-key" }

func (signer cacheControlHTTPLeaseSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.privateKey, payload), nil
}

func installCacheControlHTTPLease(
	t *testing.T,
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	privateKey ed25519.PrivateKey,
	now time.Time,
) {
	t.Helper()
	lease := entitlement.Lease{
		Schema: entitlement.SchemaV1, Audience: entitlement.ControlAudience,
		// Canonical UUIDs: revocation sets accept nothing else.
		CustomerID: "aaaaaaaa-1111-4111-8111-111111111111", InstallationID: "aaaaaaaa-2222-4222-8222-222222222222",
		LicenseID: "aaaaaaaa-3333-4333-8333-333333333333", Serial: 1, NotBefore: now.Add(-time.Hour).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(), GraceUntil: now.Add(2 * time.Hour).Unix(),
		Version:  entitlement.VersionRange{Channel: "stable", Min: "0.1.0", Max: "1.0.0"},
		Features: []entitlement.Feature{{Code: entitlementguard.FeatureSitesManage}},
		Quotas:   []entitlement.Quota{{Code: entitlementguard.QuotaDomainsCount, Limit: 100}},
	}
	guardtest.AcceptRevocation(t, pool, trust, cacheControlHTTPLeaseSigner{privateKey: privateKey}, lease, now)
	signed, err := entitlement.Sign(t.Context(), lease, cacheControlHTTPLeaseSigner{privateKey: privateKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entitlementguard.NewService(pool, trust).Install(t.Context(), entitlementguard.InstallBundle{
		InstallationID: lease.InstallationID, SignedLease: signed,
	}, now); err != nil {
		t.Fatal(err)
	}
}

func waitForCacheHTTPSharedIAMWait(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_catalog.pg_locks
			WHERE locktype='advisory' AND classid=1229016321::oid AND objid=1::oid
			  AND objsubid=2 AND mode='ShareLock' AND NOT granted)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("cache reader did not wait on the IAM global shared lock")
}

func TestCacheControlRuntimeSessionCredentialsRemainPrivate(t *testing.T) {
	rawToken := "cache-control-runtime-session-secret"
	sessionID := uuid.New()
	session := runtimeSession{sessionID: sessionID, rawToken: rawToken}
	formatted := map[string]string{
		"String": session.String(),
		"%s":     fmt.Sprintf("%s", session),
		"%v":     fmt.Sprintf("%v", session),
		"%+v":    fmt.Sprintf("%+v", session),
		"%#v":    fmt.Sprintf("%#v", session),
		"%q":     fmt.Sprintf("%q", session),
	}
	for name, value := range formatted {
		if value != redactedRuntimeSession || strings.Contains(value, rawToken) ||
			strings.Contains(value, sessionID.String()) {
			t.Errorf("%s runtime session formatting = %q", name, value)
		}
	}
	payload, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), rawToken) || strings.Contains(string(payload), sessionID.String()) {
		t.Fatalf("runtime session JSON leaked credential: %s", payload)
	}
}
