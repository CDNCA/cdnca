//go:build integration

package cachecontrolhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
)

// fix-cacheflow3 §3 (CACHE-ADD-05): cancelling a cache operation from the task
// center with a real session runs the cache module's cancel, so the cache
// projection and the unified job say the same thing, with one cache audit
// and no generic job.* write; the cache page then sees the cancel, and a
// replay of the task-center key changes nothing.
func TestTaskCenterCancelKeepsCacheAndUnifiedJobProjectionsInStep(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx := t.Context()

	// The task center needs jobs.read/jobs.manage. Migration 094 only lets
	// jobs.manage onto a tenant scope's tenant_owner system role (custom roles
	// go through RBAC facts), so the user also holds tenant_owner here.
	jobsRoleID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,'tenant_owner','Task center integration role',true)`, jobsRoleID, fixture.scopeA); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'jobs.read'),($1,'jobs.manage') ON CONFLICT DO NOTHING`, jobsRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.scopeA, fixture.userA, jobsRoleID); err != nil {
		t.Fatal(err)
	}

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
	authenticate := func(request *http.Request) (identity.Principal, error) {
		return identityService.Authenticate(request.Context(),
			strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer "))
	}
	config := ProductionConfig{CursorKey: bytes.Repeat([]byte{0x63}, 32), Clock: func() time.Time { return now }}
	dependencies := ProductionDependencies{
		Pool: pool, Entitlement: entitlementguard.NewGuard(pool, func() time.Time { return now }, trust),
		Identity: identityService, IAM: authorizer, Authenticate: authenticate,
	}
	cacheHandler, err := NewProductionHandler(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewProductionJobCommandRouter(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	jobReader, err := jobhttp.NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	jobService, err := jobhttp.NewService(jobReader, jobhttp.ServiceConfig{
		ActiveCursorKeyID: "cache-job-v1",
		CursorKeys:        map[string][]byte{"cache-job-v1": bytes.Repeat([]byte{0x6a}, 32)},
		ProducerCommands:  map[string]jobhttp.ProducerCommandRouter{"cache.operation": router},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Same principal mapping as httpapi.authenticateJobQuery for a Bearer session.
	jobHandler, err := jobhttp.NewHandler(jobService, func(request *http.Request) (jobhttp.Principal, error) {
		principal, err := authenticate(request)
		if err != nil {
			return jobhttp.Principal{}, err
		}
		permissions := make(map[string]struct{}, len(principal.Permissions))
		for _, permission := range principal.Permissions {
			permissions[permission] = struct{}{}
		}
		return jobhttp.Principal{
			UserID: principal.UserID, ScopeID: principal.ScopeID,
			ScopeKind: jobhttp.ScopeKind(principal.ScopeKind), Permissions: permissions,
		}.WithSessionCredential(strings.TrimPrefix(request.Header.Get("Authorization"), "Bearer ")), nil
	}, jobhttp.HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}

	sessionID := uuid.New()
	rawToken, _, err := tokens.Mint(fixture.userA, fixture.scopeA, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	refreshHash := sha256.Sum256([]byte("cache-task-center-" + sessionID.String()))
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), fixture.userA, fixture.scopeA,
		refreshHash[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	bearer := "Bearer " + rawToken

	created := serve(t, cacheHandler, http.MethodPost, "/v1/cache-operations",
		integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/task-center-cancel", 0),
		bearer, "task-center-cancel-create")
	if created.Code != http.StatusAccepted {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	operationID := decodeOperation(t, created).ID

	jobRequest := func(method, path, ifMatch, key string) *httptest.ResponseRecorder {
		t.Helper()
		var body *strings.Reader
		if method == http.MethodPost {
			body = strings.NewReader(`{}`)
		} else {
			body = strings.NewReader("")
		}
		request := httptest.NewRequest(method, path, body)
		request.Header.Set("Authorization", bearer)
		request.Header.Set("X-Request-ID", "task-center-cancel-01")
		if method == http.MethodPost {
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", key)
			request.Header.Set("If-Match", ifMatch)
		}
		response := httptest.NewRecorder()
		jobHandler.ServeHTTP(response, request)
		return response
	}
	detail := jobRequest(http.MethodGet, "/v1/jobs/"+operationID.String(), "", "")
	if detail.Code != http.StatusOK || detail.Header().Get("ETag") == "" {
		t.Fatalf("task center detail status = %d etag=%q: %s", detail.Code, detail.Header().Get("ETag"), detail.Body.String())
	}
	etag := detail.Header().Get("ETag")

	cancelled := jobRequest(http.MethodPost, "/v1/jobs/"+operationID.String()+"/cancel", etag, "task-center-cancel-1")
	if cancelled.Code != http.StatusOK {
		t.Fatalf("task center cancel status = %d: %s", cancelled.Code, cancelled.Body.String())
	}

	assertProjections := func(t *testing.T) {
		t.Helper()
		var cacheState, jobState string
		var cacheCancelled, jobCancelled int
		var cacheCancelRequested, jobCancelRequested bool
		if err := pool.QueryRow(ctx, `
			SELECT operation.state,operation.cancelled_count,operation.cancel_requested_at IS NOT NULL,
			       job.state,job.cancelled_count,job.cancel_requested_at IS NOT NULL
			FROM cache_operations operation JOIN background_jobs job ON job.id=operation.id
			WHERE operation.id=$1`, operationID).Scan(&cacheState, &cacheCancelled, &cacheCancelRequested,
			&jobState, &jobCancelled, &jobCancelRequested); err != nil {
			t.Fatal(err)
		}
		if cacheState != "cancelled" || jobState != "cancelled" || !cacheCancelRequested || !jobCancelRequested ||
			cacheCancelled != jobCancelled {
			t.Fatalf("projections cache=%s/%d/%v job=%s/%d/%v", cacheState, cacheCancelled, cacheCancelRequested,
				jobState, jobCancelled, jobCancelRequested)
		}
		// One cache cancel and its one unified receipt, both from the cache
		// module's transaction (receipt key "cache-…"); the generic job
		// command path wrote nothing.
		var cacheAudits, cacheReceipts, genericAudits int
		if err := pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE action='cache.operation.cancel' AND resource_type='cache_operation'),
			count(*) FILTER (WHERE action='job.cancel' AND resource_type='background_job'
			                 AND payload->>'idempotency_key' LIKE 'cache-%'),
			count(*) FILTER (WHERE action LIKE 'job.%' AND resource_type='background_job'
			                 AND COALESCE(payload->>'idempotency_key','') NOT LIKE 'cache-%')
			FROM audit_events WHERE resource_id=$1::text`, operationID.String()).Scan(
			&cacheAudits, &cacheReceipts, &genericAudits); err != nil {
			t.Fatal(err)
		}
		if cacheAudits != 1 || cacheReceipts != 1 || genericAudits != 0 {
			t.Fatalf("audits cache.operation.cancel=%d cache job.cancel=%d generic job.*=%d, want 1/1/0",
				cacheAudits, cacheReceipts, genericAudits)
		}
	}
	assertProjections(t)

	// The cache page reads the same cancellation.
	read := serve(t, cacheHandler, http.MethodGet, "/v1/cache-operations/"+operationID.String(), nil, bearer, "")
	if got := decodeOperation(t, read); string(got.State) != "cancelled" {
		t.Fatalf("cache page state = %s, want cancelled", got.State)
	}
	// Replaying the task-center key is a replay, not a second cancel.
	replayed := jobRequest(http.MethodPost, "/v1/jobs/"+operationID.String()+"/cancel", etag, "task-center-cancel-1")
	var replay jobhttp.CommandResult
	if replayed.Code != http.StatusOK || json.Unmarshal(replayed.Body.Bytes(), &replay) != nil || !replay.Replayed {
		t.Fatalf("replay status = %d: %s", replayed.Code, replayed.Body.String())
	}
	assertProjections(t)
	// A retry of a task cancelled with nothing failed is refused in both projections.
	current := jobRequest(http.MethodGet, "/v1/jobs/"+operationID.String(), "", "")
	retried := jobRequest(http.MethodPost, "/v1/jobs/"+operationID.String()+"/retry",
		current.Header().Get("ETag"), "task-center-retry-1")
	if retried.Code != http.StatusConflict {
		t.Fatalf("retry of cancelled task status = %d, want 409: %s", retried.Code, retried.Body.String())
	}
	assertProjections(t)
}
