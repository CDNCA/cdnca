package errorpagecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRuntimeHandlerPostgreSQLSmoke(t *testing.T) {
	fixture := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, fixture.pool)
	store := newRuntimeContentStore()
	scanner := &runtimeScanner{}
	tokens, err := identity.NewTokenManager(strings.Repeat("runtime-smoke-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(fixture.pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{7}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, RuntimeDependencies{
		Pool: fixture.pool, Identity: identityService,
		APIKeys: apikey.NewService(fixture.pool, bytes.Repeat([]byte{7}, 32), time.Now), IAM: iam,
		ContentStore: store, Scanner: scanner, Limits: runtimeLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}

	tenantToken := mintRuntimeToken(t, tokens, identities.tenantOwner)
	viewerToken := mintRuntimeToken(t, tokens, identities.tenantViewer)
	platformToken := mintRuntimeToken(t, tokens, identities.platform)

	response := serveRuntimeRequest(t, handler, http.MethodGet,
		"/v1/error-pages-neighbor/assets", nil, "", "")
	assertRuntimeStatus(t, response, http.StatusNotFound)
	response = serveRuntimeRequest(t, handler, http.MethodGet, apiPrefix+"/assets", nil,
		"Bearer definitely-not-a-session", "")
	assertRuntimeStatus(t, response, http.StatusUnauthorized)
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		map[string]any{"scope_id": identities.tenantScope}, "Bearer "+tenantToken, "invalid")
	assertRuntimeStatus(t, response, http.StatusBadRequest)

	content := []byte("temporarily unavailable")
	initiate := initiateAssetBody{
		ScopeID: identities.tenantScope, MIMEType: "text/plain",
		SizeBytes: int64(len(content)), SHA256: digestBytes(content),
	}
	unknownToken, _, err := tokens.Mint(identities.tenantOwner.UserID, identities.tenantScope, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	writesBefore := countRuntimeWrites(t, fixture.pool)
	storeBefore := store.snapshot()
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		initiate, "Bearer "+unknownToken, "unknown-session")
	assertRuntimeStatus(t, response, http.StatusUnauthorized)
	if writesAfter := countRuntimeWrites(t, fixture.pool); writesAfter != writesBefore || store.snapshot() != storeBefore {
		t.Fatalf("unknown session side effects writes_before=%d writes_after=%d store_before=%+v store_after=%+v",
			writesBefore, writesAfter, storeBefore, store.snapshot())
	}

	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		initiate, "Bearer "+tenantToken, "asset-initiate")
	assertRuntimeStatus(t, response, http.StatusCreated)
	asset := decodeSmokeBody[WriteResult[Asset]](t, response).Value
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		initiate, "Bearer "+tenantToken, "asset-initiate")
	assertRuntimeStatus(t, response, http.StatusCreated)
	if replay := decodeSmokeBody[WriteResult[Asset]](t, response); !replay.Replayed || replay.Value.ID != asset.ID {
		t.Fatalf("initiate replay=%#v", replay)
	}

	before := store.snapshot()
	response = serveRuntimeRequest(t, handler, http.MethodPut,
		apiPrefix+"/assets/"+asset.ID.String()+"/content", content,
		"Bearer "+viewerToken, "viewer-upload")
	assertRuntimeStatus(t, response, http.StatusForbidden)
	if after := store.snapshot(); after != before || scanner.calls() != 0 {
		t.Fatalf("denied upload side effects before=%+v after=%+v scans=%d", before, after, scanner.calls())
	}
	var deniedWrites int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_write_requests
		WHERE actor_user_id=$1 AND operation=$2`, identities.tenantViewer.UserID, operationAssetUpload).
		Scan(&deniedWrites); err != nil || deniedWrites != 0 {
		t.Fatalf("denied idempotency rows=%d err=%v", deniedWrites, err)
	}

	response = serveRuntimeRequest(t, handler, http.MethodPut,
		apiPrefix+"/assets/"+asset.ID.String()+"/content", content,
		"Bearer "+tenantToken, "owner-upload")
	assertRuntimeStatus(t, response, http.StatusOK)

	scanner.setError(errors.New("scanner backend path=/secret"))
	response = serveRuntimeRequest(t, handler, http.MethodPost,
		apiPrefix+"/assets/"+asset.ID.String()+"/finalize", nil,
		"Bearer "+tenantToken, "asset-finalize")
	assertRuntimeStatus(t, response, http.StatusServiceUnavailable)
	if strings.Contains(response.Body.String(), "scanner") || strings.Contains(response.Body.String(), "/secret") {
		t.Fatalf("scanner details leaked: %s", response.Body.String())
	}
	scanner.setError(nil)
	response = serveRuntimeRequest(t, handler, http.MethodPost,
		apiPrefix+"/assets/"+asset.ID.String()+"/finalize", nil,
		"Bearer "+tenantToken, "asset-finalize")
	assertRuntimeStatus(t, response, http.StatusOK)
	ready := decodeSmokeBody[WriteResult[Asset]](t, response).Value
	if ready.Status != StatusReady || scanner.calls() != 2 {
		t.Fatalf("ready status=%s scanner_calls=%d", ready.Status, scanner.calls())
	}

	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/rules", createRuleBody{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: identities.tenantScope, SiteID: &identities.siteID},
		Fields: RuleFields{
			Category: CategoryEdgeRoute, Match: StatusSelector{Kind: MatchExact, From: 503},
			AssetID: asset.ID, Enabled: true,
		},
	}, "Bearer "+tenantToken, "rule-create")
	assertRuntimeStatus(t, response, http.StatusCreated)
	rule := decodeSmokeBody[WriteResult[Rule]](t, response).Value
	response = serveRuntimeRequest(t, handler, http.MethodGet,
		apiPrefix+"/rules/"+rule.ID.String(), nil, "Bearer "+tenantToken, "")
	assertRuntimeStatus(t, response, http.StatusOK)
	response = serveRuntimeRequest(t, handler, http.MethodGet,
		apiPrefix+"/publication-snapshot", nil, "Bearer "+platformToken, "")
	assertRuntimeStatus(t, response, http.StatusOK)
	snapshot := decodeSmokeBody[PublicationSnapshot](t, response)
	if snapshot.Policy.Revision < 1 || snapshot.Policy.Schema != SchemaV1 || snapshot.SHA256 == "" {
		t.Fatalf("publication snapshot=%#v", snapshot)
	}

	var crossTenantWritesBefore int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_write_requests`).
		Scan(&crossTenantWritesBefore); err != nil {
		t.Fatal(err)
	}
	crossTenant := initiate
	crossTenant.ScopeID = identities.otherTenantScope
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		crossTenant, "Bearer "+tenantToken, "cross-tenant")
	assertRuntimeStatus(t, response, http.StatusForbidden)
	var crossTenantWritesAfter int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_write_requests`).
		Scan(&crossTenantWritesAfter); err != nil || crossTenantWritesAfter != crossTenantWritesBefore {
		t.Fatalf("cross-tenant writes before=%d after=%d err=%v",
			crossTenantWritesBefore, crossTenantWritesAfter, err)
	}

	rbacNow := storeTime(time.Now())
	rbac, err := rbacmanager.NewServiceWithDependencies(
		fixture.pool, audit.New(fixture.pool), reviewStepUp{now: rbacNow}, func() time.Time { return rbacNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	rbacActor := rbacmanager.Actor{
		UserID: identities.tenantOwner.UserID, ScopeID: identities.tenantScope,
		SessionID: identities.tenantOwner.Credential.ID, ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	manageRole, err := rbac.CreateRole(t.Context(), rbacActor, rbacmanager.CreateRoleRequest{
		Name: "error_page_runtime_smoke", Permissions: []string{permissionManage},
		Mutation: reviewRBACMutation("runtime-smoke-role-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	manageGrant, err := rbac.AssignRole(t.Context(), rbacActor, rbacmanager.AssignRoleRequest{
		RoleID: manageRole.ID, ExpectedRoleRevision: manageRole.CurrentRevision,
		SubjectUserID: identities.tenantViewer.UserID,
		Mutation:      reviewRBACMutation("runtime-smoke-role-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}
	temporaryContent := []byte("temporary manage permission")
	temporaryInitiate := initiate
	temporaryInitiate.SizeBytes = int64(len(temporaryContent))
	temporaryInitiate.SHA256 = digestBytes(temporaryContent)
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		temporaryInitiate, "Bearer "+viewerToken, "temporary-manage-active")
	assertRuntimeStatus(t, response, http.StatusCreated)
	if _, err := rbac.RevokeGrant(t.Context(), rbacActor, rbacmanager.RevokeGrantRequest{
		GrantID: manageGrant.ID, Mutation: reviewRBACMutation("runtime-smoke-grant-revoke"),
	}); err != nil {
		t.Fatal(err)
	}
	writesBefore = countRuntimeWrites(t, fixture.pool)
	storeBefore = store.snapshot()
	response = serveRuntimeRequest(t, handler, http.MethodPost, apiPrefix+"/assets/initiate",
		temporaryInitiate, "Bearer "+viewerToken, "revoked-permission")
	assertRuntimeStatus(t, response, http.StatusForbidden)
	if writesAfter := countRuntimeWrites(t, fixture.pool); writesAfter != writesBefore || store.snapshot() != storeBefore {
		t.Fatalf("revoked permission side effects writes_before=%d writes_after=%d store_before=%+v store_after=%+v",
			writesBefore, writesAfter, storeBefore, store.snapshot())
	}

	if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
		SET revoked_at=now(),revocation_reason='runtime_smoke' WHERE id=$1`,
		identities.tenantOwner.Credential.ID); err != nil {
		t.Fatal(err)
	}
	before = store.snapshot()
	writesBefore = countRuntimeWrites(t, fixture.pool)
	response = serveRuntimeRequest(t, handler, http.MethodDelete,
		apiPrefix+"/rules/"+rule.ID.String(), nil, "Bearer "+tenantToken, "revoked-delete")
	assertRuntimeStatus(t, response, http.StatusUnauthorized)
	if after, writesAfter := store.snapshot(), countRuntimeWrites(t, fixture.pool); after != before || writesAfter != writesBefore {
		t.Fatalf("revoked request side effects store_before=%+v store_after=%+v writes_before=%d writes_after=%d",
			before, after, writesBefore, writesAfter)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions
		SET revoked_at=NULL,revocation_reason=NULL WHERE id=$1`, identities.tenantOwner.Credential.ID); err != nil {
		t.Fatal(err)
	}
	response = serveRuntimeRequest(t, handler, http.MethodGet,
		apiPrefix+"/assets/"+asset.ID.String(), nil, "Bearer "+tenantToken, "")
	assertRuntimeStatus(t, response, http.StatusOK)
}

func TestRuntimeIAMRejectionDoesNotStarveBoundedPool(t *testing.T) {
	const concurrentRequests = 4
	for _, scenario := range []struct {
		name       string
		invalidJWT bool
		revoke     bool
		wantStatus int
		wantCode   string
	}{
		{name: "invalid bearer", invalidJWT: true, wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "valid without permission", wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
		{name: "formally revoked session", revoke: true, wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			database := openErrorPageDatabase(t)
			identities := seedErrorPageIdentities(t, database.pool)
			requestPool, _ := newRuntimeNamedPool(t, database.pool,
				"errorpage_runtime_pool_starvation_", concurrentRequests)
			store := newRuntimeContentStore()
			tokens, err := identity.NewTokenManager(strings.Repeat("runtime-pool-starvation-secret-", 2), time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			identityService, err := identity.NewService(identity.NewStore(requestPool), tokens, 24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x4e}, 32), time.Now)
			if err != nil {
				t.Fatal(err)
			}
			iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
			if err != nil {
				t.Fatal(err)
			}
			barrier := newRuntimeAuthorizationBarrier(concurrentRequests,
				runtimeTxAuthorizer{identity: identityService, iam: iam})
			defer barrier.releaseRequests()
			service, err := NewService(requestPool, store, &runtimeScanner{}, runtimeLimits(), barrier)
			if err != nil {
				t.Fatal(err)
			}

			rawToken := mintRuntimeToken(t, tokens, identities.tenantViewer)
			var authenticator Authenticator = runtimeAuthenticator{identity: identityService}
			if scenario.invalidJWT {
				request := httptest.NewRequest(http.MethodGet, "http://control.test"+apiPrefix+"/assets", nil)
				request.Header.Set("Authorization", "Bearer "+rawToken)
				actor, err := (runtimeAuthenticator{identity: identityService}).Authenticate(request)
				if err != nil {
					t.Fatal(err)
				}
				actor.rawSession = "definitely-not-a-session"
				authenticator = fixedAuthenticator{actor: actor}
				rawToken = actor.rawSession
			}
			inner, err := NewHandler(service, authenticator)
			if err != nil {
				t.Fatal(err)
			}
			handler := runtimeMetadataHandler{inner: inner}
			beforeFacts := readRuntimeDomainFacts(t, database.pool)
			beforeStore := store.snapshot()

			requestCtx, cancelRequests := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancelRequests()
			start := make(chan struct{})
			responses := make(chan runtimeResponseResult, concurrentRequests)
			content := []byte("pool starvation regression")
			body := initiateAssetBody{
				ScopeID: identities.tenantScope, MIMEType: "text/plain",
				SizeBytes: int64(len(content)), SHA256: digestBytes(content),
			}
			for index := 0; index < concurrentRequests; index++ {
				go func(index int) {
					select {
					case <-requestCtx.Done():
						responses <- runtimeResponseResult{err: requestCtx.Err()}
					case <-start:
						response, err := serveRuntimeRequestWithContext(requestCtx, handler, http.MethodPost,
							apiPrefix+"/assets/initiate", body, "Bearer "+rawToken,
							fmt.Sprintf("pool-starvation-%d", index))
						responses <- runtimeResponseResult{response: response, err: err}
					}
				}(index)
			}
			close(start)

			select {
			case <-barrier.reached:
			case <-requestCtx.Done():
				t.Fatalf("requests did not acquire %d business transactions: %v", concurrentRequests, requestCtx.Err())
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != concurrentRequests {
				t.Fatalf("acquired connections=%d want=%d", acquired, concurrentRequests)
			}
			if scenario.revoke {
				var refreshHash []byte
				if err := database.pool.QueryRow(requestCtx,
					`SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`,
					identities.tenantViewer.Credential.ID).Scan(&refreshHash); err != nil {
					t.Fatal(err)
				}
				if err := identity.NewStore(database.pool).RevokeSessionFamily(
					requestCtx, refreshHash, "pool-starvation-session-revoke"); err != nil {
					t.Fatal(err)
				}
			}
			barrier.releaseRequests()

			for index := 0; index < concurrentRequests; index++ {
				select {
				case result := <-responses:
					if result.err != nil {
						t.Fatal(result.err)
					}
					assertRuntimeRevocationDenied(t, result.response, scenario.wantStatus, scenario.wantCode)
				case <-requestCtx.Done():
					t.Fatalf("request %d exceeded bounded completion deadline: %v", index, requestCtx.Err())
				}
			}
			if acquired := requestPool.Stat().AcquiredConns(); acquired != 0 {
				t.Fatalf("acquired connections after rejection=%d want=0", acquired)
			}
			assertRuntimeDomainFacts(t, database.pool, beforeFacts)
			if afterStore := store.snapshot(); afterStore != beforeStore {
				t.Fatalf("rejected requests changed object facts: before=%+v after=%+v", beforeStore, afterStore)
			}
		})
	}
}

func mintRuntimeToken(t *testing.T, tokens *identity.TokenManager, actor Actor) string {
	t.Helper()
	raw, _, err := tokens.Mint(actor.UserID, actor.ScopeID, actor.Credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func serveRuntimeRequest(
	t *testing.T,
	handler http.Handler,
	method, target string,
	body any,
	authorization, writeKey string,
) *httptest.ResponseRecorder {
	t.Helper()
	response, err := serveRuntimeRequestWithContext(
		t.Context(), handler, method, target, body, authorization, writeKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func serveRuntimeRequestWithContext(
	ctx context.Context,
	handler http.Handler,
	method, target string,
	body any,
	authorization, writeKey string,
) (*httptest.ResponseRecorder, error) {
	var encoded []byte
	switch value := body.(type) {
	case nil:
	case []byte:
		encoded = value
	default:
		var err error
		encoded, err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	request := httptest.NewRequestWithContext(
		ctx, method, "http://control.test"+target, bytes.NewReader(encoded),
	)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	request.Header.Set("X-Request-ID", "runtime-smoke-request")
	if writeKey != "" {
		request.Header.Set("Idempotency-Key", writeKey)
		request.Header.Set("X-Request-ID", writeKey+"-request")
		request.Header.Set("X-Trace-ID", writeKey+"-trace")
		if _, ok := body.([]byte); ok {
			request.Header.Set("Content-Type", "text/plain")
		} else if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response, nil
}

func assertRuntimeStatus(t *testing.T, response *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if response.Code != expected {
		t.Fatalf("status=%d want=%d body=%s", response.Code, expected, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
}

func countRuntimeWrites(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM error_page_write_requests`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

type runtimeContentStore struct {
	inner *memoryContentStore
	mu    sync.Mutex
	stats runtimeStoreStats
}

type runtimeStoreStats struct {
	Put      int
	Open     int
	Finalize int
	Stat     int
	Delete   int
}

func newRuntimeContentStore() *runtimeContentStore {
	return &runtimeContentStore{inner: newMemoryContentStore()}
}

func (store *runtimeContentStore) Capabilities() ObjectStoreCapabilities {
	return store.inner.Capabilities()
}

func (store *runtimeContentStore) PutStaging(
	ctx context.Context,
	ref ObjectRef,
	body []byte,
	mime string,
) (ObjectInfo, error) {
	store.increment(func(stats *runtimeStoreStats) { stats.Put++ })
	return store.inner.PutStaging(ctx, ref, body, mime)
}

func (store *runtimeContentStore) Open(ctx context.Context, ref ObjectRef, token string) (io.ReadCloser, error) {
	store.increment(func(stats *runtimeStoreStats) { stats.Open++ })
	return store.inner.Open(ctx, ref, token)
}

func (store *runtimeContentStore) Finalize(
	ctx context.Context,
	stagingRef, objectRef ObjectRef,
	expected ObjectInfo,
) (ObjectInfo, error) {
	store.increment(func(stats *runtimeStoreStats) { stats.Finalize++ })
	return store.inner.Finalize(ctx, stagingRef, objectRef, expected)
}

func (store *runtimeContentStore) Stat(ctx context.Context, ref ObjectRef) (ObjectInfo, error) {
	store.increment(func(stats *runtimeStoreStats) { stats.Stat++ })
	return store.inner.Stat(ctx, ref)
}

func (store *runtimeContentStore) Delete(ctx context.Context, ref ObjectRef) error {
	store.increment(func(stats *runtimeStoreStats) { stats.Delete++ })
	return store.inner.Delete(ctx, ref)
}

func (store *runtimeContentStore) increment(increment func(*runtimeStoreStats)) {
	store.mu.Lock()
	defer store.mu.Unlock()
	increment(&store.stats)
}

func (store *runtimeContentStore) snapshot() runtimeStoreStats {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.stats
}

type runtimeScanner struct {
	mu  sync.Mutex
	err error
	n   int
}

func (*runtimeScanner) Name() string { return "runtime-smoke-scanner" }

func (scanner *runtimeScanner) Scan(_ context.Context, input ScanInput) error {
	if _, err := io.ReadAll(input.Body); err != nil {
		return err
	}
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	scanner.n++
	return scanner.err
}

func (scanner *runtimeScanner) setError(err error) {
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	scanner.err = err
}

func (scanner *runtimeScanner) calls() int {
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	return scanner.n
}

type runtimeRevocationFixture struct {
	pool        *pgxpool.Pool
	blockerPool *pgxpool.Pool
	requestApp  string
	mutationApp string
	handler     http.Handler
	token       string
	actor       Actor
	identities  seededIdentities
	asset       Asset
	store       *runtimeContentStore
	identity    *identity.Store
	rbac        *rbacmanager.Service
	rbacActor   rbacmanager.Actor
	grantID     uuid.UUID
	sessionHash []byte
}

type runtimeDomainFactCounts struct {
	errorAssets            int64
	errorAssetScans        int64
	errorRules             int64
	errorRuleRevisions     int64
	errorPublications      int64
	errorWrites            int64
	errorAudits            int64
	challengePolicies      int64
	challengeRuleRevisions int64
	challengeWrites        int64
	challengeAudits        int64
}

type runtimeResponseResult struct {
	response *httptest.ResponseRecorder
	err      error
}

type runtimeAuthorizationBarrier struct {
	inner       runtimeTxAuthorizer
	total       int
	reached     chan struct{}
	release     chan struct{}
	mu          sync.Mutex
	arrivals    int
	reachedOnce sync.Once
	releaseOnce sync.Once
}

func newRuntimeAuthorizationBarrier(total int, inner runtimeTxAuthorizer) *runtimeAuthorizationBarrier {
	return &runtimeAuthorizationBarrier{
		inner: inner, total: total, reached: make(chan struct{}), release: make(chan struct{}),
	}
}

func (barrier *runtimeAuthorizationBarrier) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	permission string,
) error {
	return barrier.AuthorizeTarget(ctx, tx, actor, actor.ScopeID, permission)
}

func (barrier *runtimeAuthorizationBarrier) AuthorizeTarget(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) error {
	barrier.mu.Lock()
	barrier.arrivals++
	if barrier.arrivals == barrier.total {
		barrier.reachedOnce.Do(func() { close(barrier.reached) })
	}
	barrier.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-barrier.release:
		return barrier.inner.AuthorizeTarget(ctx, tx, actor, targetScopeID, permission)
	}
}

func (barrier *runtimeAuthorizationBarrier) releaseRequests() {
	barrier.releaseOnce.Do(func() { close(barrier.release) })
}

func TestRuntimeHandlerFormalRevocationCommitOrder(t *testing.T) {
	for _, revocation := range []struct {
		name       string
		wantStatus int
		wantCode   string
	}{
		{name: "session", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		{name: "role_permission", wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
	} {
		for _, order := range []string{"business_first", "revocation_first"} {
			for _, replay := range []bool{false, true} {
				mode := "fresh"
				if replay {
					mode = "completed_replay"
				}
				t.Run(revocation.name+"/"+order+"/"+mode, func(t *testing.T) {
					scenarioCtx, cancelScenario := context.WithTimeout(t.Context(), 30*time.Second)
					defer cancelScenario()
					fixture := newRuntimeRevocationFixture(t)
					key := "runtime-" + revocation.name + "-" + order + "-" + mode
					if replay {
						created, err := fixture.createRule(scenarioCtx, key)
						if err != nil {
							t.Fatal(err)
						}
						assertRuntimeStatus(t, created, http.StatusCreated)
						if result := decodeSmokeBody[WriteResult[Rule]](t, created); result.Replayed {
							t.Fatal("initial write unexpectedly reported an idempotent replay")
						}
					}

					switch order {
					case "business_first":
						runRuntimeBusinessFirstRevocation(t, scenarioCtx, cancelScenario, fixture,
							revocation.name, key, replay, revocation.wantStatus, revocation.wantCode)
					case "revocation_first":
						runRuntimeRevocationFirst(t, scenarioCtx, cancelScenario, fixture,
							revocation.name, key, revocation.wantStatus, revocation.wantCode)
					default:
						t.Fatalf("unknown commit order %q", order)
					}
				})
			}
		}
	}
}

func newRuntimeRevocationFixture(t *testing.T) *runtimeRevocationFixture {
	t.Helper()
	database := openErrorPageDatabase(t)
	identities := seedErrorPageIdentities(t, database.pool)
	requestPool, requestApp := newRuntimeNamedPool(t, database.pool, "errorpage_runtime_request_", 2)
	mutationPool, mutationApp := newRuntimeNamedPool(t, database.pool, "errorpage_runtime_mutation_", 1)
	blockerPool, _ := newRuntimeNamedPool(t, database.pool, "errorpage_runtime_blocker_", 1)
	store := newRuntimeContentStore()
	limits := staticLimits{quota: AssetQuota{
		MaxAssetBytes: MaxEdgeResourceBytes, MaxAssets: 1000, MaxTotalBytes: 64 << 20,
	}}
	setup, err := NewServiceWithDependencies(database.pool, store, &runtimeScanner{}, limits,
		audit.New(database.pool), time.Now, testTxAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	asset := readyAsset(t, setup, identities.tenantOwner, identities.tenantScope,
		"runtime-revocation-asset", []byte("runtime revocation body"), "text/plain")

	now := storeTime(time.Now())
	rbac, err := rbacmanager.NewServiceWithDependencies(
		mutationPool, audit.New(mutationPool), reviewStepUp{now: now}, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	rbacActor := rbacmanager.Actor{
		UserID: identities.tenantOwner.UserID, ScopeID: identities.tenantScope,
		SessionID: identities.tenantOwner.Credential.ID, ScopeKind: "tenant",
		IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	role, err := rbac.CreateRole(t.Context(), rbacActor, rbacmanager.CreateRoleRequest{
		Name: "error_page_runtime_revocation", Permissions: []string{permissionManage},
		Mutation: reviewRBACMutation("runtime-revocation-role-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := rbac.AssignRole(t.Context(), rbacActor, rbacmanager.AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision,
		SubjectUserID: identities.tenantViewer.UserID,
		Mutation:      reviewRBACMutation("runtime-revocation-role-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := identity.NewTokenManager(strings.Repeat("runtime-revocation-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(requestPool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x71}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	iam, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true}, RuntimeDependencies{
		Pool: requestPool, Identity: identityService,
		APIKeys: apikey.NewService(requestPool, bytes.Repeat([]byte{0x71}, 32), time.Now), IAM: iam,
		ContentStore: store, Scanner: &runtimeScanner{}, Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	token := mintRuntimeToken(t, tokens, identities.tenantViewer)
	var sessionHash []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT refresh_token_hash FROM auth_sessions WHERE id=$1`,
		identities.tenantViewer.Credential.ID).Scan(&sessionHash); err != nil {
		t.Fatal(err)
	}
	return &runtimeRevocationFixture{
		pool: database.pool, blockerPool: blockerPool,
		requestApp: requestApp, mutationApp: mutationApp, handler: handler, token: token,
		actor: identities.tenantViewer, identities: identities, asset: asset, store: store,
		identity: identity.NewStore(mutationPool), rbac: rbac, rbacActor: rbacActor,
		grantID: grant.ID, sessionHash: append([]byte(nil), sessionHash...),
	}
}

func newRuntimeNamedPool(
	t *testing.T,
	source *pgxpool.Pool,
	prefix string,
	maxConns int32,
) (*pgxpool.Pool, string) {
	t.Helper()
	applicationName := prefix + strings.ReplaceAll(uuid.NewString(), "-", "")
	config := source.Config().Copy()
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.MaxConns = maxConns
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, applicationName
}

func (fixture *runtimeRevocationFixture) createRule(
	ctx context.Context,
	key string,
) (*httptest.ResponseRecorder, error) {
	return serveRuntimeRequestWithContext(ctx, fixture.handler, http.MethodPost, apiPrefix+"/rules", createRuleBody{
		Target: RuleTarget{Kind: ScopeSite, ScopeID: fixture.identities.tenantScope,
			SiteID: &fixture.identities.siteID},
		Fields: RuleFields{
			Category: CategoryOriginResponse, Match: StatusSelector{Kind: MatchExact, From: 598},
			AssetID: fixture.asset.ID, Enabled: true,
		},
	}, "Bearer "+fixture.token, key)
}

func (fixture *runtimeRevocationFixture) revoke(ctx context.Context, revocation, key string) error {
	switch revocation {
	case "session":
		return fixture.identity.RevokeSessionFamily(ctx, fixture.sessionHash, key+"-session-revoke")
	case "role_permission":
		_, err := fixture.rbac.RevokeGrant(ctx, fixture.rbacActor, rbacmanager.RevokeGrantRequest{
			GrantID: fixture.grantID, Mutation: reviewRBACMutation(key + "-grant-revoke"),
		})
		return err
	default:
		return errors.New("unknown runtime revocation")
	}
}

func runRuntimeRevocationFirst(
	t *testing.T,
	ctx context.Context,
	cancel context.CancelFunc,
	fixture *runtimeRevocationFixture,
	revocation, key string,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	beforeFacts := readRuntimeDomainFacts(t, fixture.pool)
	beforeStore := fixture.store.snapshot()
	blocker, err := beginRuntimeRevocationBlocker(ctx, fixture, revocation)
	if err != nil {
		t.Fatal(err)
	}
	blockerReleased := false
	requestStart := make(chan struct{})
	revocationStart := make(chan struct{})
	responses := startRuntimeRuleWorker(ctx, requestStart, fixture, key)
	revoked := startRuntimeRevocationWorker(ctx, revocationStart, fixture, revocation, key)
	responseReceived := false
	revocationReceived := false
	defer cleanupRuntimeRevocationWorkers(t, ctx, cancel, blocker, &blockerReleased,
		responses, &responseReceived, revoked, &revocationReceived)

	close(revocationStart)
	if err := waitForRuntimeIAMLock(ctx, fixture.pool, fixture.mutationApp, "ExclusiveLock", true); err != nil {
		t.Fatal(err)
	}
	close(requestStart)
	if err := waitForRuntimeIAMLock(ctx, fixture.pool, fixture.requestApp, "ShareLock", false); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	blockerReleased = true
	revocationErr, err := receiveRuntimeError(ctx, cancel, revoked)
	if err != nil {
		t.Fatal(err)
	}
	revocationReceived = true
	responseResult, err := receiveRuntimeResponse(ctx, cancel, responses)
	if err != nil {
		t.Fatal(err)
	}
	responseReceived = true
	if revocationErr != nil {
		t.Fatal(revocationErr)
	}
	if responseResult.err != nil {
		t.Fatal(responseResult.err)
	}
	assertRuntimeRevocationState(t, fixture, revocation)
	assertRuntimeRevocationDenied(t, responseResult.response, wantStatus, wantCode)
	assertRuntimeDomainFacts(t, fixture.pool, beforeFacts)
	if afterStore := fixture.store.snapshot(); afterStore != beforeStore {
		t.Fatalf("revocation-first object facts changed: before=%+v after=%+v", beforeStore, afterStore)
	}
}

func runRuntimeBusinessFirstRevocation(
	t *testing.T,
	ctx context.Context,
	cancel context.CancelFunc,
	fixture *runtimeRevocationFixture,
	revocation, key string,
	replay bool,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	holder, err := beginRuntimeBusinessBlocker(ctx, fixture)
	if err != nil {
		t.Fatal(err)
	}
	holderReleased := false
	requestStart := make(chan struct{})
	revocationStart := make(chan struct{})
	responses := startRuntimeRuleWorker(ctx, requestStart, fixture, key)
	revoked := startRuntimeRevocationWorker(ctx, revocationStart, fixture, revocation, key)
	responseReceived := false
	revocationReceived := false
	defer cleanupRuntimeRevocationWorkers(t, ctx, cancel, holder, &holderReleased,
		responses, &responseReceived, revoked, &revocationReceived)

	close(requestStart)
	if err := waitForRuntimeBusinessWaiter(ctx, fixture.pool, fixture.requestApp, "sites"); err != nil {
		t.Fatal(err)
	}
	close(revocationStart)
	if err := waitForRuntimeIAMLock(ctx, fixture.pool, fixture.mutationApp, "ExclusiveLock", false); err != nil {
		t.Fatal(err)
	}
	if err := holder.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	holderReleased = true
	responseResult, err := receiveRuntimeResponse(ctx, cancel, responses)
	if err != nil {
		t.Fatal(err)
	}
	responseReceived = true
	revocationErr, err := receiveRuntimeError(ctx, cancel, revoked)
	if err != nil {
		t.Fatal(err)
	}
	revocationReceived = true
	if responseResult.err != nil {
		t.Fatal(responseResult.err)
	}
	if revocationErr != nil {
		t.Fatal(revocationErr)
	}
	succeeded := responseResult.response
	assertRuntimeStatus(t, succeeded, http.StatusCreated)
	if result := decodeSmokeBody[WriteResult[Rule]](t, succeeded); result.Replayed != replay {
		t.Fatalf("business-first replayed=%t want=%t", result.Replayed, replay)
	}
	assertRuntimeRevocationState(t, fixture, revocation)
	afterSuccess := readRuntimeDomainFacts(t, fixture.pool)
	afterStore := fixture.store.snapshot()
	denied, err := fixture.createRule(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	assertRuntimeRevocationDenied(t, denied, wantStatus, wantCode)
	assertRuntimeDomainFacts(t, fixture.pool, afterSuccess)
	if finalStore := fixture.store.snapshot(); finalStore != afterStore {
		t.Fatalf("post-revocation object facts changed: before=%+v after=%+v", afterStore, finalStore)
	}
}

func beginRuntimeRevocationBlocker(
	ctx context.Context,
	fixture *runtimeRevocationFixture,
	revocation string,
) (pgx.Tx, error) {
	blocker, err := fixture.blockerPool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	var locked uuid.UUID
	switch revocation {
	case "session":
		err = blocker.QueryRow(ctx, `SELECT id FROM auth_sessions WHERE id=$1 FOR UPDATE`,
			fixture.actor.Credential.ID).Scan(&locked)
	case "role_permission":
		err = blocker.QueryRow(ctx, `SELECT id FROM custom_role_grants WHERE id=$1 FOR UPDATE`,
			fixture.grantID).Scan(&locked)
	default:
		err = errors.New("unknown runtime revocation blocker")
	}
	if err != nil {
		_ = rollbackRuntimeBlocker(ctx, blocker)
		return nil, err
	}
	return blocker, nil
}

func beginRuntimeBusinessBlocker(ctx context.Context, fixture *runtimeRevocationFixture) (pgx.Tx, error) {
	blocker, err := fixture.blockerPool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := blocker.Exec(ctx, "LOCK TABLE sites IN ACCESS EXCLUSIVE MODE"); err != nil {
		_ = rollbackRuntimeBlocker(ctx, blocker)
		return nil, err
	}
	return blocker, nil
}

func waitForRuntimeBusinessWaiter(
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName, relation string,
) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM pg_catalog.pg_stat_activity activity
			JOIN pg_catalog.pg_locks shared ON shared.pid=activity.pid
			JOIN pg_catalog.pg_locks business ON business.pid=activity.pid
			WHERE activity.application_name=$1
			  AND shared.locktype='advisory' AND shared.classid=1229016321::oid
			  AND shared.objid=1::oid AND shared.objsubid=2
			  AND shared.mode='ShareLock' AND shared.granted
			  AND business.relation=pg_catalog.to_regclass($2) AND NOT business.granted)`,
			applicationName, relation).Scan(&waiting)
		if err != nil {
			return err
		}
		if waiting {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitForRuntimeIAMLock(
	ctx context.Context,
	pool *pgxpool.Pool,
	applicationName, mode string,
	granted bool,
) error {
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var found bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1
			FROM pg_catalog.pg_locks lock
			JOIN pg_catalog.pg_stat_activity activity ON activity.pid=lock.pid
			WHERE activity.application_name=$1
			  AND lock.locktype='advisory' AND lock.classid=1229016321::oid
			  AND lock.objid=1::oid AND lock.objsubid=2
			  AND lock.mode=$2 AND lock.granted=$3)`, applicationName, mode, granted).Scan(&found)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func startRuntimeRuleWorker(
	ctx context.Context,
	start <-chan struct{},
	fixture *runtimeRevocationFixture,
	key string,
) <-chan runtimeResponseResult {
	results := make(chan runtimeResponseResult, 1)
	go func() {
		select {
		case <-ctx.Done():
			results <- runtimeResponseResult{err: ctx.Err()}
		case <-start:
			response, err := fixture.createRule(ctx, key)
			results <- runtimeResponseResult{response: response, err: err}
		}
	}()
	return results
}

func startRuntimeRevocationWorker(
	ctx context.Context,
	start <-chan struct{},
	fixture *runtimeRevocationFixture,
	revocation, key string,
) <-chan error {
	results := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			results <- ctx.Err()
		case <-start:
			results <- fixture.revoke(ctx, revocation, key)
		}
	}()
	return results
}

func receiveRuntimeResponse(
	ctx context.Context,
	cancel context.CancelFunc,
	responses <-chan runtimeResponseResult,
) (runtimeResponseResult, error) {
	select {
	case response := <-responses:
		return response, nil
	case <-ctx.Done():
		cancel()
		return runtimeResponseResult{}, ctx.Err()
	}
}

func receiveRuntimeError(
	ctx context.Context,
	cancel context.CancelFunc,
	results <-chan error,
) (error, error) {
	select {
	case err := <-results:
		return err, nil
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	}
}

func cleanupRuntimeRevocationWorkers(
	t *testing.T,
	ctx context.Context,
	cancel context.CancelFunc,
	blocker pgx.Tx,
	blockerReleased *bool,
	responses <-chan runtimeResponseResult,
	responseReceived *bool,
	revocations <-chan error,
	revocationReceived *bool,
) {
	t.Helper()
	cancel()
	if !*blockerReleased {
		if err := rollbackRuntimeBlocker(ctx, blocker); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("release runtime blocker: %v", err)
		}
		*blockerReleased = true
	}

	drainCtx, drainCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer drainCancel()
	if !*responseReceived {
		select {
		case <-responses:
			*responseReceived = true
		case <-drainCtx.Done():
			t.Errorf("runtime response worker did not exit: %v", drainCtx.Err())
		}
	}
	if !*revocationReceived {
		select {
		case <-revocations:
			*revocationReceived = true
		case <-drainCtx.Done():
			t.Errorf("runtime revocation worker did not exit: %v", drainCtx.Err())
		}
	}
}

func rollbackRuntimeBlocker(ctx context.Context, blocker pgx.Tx) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return blocker.Rollback(rollbackCtx)
}

func assertRuntimeRevocationDenied(
	t *testing.T,
	response *httptest.ResponseRecorder,
	wantStatus int,
	wantCode string,
) {
	t.Helper()
	assertRuntimeStatus(t, response, wantStatus)
	if !strings.Contains(response.Body.String(), `"code":"`+wantCode+`"`) {
		t.Fatalf("runtime denial code=%q status=%d body=%s", wantCode, response.Code, response.Body)
	}
	for _, leaked := range []string{"SQLSTATE", "40001", "40P01", "55P03"} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("runtime denial leaked %q: %s", leaked, response.Body)
		}
	}
}

func assertRuntimeRevocationState(t *testing.T, fixture *runtimeRevocationFixture, revocation string) {
	t.Helper()
	var revoked bool
	switch revocation {
	case "session":
		if err := fixture.pool.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL
			FROM auth_sessions WHERE id=$1`, fixture.actor.Credential.ID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
	case "role_permission":
		if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM custom_role_grant_revocations WHERE grant_id=$1)
			AND NOT EXISTS(
				SELECT 1 FROM custom_role_grants grant_row
				JOIN role_assignments assignment
				  ON assignment.scope_id=grant_row.tenant_scope_id
				 AND assignment.user_id=grant_row.subject_user_id
				 AND assignment.role_id=grant_row.role_id
				WHERE grant_row.id=$1)`, fixture.grantID).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown runtime revocation %q", revocation)
	}
	if !revoked {
		t.Fatalf("formal %s revocation did not commit", revocation)
	}
}

func readRuntimeDomainFacts(t *testing.T, pool *pgxpool.Pool) runtimeDomainFactCounts {
	t.Helper()
	var facts runtimeDomainFactCounts
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM error_page_assets),
		(SELECT count(*) FROM error_page_asset_scan_facts),
		(SELECT count(*) FROM error_page_rules),
		(SELECT count(*) FROM error_page_rule_revisions),
		(SELECT count(*) FROM error_page_publications),
		(SELECT count(*) FROM error_page_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'error_page.%'),
		(SELECT count(*) FROM challenge_policies),
		(SELECT count(*) FROM challenge_policy_revisions),
		(SELECT count(*) FROM challenge_policy_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'challenge_policy.%')`).Scan(
		&facts.errorAssets, &facts.errorAssetScans, &facts.errorRules, &facts.errorRuleRevisions,
		&facts.errorPublications, &facts.errorWrites, &facts.errorAudits, &facts.challengePolicies,
		&facts.challengeRuleRevisions, &facts.challengeWrites, &facts.challengeAudits,
	); err != nil {
		t.Fatal(err)
	}
	return facts
}

func assertRuntimeDomainFacts(t *testing.T, pool *pgxpool.Pool, before runtimeDomainFactCounts) {
	t.Helper()
	if after := readRuntimeDomainFacts(t, pool); after != before {
		t.Fatalf("runtime domain facts changed: before=%+v after=%+v", before, after)
	}
}
