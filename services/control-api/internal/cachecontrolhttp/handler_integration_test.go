//go:build integration

package cachecontrolhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCacheControlHTTPPostgresContract(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	store, err := cachecontrol.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, reader, bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(service, fixture.authenticate)
	if err != nil {
		t.Fatal(err)
	}

	policyBody := map[string]any{"expected_revision": int64(0), "document": integrationPolicyV2(60, 30)}
	response := serve(t, handler, http.MethodPost, "/v1/cache-policies/"+fixture.siteA.String(), policyBody, "tenant-a", "policy-create")
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("publish policy: status=%d body=%s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-policies/"+fixture.siteA.String(), policyBody, "tenant-a", "policy-create")
	if response.Code != http.StatusCreated || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("policy replay: status=%d body=%s", response.Code, response.Body.String())
	}
	changedPolicy := map[string]any{"expected_revision": int64(0), "document": integrationPolicyV2(61, 30)}
	response = serve(t, handler, http.MethodPost, "/v1/cache-policies/"+fixture.siteA.String(), changedPolicy, "tenant-a", "policy-create")
	assertAPIError(t, response, http.StatusConflict, "idempotency_conflict")
	response = serve(t, handler, http.MethodPost, "/v1/cache-policies/"+fixture.siteA.String(), changedPolicy, "tenant-a", "policy-stale")
	assertAPIError(t, response, http.StatusPreconditionFailed, "revision_conflict")
	secondPolicy := map[string]any{"expected_revision": int64(1), "document": integrationPolicy(120)}
	response = serve(t, handler, http.MethodPost, "/v1/cache-policies/"+fixture.siteA.String(), secondPolicy, "tenant-a", "policy-second")
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("second policy: status=%d body=%s", response.Code, response.Body.String())
	}

	response = serve(t, handler, http.MethodGet, "/v1/cache-policies/"+fixture.siteA.String()+"/revisions?limit=1", nil, "tenant-a", "")
	firstPolicyPage := decodePolicyPage(t, response)
	if len(firstPolicyPage.Items) != 1 || firstPolicyPage.Items[0].Revision != 2 || firstPolicyPage.NextCursor == "" {
		t.Fatalf("first policy page=%+v", firstPolicyPage)
	}
	// A schema v1 document goes on the wire without schema_version (only v2
	// carries it, openapi const 2), so the client reads it back as 0.
	if version := firstPolicyPage.Items[0].Document.SchemaVersion; version != 0 {
		t.Fatalf("newest legacy policy schema=%d, want v1 (schema_version omitted)", version)
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-policies/"+fixture.siteA.String()+"/revisions?limit=1&cursor="+firstPolicyPage.NextCursor, nil, "tenant-a", "")
	secondPolicyPage := decodePolicyPage(t, response)
	if len(secondPolicyPage.Items) != 1 || secondPolicyPage.Items[0].Revision != 1 || secondPolicyPage.NextCursor != "" {
		t.Fatalf("second policy page=%+v", secondPolicyPage)
	}
	if secondPolicyPage.Items[0].Document.SchemaVersion != cachecontrol.PolicySchemaV2 ||
		secondPolicyPage.Items[0].Document.Rules[0].Action != cachecontrol.RuleActionCache ||
		secondPolicyPage.Items[0].Document.Rules[0].BrowserTTLSeconds != 30 {
		t.Fatalf("V2 policy history lost schema/action/browser TTL: %+v", secondPolicyPage.Items[0].Document)
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-policies/"+fixture.siteA.String(), nil, "tenant-b", "")
	assertAPIError(t, response, http.StatusNotFound, "not_found")
	response = serve(t, handler, http.MethodGet, "/v1/admin/cache-policies/"+fixture.siteA.String(), nil, "platform", "")
	assertAPIError(t, response, http.StatusBadRequest, "invalid_request")
	response = serve(t, handler, http.MethodGet, "/v1/admin/cache-policies/"+fixture.siteA.String()+"?scope_id="+fixture.scopeA.String(), nil, "platform", "")
	assertAPIError(t, response, http.StatusNotFound, "not_found")
	response = serve(t, handler, http.MethodGet, "/v1/admin/cache-policies/"+fixture.siteA.String()+"?scope_id="+fixture.scopeB.String(), nil, "platform", "")
	assertAPIError(t, response, http.StatusNotFound, "not_found")

	querySecret := "query-signature-must-remain-private"
	operationBody := integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/assets/app.js?sig="+querySecret, 1)
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", operationBody, "tenant-a", "operation-main")
	if response.Code != http.StatusAccepted {
		t.Fatalf("create operation: status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), querySecret) || strings.Contains(response.Body.String(), "operation-main") ||
		!strings.Contains(response.Body.String(), "query=redacted") {
		t.Fatalf("operation response leaked sensitive values: %s", response.Body.String())
	}
	mainOperation := decodeOperation(t, response)
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", operationBody, "tenant-a", "operation-main")
	if response.Code != http.StatusAccepted || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("operation replay: status=%d body=%s", response.Code, response.Body.String())
	}
	conflictingBody := integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/other", 1)
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", conflictingBody, "tenant-a", "operation-main")
	assertAPIError(t, response, http.StatusConflict, "idempotency_conflict")
	crossNodeBody := integrationOperationBody(fixture.siteA, fixture.nodeB, "http://a.cache.example/cross", 0)
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", crossNodeBody, "tenant-a", "operation-cross-node")
	// fix-cacheflow2 P2-11: a named node that does not carry the site is target_node_unavailable.
	assertAPIError(t, response, http.StatusConflict, "target_node_unavailable")

	queuedIDs := []uuid.UUID{mainOperation.ID}
	for index := 0; index < 2; index++ {
		body := integrationOperationBody(fixture.siteA, fixture.nodeA, fmt.Sprintf("http://a.cache.example/page-%d", index), 0)
		response = serve(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant-a", fmt.Sprintf("operation-page-%d", index))
		if response.Code != http.StatusAccepted {
			t.Fatalf("create paged operation %d: %d %s", index, response.Code, response.Body.String())
		}
		queuedIDs = append(queuedIDs, decodeOperation(t, response).ID)
	}
	listPath := "/v1/cache-operations?limit=1&state=queued&site_id=" + fixture.siteA.String()
	response = serve(t, handler, http.MethodGet, listPath, nil, "tenant-a", "")
	firstOperationPage := decodeOperationPage(t, response)
	if len(firstOperationPage.Items) != 1 || firstOperationPage.NextCursor == "" {
		t.Fatalf("first operation page=%+v", firstOperationPage)
	}
	newAfterSnapshot := integrationOperationBody(fixture.siteA, fixture.nodeA, "http://a.cache.example/after-snapshot", 0)
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations", newAfterSnapshot, "tenant-a", "operation-after-snapshot")
	if response.Code != http.StatusAccepted {
		t.Fatalf("after-snapshot create: %d %s", response.Code, response.Body.String())
	}
	newOperationID := decodeOperation(t, response).ID
	response = serve(t, handler, http.MethodGet, listPath+"&cursor="+firstOperationPage.NextCursor, nil, "tenant-a", "")
	secondOperationPage := decodeOperationPage(t, response)
	if len(secondOperationPage.Items) != 1 || secondOperationPage.Items[0].ID == newOperationID {
		t.Fatalf("snapshot page included new operation: %+v", secondOperationPage)
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?limit=1&state=failed&site_id="+fixture.siteA.String()+"&cursor="+firstOperationPage.NextCursor, nil, "tenant-a", "")
	assertAPIError(t, response, http.StatusBadRequest, "invalid_request")
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations/"+mainOperation.ID.String(), nil, "tenant-b", "")
	assertAPIError(t, response, http.StatusNotFound, "not_found")
	response = serve(t, handler, http.MethodGet, "/v1/admin/cache-operations?scope_id="+fixture.scopeA.String()+"&site_id="+fixture.siteA.String(), nil, "platform", "")
	if response.Code != http.StatusOK {
		t.Fatalf("platform operation list: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?site_id="+fixture.siteB.String(), nil, "tenant-a", "")
	foreignSitePage := response.Body.String()
	// tp-b4b: the list carries per-state counts; a foreign site reads as empty with all-zero counts.
	if response.Code != http.StatusOK || foreignSitePage != `{"items":[],"state_counts":{"cancelled":0,"failed":0,"partial_failed":0,"queued":0,"running":0,"succeeded":0}}`+"\n" {
		t.Fatalf("foreign site filter: %d %s", response.Code, foreignSitePage)
	}
	response = serve(t, handler, http.MethodGet, "/v1/cache-operations?site_id="+uuid.NewString(), nil, "tenant-a", "")
	if response.Code != http.StatusOK || response.Body.String() != foreignSitePage {
		t.Fatalf("unknown site filter differs: %d %s", response.Code, response.Body.String())
	}

	cancelID := queuedIDs[len(queuedIDs)-1]
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+cancelID.String()+"/cancel", map[string]any{}, "tenant-a", "cancel-main")
	if response.Code != http.StatusOK || decodeOperation(t, response).State != cachecontrol.StateCancelled {
		t.Fatalf("cancel operation: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+cancelID.String()+"/cancel", map[string]any{}, "tenant-a", "cancel-main")
	if response.Code != http.StatusOK || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("cancel replay: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+cancelID.String()+"/cancel", map[string]any{}, "tenant-a", "cancel-terminal")
	assertAPIError(t, response, http.StatusConflict, "invalid_operation_transition")

	failedResult, err := store.CreateOperation(t.Context(), cachecontrol.Actor{
		UserID: fixture.userA, ScopeID: fixture.scopeA, ActorScopeID: fixture.scopeA,
	}, cachecontrol.CreateOperationRequest{
		SiteID: fixture.siteA, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://a.cache.example/retry"}, NodeIDs: []uuid.UUID{fixture.nodeA}, MaxRetries: 1,
		IdempotencyKey: "retry-operation", RequestID: "retry-operation-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := store.Claim(t.Context(), cachecontrol.ClaimRequest{
		ScopeID: fixture.scopeA, WorkerID: "integration-worker", OnlineNodeIDs: []uuid.UUID{fixture.nodeA},
		Limit: 100, LeaseDuration: time.Minute, RequestID: "integration-claim",
	})
	if err != nil {
		t.Fatal(err)
	}
	var failedClaim cachecontrol.Claim
	for _, claim := range claims {
		if claim.OperationID == failedResult.Operation.ID {
			failedClaim = claim
			break
		}
	}
	if failedClaim.OperationID == uuid.Nil {
		t.Fatalf("failed operation was not claimed: %+v", claims)
	}
	results := make([]cachecontrol.TargetResult, len(failedClaim.Targets))
	for index, target := range failedClaim.Targets {
		results[index] = cachecontrol.TargetResult{TargetOrdinal: target.Ordinal, State: cachecontrol.ItemFailed, ErrorCode: "edge_failed"}
	}
	if _, err := store.Report(t.Context(), cachecontrol.ReportRequest{
		ScopeID: fixture.scopeA, OperationID: failedClaim.OperationID, NodeID: failedClaim.NodeID,
		WorkerID: "integration-worker", LeaseID: failedClaim.LeaseID, Attempt: failedClaim.Attempt,
		Sequence: 1, Results: results, RequestID: "integration-report",
	}); err != nil {
		t.Fatal(err)
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+failedResult.Operation.ID.String()+"/retry", map[string]any{}, "tenant-a", "retry-main")
	if response.Code != http.StatusOK || decodeOperation(t, response).State != cachecontrol.StateQueued {
		t.Fatalf("retry operation: %d %s", response.Code, response.Body.String())
	}
	response = serve(t, handler, http.MethodPost, "/v1/cache-operations/"+failedResult.Operation.ID.String()+"/retry", map[string]any{}, "tenant-a", "retry-main")
	if response.Code != http.StatusOK || response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("retry replay: %d %s", response.Code, response.Body.String())
	}

	closedConfig, err := pgxpool.ParseConfig(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	closedPool, err := pgxpool.NewWithConfig(t.Context(), closedConfig)
	if err != nil {
		t.Fatal(err)
	}
	closedReader, err := NewPostgresReader(closedPool)
	if err != nil {
		t.Fatal(err)
	}
	closedPool.Close()
	closedService, err := NewService(store, closedReader, bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	closedHandler, err := NewHandler(closedService, fixture.authenticate)
	if err != nil {
		t.Fatal(err)
	}
	response = serve(t, closedHandler, http.MethodGet, "/v1/cache-operations", nil, "tenant-a", "")
	assertAPIError(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestCacheControlHTTPPlatformWriteGapEvidenceRequiresTargetTenantMembership(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	platformUserID, platformRoleID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES($1,$2,'Unbound cache platform actor','test-hash','active')`,
		platformUserID, "cache-http-unbound-platform-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, fixture.platformScope, platformUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'Cache platform boundary evidence',true)`, platformRoleID,
		fixture.platformScope, "cache-http-unbound-platform-role-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'sites.read'),($1,'sites.manage')`, platformRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.platformScope, platformUserID, platformRoleID); err != nil {
		t.Fatal(err)
	}

	store, err := cachecontrol.NewStore(pool, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, reader, bytes.Repeat([]byte{0x6a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	permissions := []string{
		PermissionPoliciesRead, PermissionPoliciesManage,
		PermissionOperationsRead, PermissionOperationsManage,
	}
	handler, err := NewHandler(service, func(request *http.Request) (identity.Principal, error) {
		if request.Header.Get("Authorization") != "platform-unbound" {
			return identity.Principal{}, identity.ErrInvalidSession
		}
		return principal(platformUserID, fixture.platformScope, "platform", permissions...), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	scopeQuery := "?scope_id=" + fixture.scopeA.String()
	response := serve(t, handler, http.MethodPost,
		"/v1/admin/cache-policies/"+fixture.siteA.String()+scopeQuery,
		map[string]any{"expected_revision": int64(0), "document": integrationPolicy(60)},
		"platform-unbound", "platform-policy-gap-evidence")
	assertAPIError(t, response, http.StatusNotFound, "not_found")
	response = serve(t, handler, http.MethodPost, "/v1/admin/cache-operations"+scopeQuery,
		integrationOperationBody(fixture.siteA, fixture.nodeA,
			"http://a.cache.example/platform-gap-evidence", 0),
		"platform-unbound", "platform-operation-gap-evidence")
	assertAPIError(t, response, http.StatusNotFound, "not_found")

	var policies, operations int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$2),
		(SELECT count(*) FROM cache_operations WHERE scope_id=$1 AND actor_user_id=$3)`,
		fixture.scopeA, fixture.siteA, platformUserID).Scan(&policies, &operations); err != nil {
		t.Fatal(err)
	}
	if policies != 0 || operations != 0 {
		t.Fatalf("platform gap evidence created facts: policies=%d operations=%d", policies, operations)
	}
}

func TestOperationSnapshotUsesCommittedAuditWatermark(t *testing.T) {
	pool := openHTTPIntegrationDatabase(t)
	fixture := seedHTTPFixture(t, pool)
	var databaseTime time.Time
	if err := pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&databaseTime); err != nil {
		t.Fatal(err)
	}
	aheadStore, err := cachecontrol.NewStore(pool, func() time.Time { return databaseTime.Add(24 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	behindStore, err := cachecontrol.NewStore(pool, func() time.Time { return databaseTime.Add(-24 * time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	aheadID := createSnapshotOperation(t, aheadStore, fixture, "snapshot-ahead", "/ahead")
	behindID := createSnapshotOperation(t, behindStore, fixture, "snapshot-behind", "/behind")

	lockKey := auditAdvisoryLockKey(fixture.scopeA)
	lockConnection, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = lockConnection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
		}
		lockConnection.Release()
	}()
	if _, err := lockConnection.Exec(t.Context(), `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}

	clockCalled := make(chan struct{}, 1)
	earlyTime := databaseTime.Add(-48 * time.Hour)
	earlyStore, err := cachecontrol.NewStore(pool, func() time.Time {
		select {
		case clockCalled <- struct{}{}:
		default:
		}
		return earlyTime
	})
	if err != nil {
		t.Fatal(err)
	}
	createContext, cancelCreate := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancelCreate()
	type createResult struct {
		result cachecontrol.OperationWriteResult
		err    error
	}
	created := make(chan createResult, 1)
	go func() {
		result, err := earlyStore.CreateOperation(createContext, cachecontrol.Actor{
			UserID: fixture.userA, ScopeID: fixture.scopeA, ActorScopeID: fixture.scopeA,
		}, cachecontrol.CreateOperationRequest{
			SiteID: fixture.siteA, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
			Targets: []string{"http://a.cache.example/late-commit"}, NodeIDs: []uuid.UUID{fixture.nodeA},
			IdempotencyKey: "snapshot-late", RequestID: "snapshot-late-request",
		})
		created <- createResult{result: result, err: err}
	}()
	select {
	case <-clockCalled:
	case <-createContext.Done():
		t.Fatal("operation did not take its application timestamp")
	}
	waitForAdvisoryWait(t, pool, lockKey)

	reader, err := NewPostgresReader(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(aheadStore, reader, bytes.Repeat([]byte{0x6a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	actor := principal(fixture.userA, fixture.scopeA, "tenant", PermissionOperationsRead)
	page, err := service.Operations(t.Context(), actor, AudienceTenant, nil, OperationListInput{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != aheadID || page.NextCursor == "" {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	if _, err := lockConnection.Exec(t.Context(), `SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
		t.Fatal(err)
	}
	locked = false
	late := <-created
	if late.err != nil {
		t.Fatal(late.err)
	}

	seen := map[uuid.UUID]bool{page.Items[0].ID: true}
	for page.NextCursor != "" {
		page, err = service.Operations(t.Context(), actor, AudienceTenant, nil, OperationListInput{Limit: 1, Cursor: page.NextCursor})
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			seen[item.ID] = true
		}
	}
	if !seen[aheadID] || !seen[behindID] || seen[late.result.Operation.ID] {
		t.Fatalf("old snapshot membership=%v late=%s", seen, late.result.Operation.ID)
	}
	fresh, err := service.Operations(t.Context(), actor, AudienceTenant, nil, OperationListInput{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	freshSeen := map[uuid.UUID]bool{}
	for _, item := range fresh.Items {
		freshSeen[item.ID] = true
	}
	if !freshSeen[aheadID] || !freshSeen[behindID] || !freshSeen[late.result.Operation.ID] {
		t.Fatalf("fresh snapshot membership=%v", freshSeen)
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.scopeA).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	now := databaseTime.UTC()
	_, err = pool.Exec(t.Context(), `INSERT INTO cache_operations(
		id,scope_id,actor_scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
		request_id,actor_user_id,state,max_attempts,target_count,node_count,total_count,created_at,updated_at
	) VALUES($1,$2,$2,$3,$4,'purge','exact_url','snapshot-corrupt',$5,'snapshot-corrupt-request',
		$6,'queued',1,1,1,1,$7,$7)`, uuid.New(), fixture.scopeA, tenantID, fixture.siteA,
		bytes.Repeat([]byte{0x7b}, 32), fixture.userA, now)
	var pgError *pgconn.PgError
	if err == nil || !errors.As(err, &pgError) || pgError.Code != "P8004" ||
		!strings.Contains(pgError.Message, "cache operation actor scope integrity violation") {
		t.Fatalf("corrupt operation insert err=%v, want P8004 actor scope integrity violation", err)
	}
}

func createSnapshotOperation(t *testing.T, store *cachecontrol.Store, fixture httpFixture, key, path string) uuid.UUID {
	t.Helper()
	result, err := store.CreateOperation(t.Context(), cachecontrol.Actor{
		UserID: fixture.userA, ScopeID: fixture.scopeA, ActorScopeID: fixture.scopeA,
	}, cachecontrol.CreateOperationRequest{
		SiteID: fixture.siteA, Action: cachecontrol.ActionPurge, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://a.cache.example" + path}, NodeIDs: []uuid.UUID{fixture.nodeA},
		IdempotencyKey: key, RequestID: key + "-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Operation.ID
}

func auditAdvisoryLockKey(scopeID uuid.UUID) int64 {
	digest := sha256.Sum256(scopeID[:])
	return int64(binary.BigEndian.Uint64(digest[:8]))
}

func waitForAdvisoryWait(t *testing.T, pool *pgxpool.Pool, key int64) {
	t.Helper()
	unsigned := uint64(key)
	classID, objectID := int64(uint32(unsigned>>32)), int64(uint32(unsigned))
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE locktype='advisory' AND classid::bigint=$1 AND objid::bigint=$2 AND NOT granted
		)`, classID, objectID).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operation did not block on the audit stream lock")
}

type httpFixture struct {
	scopeA, scopeB, platformScope uuid.UUID
	userA, userB, platformUser    uuid.UUID
	siteA, siteB                  uuid.UUID
	nodeA, nodeB                  uuid.UUID
}

func (fixture httpFixture) authenticate(request *http.Request) (identity.Principal, error) {
	permissions := []string{PermissionPoliciesRead, PermissionPoliciesManage, PermissionOperationsRead, PermissionOperationsManage}
	switch request.Header.Get("Authorization") {
	case "tenant-a":
		return principal(fixture.userA, fixture.scopeA, "tenant", permissions...), nil
	case "tenant-b":
		return principal(fixture.userB, fixture.scopeB, "tenant", permissions...), nil
	case "platform":
		return principal(fixture.platformUser, fixture.platformScope, "platform", permissions...), nil
	default:
		return identity.Principal{}, identity.ErrInvalidSession
	}
}

func seedHTTPFixture(t *testing.T, pool *pgxpool.Pool) httpFixture {
	t.Helper()
	fixture := httpFixture{
		scopeA: uuid.New(), scopeB: uuid.New(), platformScope: uuid.New(), userA: uuid.New(),
		userB: uuid.New(), platformUser: uuid.New(), siteA: uuid.New(), siteB: uuid.New(),
		nodeA: uuid.New(), nodeB: uuid.New(),
	}
	ctx := t.Context()
	for _, tenant := range []struct {
		id, scope uuid.UUID
		name      string
	}{{uuid.New(), fixture.scopeA, "Cache HTTP A"}, {uuid.New(), fixture.scopeB, "Cache HTTP B"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name,status) VALUES($1,$2,'active')`, tenant.id, tenant.name); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, tenant.scope, tenant.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, fixture.platformScope); err != nil {
		t.Fatal(err)
	}
	for _, user := range []struct {
		id       uuid.UUID
		username string
	}{{fixture.userA, "cache-http-a"}, {fixture.userB, "cache-http-b"}, {fixture.platformUser, "cache-http-platform"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status)
			VALUES($1,$2,$2,'test-hash','active')`, user.id, user.username); err != nil {
			t.Fatal(err)
		}
	}
	for _, membership := range []struct{ scope, user uuid.UUID }{
		{fixture.scopeA, fixture.userA}, {fixture.scopeB, fixture.userB},
		{fixture.platformScope, fixture.platformUser}, {fixture.scopeA, fixture.platformUser},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, membership.scope, membership.user); err != nil {
			t.Fatal(err)
		}
	}
	for _, assignment := range []struct {
		scope uuid.UUID
		users []uuid.UUID
		name  string
	}{
		{fixture.scopeA, []uuid.UUID{fixture.userA, fixture.platformUser}, "cache-http-role-a"},
		{fixture.scopeB, []uuid.UUID{fixture.userB}, "cache-http-role-b"},
	} {
		roleID := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,$3,'Cache HTTP integration role',true)`, roleID, assignment.scope,
			assignment.name+"-"+uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'sites.read'),($1,'sites.manage')`, roleID); err != nil {
			t.Fatal(err)
		}
		for _, userID := range assignment.users {
			if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3)`, assignment.scope, userID, roleID); err != nil {
				t.Fatal(err)
			}
		}
	}
	seedHTTPSite(t, pool, fixture.siteA, fixture.scopeA, fixture.userA, "a.cache.example")
	seedHTTPSite(t, pool, fixture.siteB, fixture.scopeB, fixture.userB, "b.cache.example")
	for _, node := range []struct {
		id, scope, user uuid.UUID
		name            string
	}{{fixture.nodeA, fixture.scopeA, fixture.userA, "cache-node-a"}, {fixture.nodeB, fixture.scopeB, fixture.userB, "cache-node-b"}} {
		// display_id from the per-scope sequence, as node.Store allocates it.
		if _, err := pool.Exec(ctx, `WITH display AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,display.display_id,$2,$3,'active',$4 FROM display`, node.id, node.scope, node.name, node.user); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func seedHTTPSite(t *testing.T, pool *pgxpool.Pool, siteID, scopeID, userID uuid.UUID, domain string) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		// display_id from the per-scope sequence, as site.Store allocates it.
		if _, err := tx.Exec(t.Context(), `WITH display AS (
			INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,created_by_user_id,updated_by_user_id
		) SELECT $1,display.display_id,$2,$3,$4,$5,$6,$7,$8,true,true,'active',$3,$3 FROM display`,
			siteID, scopeID, userID, domain, []string{"80"}, []string{"443"},
			[]string{"192.0.2.10"}, []string{"192.0.2.10"}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.10',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func integrationPolicy(ttl int64) cachecontrol.PolicyDocument {
	return cachecontrol.PolicyDocument{
		Mode:      cachecontrol.PolicyOverride,
		Rules:     []cachecontrol.Rule{{Order: 1, Extensions: []string{".js"}, StatusCodes: []int{200}, TTLSeconds: ttl}},
		QueryMode: cachecontrol.QueryPreserve, QueryNames: []string{},
		VaryHeaders: []string{"accept-encoding"}, DiskQuotaBytes: 64 << 20,
	}
}

func integrationPolicyV2(ttl, browserTTL int64) cachecontrol.PolicyDocument {
	return cachecontrol.PolicyDocument{
		SchemaVersion: cachecontrol.PolicySchemaV2,
		Mode:          cachecontrol.PolicyOverride,
		Rules: []cachecontrol.Rule{{
			Order: 1, Extensions: []string{".js"}, StatusCodes: []int{200},
			Action: cachecontrol.RuleActionCache, TTLSeconds: ttl, BrowserTTLSeconds: browserTTL,
		}, {
			Order: 2, PathPrefix: "/private/", Action: cachecontrol.RuleActionNoCache,
		}},
		QueryMode: cachecontrol.QueryPreserve, QueryNames: []string{},
		VaryHeaders: []string{"accept-encoding"}, DiskQuotaBytes: 64 << 20,
	}
}

func integrationOperationBody(siteID, nodeID uuid.UUID, target string, maxRetries uint32) map[string]any {
	return map[string]any{
		"site_id": siteID.String(), "action": "purge", "target_type": "exact_url",
		"targets": []string{target}, "node_ids": []string{nodeID.String()}, "max_retries": maxRetries,
	}
}

func decodePolicyPage(t *testing.T, response interface {
	Result() *http.Response
}) PolicyPage {
	t.Helper()
	var page PolicyPage
	decodeRecorderJSON(t, response, http.StatusOK, &page)
	return page
}

func decodeOperationPage(t *testing.T, response interface {
	Result() *http.Response
}) OperationPage {
	t.Helper()
	var page OperationPage
	decodeRecorderJSON(t, response, http.StatusOK, &page)
	return page
}

func decodeOperation(t *testing.T, response interface {
	Result() *http.Response
}) OperationView {
	t.Helper()
	var operation OperationView
	decodeRecorderJSON(t, response, 0, &operation)
	return operation
}

func decodeRecorderJSON(t *testing.T, source interface {
	Result() *http.Response
}, expectedStatus int, destination any) {
	t.Helper()
	response := source.Result()
	defer response.Body.Close()
	if expectedStatus != 0 && response.StatusCode != expectedStatus {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		t.Fatal(err)
	}
}

func assertAPIError(t *testing.T, response interface {
	Result() *http.Response
}, status int, code string) {
	t.Helper()
	var envelope errorEnvelope
	decodeRecorderJSON(t, response, status, &envelope)
	if envelope.Error.Code != code {
		t.Fatalf("error code=%q want=%q", envelope.Error.Code, code)
	}
}

// openHTTPIntegrationDatabase opens a schema at the release head (a template
// clone when TEST_DATABASE_TEMPLATE is set): the cache handlers and stores
// under test read today's schema (cache policy definitions 143, site domain
// facts 148, tenant carriage 287, revocation LKG 077, ...), which the former
// replay through migration 80 plus hand-made table slices did not match.
func openHTTPIntegrationDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return databasetest.MigratedPool(t, nil)
}
