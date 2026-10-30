//go:build integration

package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var cacheTestNow = time.Date(2026, 7, 22, 16, 0, 0, 0, time.UTC)

func TestCacheControlMigrationRoundTrip(t *testing.T) {
	pool := openCacheTestDatabase(t, false)
	migrateCacheThrough34(t, pool)
	assertCacheMigration(t, pool, 34, true)
	applyCacheMigrationFile(t, pool, "034_cache_control.down.sql", 34, false)
	assertCacheMigrationBelow(t, pool, 34, false)
	applyCacheMigrationFile(t, pool, "034_cache_control.up.sql", 34, true)
	assertCacheMigration(t, pool, 34, true)
}

func TestCacheControlMigrationDownRejectsPersistedFacts(t *testing.T) {
	pool := openCacheTestDatabase(t, false)
	migrateCacheThrough34(t, pool)
	fixture := seedCacheFixture(t, pool, "down-facts", 1)
	operationID := uuid.New()

	script, err := fs.ReadFile(migrations.FS, "034_cache_control.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	ctx := context.Background()
	if _, err = tx.Exec(ctx, `
		ALTER TABLE cache_policy_heads DISABLE TRIGGER cache_policy_heads_integrity;
		ALTER TABLE cache_policy_revisions DISABLE TRIGGER cache_policy_revisions_integrity;
		ALTER TABLE cache_operations DISABLE TRIGGER cache_operations_integrity`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cache_policy_heads(
		site_id,scope_id,tenant_id,current_revision,created_at,updated_at
	) VALUES($1,$2,$3,1,$4,$4)`, fixture.siteID, fixture.actor.ScopeID,
		fixture.tenantID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cache_policy_revisions(
			site_id,scope_id,tenant_id,revision,mode,rules,query_mode,query_names,vary_headers,
			disk_quota_bytes,request_digest,created_by_user_id,request_id,created_at
		) VALUES($1,$2,$3,1,'override','[{"order":1}]','preserve',ARRAY[]::text[],ARRAY[]::text[],
			1048576,$5,$6,'down-policy-request',$4)`, fixture.siteID, fixture.actor.ScopeID,
		fixture.tenantID, cacheTestNow, make([]byte, 32), fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cache_operations(
			id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
			request_id,actor_user_id,state,max_attempts,target_count,node_count,total_count,
			created_at,updated_at
		) VALUES($1,$2,$3,$4,'purge','exact_url','down-operation',$5,
			'down-operation-request',$6,'queued',1,1,1,1,$7,$7)`, operationID,
		fixture.actor.ScopeID, fixture.tenantID, fixture.siteID, make([]byte, 32),
		fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `
		ALTER TABLE cache_operations ENABLE TRIGGER cache_operations_integrity;
		ALTER TABLE cache_policy_revisions ENABLE TRIGGER cache_policy_revisions_integrity;
		ALTER TABLE cache_policy_heads ENABLE TRIGGER cache_policy_heads_integrity`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SAVEPOINT cache_control_down_attempt`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(ctx, string(script))
	var pgError *pgconn.PgError
	if err == nil || !errors.As(err, &pgError) || pgError.Code != "P0001" ||
		!strings.Contains(err.Error(), "cache control facts exist") {
		t.Fatalf("non-empty cache control down error=%v, want P0001 fact guard", err)
	}
	if _, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT cache_control_down_attempt`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	assertCacheMigration(t, pool, 34, true)
	var policyCount, operationCount int
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM cache_policy_revisions WHERE site_id=$1),
		(SELECT count(*) FROM cache_operations WHERE id=$2)`,
		fixture.siteID, operationID).Scan(&policyCount, &operationCount); err != nil {
		t.Fatal(err)
	}
	if policyCount != 1 || operationCount != 1 {
		t.Fatalf("facts after rejected down: policies=%d operations=%d", policyCount, operationCount)
	}
}

func TestPolicyCASIsolationIdempotencyAndAuditRollback(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixtureA := seedCacheFixture(t, pool, "policy-a", 1)
	fixtureB := seedCacheFixture(t, pool, "policy-b", 1)
	document := validPolicyV2Document(60, 30)

	first, err := store.PublishPolicy(context.Background(), fixtureA.actor, PublishPolicyRequest{
		SiteID: fixtureA.siteID, ExpectedRevision: 0, Document: document,
		IdempotencyKey: "policy-create", RequestID: "policy-create-request",
	})
	if err != nil || first.Replayed || first.Policy.Revision != 1 || !first.Policy.CreatedAt.Equal(cacheTestNow) {
		t.Fatalf("first policy publish: result=%+v err=%v", first, err)
	}
	replay, err := store.PublishPolicy(context.Background(), fixtureA.actor, PublishPolicyRequest{
		SiteID: fixtureA.siteID, ExpectedRevision: 0, Document: document,
		IdempotencyKey: "policy-create", RequestID: "policy-replay-request",
	})
	if err != nil || !replay.Replayed || replay.Policy.Revision != 1 {
		t.Fatalf("policy replay: result=%+v err=%v", replay, err)
	}
	changed := validPolicyV2Document(61, 30)
	if _, err := store.PublishPolicy(context.Background(), fixtureA.actor, PublishPolicyRequest{
		SiteID: fixtureA.siteID, ExpectedRevision: 0, Document: changed,
		IdempotencyKey: "policy-create", RequestID: "policy-conflict-request",
	}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same key with different policy: %v", err)
	}

	start := make(chan struct{})
	type publishOutcome struct {
		result PolicyWriteResult
		err    error
	}
	outcomes := make(chan publishOutcome, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			result, err := store.PublishPolicy(context.Background(), fixtureA.actor, PublishPolicyRequest{
				SiteID: fixtureA.siteID, ExpectedRevision: 1, Document: validPolicyDocument(int64(120 + index)),
				IdempotencyKey: fmt.Sprintf("policy-race-%d", index),
				RequestID:      fmt.Sprintf("policy-race-request-%d", index),
			})
			outcomes <- publishOutcome{result, err}
		}()
	}
	close(start)
	var successes, conflicts int
	for range 2 {
		outcome := <-outcomes
		switch {
		case outcome.err == nil && outcome.result.Policy.Revision == 2:
			successes++
		case errors.Is(outcome.err, ErrRevisionConflict):
			conflicts++
		default:
			t.Fatalf("unexpected policy CAS outcome: result=%+v err=%v", outcome.result, outcome.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("policy CAS successes=%d conflicts=%d", successes, conflicts)
	}
	if _, err := store.GetPolicy(context.Background(), fixtureB.actor, fixtureA.siteID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant policy read: %v", err)
	}
	stored, err := store.GetPolicy(context.Background(), fixtureA.actor, fixtureA.siteID, 1)
	if err != nil || stored.Document.SchemaVersion != PolicySchemaV2 ||
		stored.Document.Rules[0].Action != RuleActionCache || stored.Document.Rules[0].BrowserTTLSeconds != 30 {
		t.Fatalf("stored V2 policy=%+v err=%v", stored, err)
	}

	rollbackStore := *store
	rollbackStore.auditor = failingAuditor{}
	if _, err := rollbackStore.PublishPolicy(context.Background(), fixtureA.actor, PublishPolicyRequest{
		SiteID: fixtureA.siteID, ExpectedRevision: 2, Document: validPolicyDocument(300),
		IdempotencyKey: "policy-audit-failure", RequestID: "policy-audit-failure-request",
	}); err == nil {
		t.Fatal("policy publish unexpectedly survived audit failure")
	}
	var revision int64
	if err := pool.QueryRow(context.Background(), `
		SELECT current_revision FROM cache_policy_heads WHERE site_id=$1`, fixtureA.siteID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if revision != 2 {
		t.Fatalf("policy revision=%d after audit rollback, want 2", revision)
	}
	var failedWriteCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM cache_policy_write_requests
		WHERE scope_id=$1 AND idempotency_key='policy-audit-failure'`, fixtureA.actor.ScopeID).Scan(&failedWriteCount); err != nil {
		t.Fatal(err)
	}
	if failedWriteCount != 0 {
		t.Fatalf("audit-failed policy write rows=%d, want 0", failedWriteCount)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE cache_policy_revisions SET disk_quota_bytes=disk_quota_bytes+1
		WHERE site_id=$1 AND revision=1`, fixtureA.siteID); err == nil {
		t.Fatal("immutable cache policy revision accepted direct update")
	}
}

func TestPolicyV2DisabledAndFollowOriginRoundTrip(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "policy-v2-empty-modes", 1)
	for index, document := range []PolicyDocument{
		{SchemaVersion: PolicySchemaV2, Mode: PolicyDisabled, QueryMode: QueryIgnore},
		{SchemaVersion: PolicySchemaV2, Mode: PolicyFollowOrigin, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes},
	} {
		revision := int64(index + 1)
		result, err := store.PublishPolicy(context.Background(), fixture.actor, PublishPolicyRequest{
			SiteID: fixture.siteID, ExpectedRevision: int64(index), Document: document,
			IdempotencyKey: fmt.Sprintf("policy-v2-empty-%d", revision),
			RequestID:      fmt.Sprintf("policy-v2-empty-request-%d", revision),
		})
		if err != nil || result.Policy.Document.SchemaVersion != PolicySchemaV2 ||
			result.Policy.Document.Mode != document.Mode || len(result.Policy.Document.Rules) != 0 {
			t.Fatalf("publish V2 %s=%+v err=%v", document.Mode, result, err)
		}
		stored, err := store.GetPolicy(context.Background(), fixture.actor, fixture.siteID, revision)
		if err != nil || stored.Document.SchemaVersion != PolicySchemaV2 || stored.Document.Mode != document.Mode {
			t.Fatalf("read V2 %s=%+v err=%v", document.Mode, stored, err)
		}
	}
}

func TestPolicyEntitlementDenialPrecedesIdempotencyAndPersistsOneAudit(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	unguardedStore := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "policy-entitlement", 1)
	request := PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-entitlement-existing", RequestID: "policy-entitlement-existing-request",
	}
	if _, err := unguardedStore.PublishPolicy(context.Background(), fixture.actor, request); err != nil {
		t.Fatal(err)
	}
	guardedStore, err := NewStoreWithEntitlement(
		pool, clock.Now, entitlementguard.NewGuard(pool, clock.Now, nil),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertConcurrentDenials := func(request PublishPolicyRequest) {
		t.Helper()
		start := make(chan struct{})
		outcomes := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				_, err := guardedStore.PublishPolicy(context.Background(), fixture.actor, request)
				outcomes <- err
			}()
		}
		close(start)
		for range 2 {
			if err := <-outcomes; !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("policy entitlement error=%v, want %v", err, ErrEntitlementDenied)
			}
		}
	}
	assertConcurrentDenials(request)
	fresh := request
	fresh.IdempotencyKey = "policy-entitlement-fresh"
	fresh.RequestID = "policy-entitlement-fresh-request"
	assertConcurrentDenials(fresh)

	var headRevision, revisionCount, writeCount, denialCount int
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT current_revision FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$2),
		(SELECT count(*) FROM cache_policy_revisions WHERE scope_id=$1 AND site_id=$2),
		(SELECT count(*) FROM cache_policy_write_requests WHERE scope_id=$1 AND site_id=$2),
		(SELECT count(*) FROM audit_events
		 WHERE scope_id=$1 AND actor_user_id=$3 AND action='entitlement.guard.reject'
		   AND resource_type='site' AND resource_id=$2::text AND result='denied'
		   AND request_id IN ($4,$5) AND payload->>'operation'='cache.policy.publish')`,
		fixture.actor.ScopeID, fixture.siteID, fixture.actor.UserID,
		request.RequestID, fresh.RequestID,
	).Scan(&headRevision, &revisionCount, &writeCount, &denialCount); err != nil {
		t.Fatal(err)
	}
	if headRevision != 1 || revisionCount != 1 || writeCount != 1 {
		t.Fatalf("policy facts after entitlement denial head/revisions/writes=%d/%d/%d, want 1/1/1",
			headRevision, revisionCount, writeCount)
	}
	if denialCount != 2 {
		t.Fatalf("durable entitlement denial audits=%d, want one per fixed request", denialCount)
	}
}

func TestPolicyEntitlementDenialAuditFailureReturnsBothErrors(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	fixture := seedCacheFixture(t, pool, "policy-entitlement-audit-failure", 1)
	injected := errors.New("injected entitlement denial audit failure")
	checker := &failingEntitlementDenialAuditor{auditor: audit.New(pool), failure: injected}
	store, err := NewStoreWithEntitlement(pool, func() time.Time { return cacheTestNow }, checker)
	if err != nil {
		t.Fatal(err)
	}
	request := PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-entitlement-audit-failure",
		RequestID:      "policy-entitlement-audit-failure-request",
	}
	if _, err := store.PublishPolicy(context.Background(), fixture.actor, request); !errors.Is(err, ErrEntitlementDenied) ||
		!errors.Is(err, injected) {
		t.Fatalf("policy entitlement audit failure=%v, want denial joined with injected failure", err)
	}
	var factCount, auditCount int
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM cache_policy_write_requests WHERE scope_id=$1 AND idempotency_key=$2) +
		(SELECT count(*) FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$3) +
		(SELECT count(*) FROM cache_policy_revisions WHERE scope_id=$1 AND site_id=$3),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND request_id=$4
		 AND action='entitlement.guard.reject')`,
		fixture.actor.ScopeID, request.IdempotencyKey, request.SiteID, request.RequestID,
	).Scan(&factCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	if factCount != 0 || auditCount != 0 || checker.callCount() != 2 {
		t.Fatalf("failed denial audit facts/audits/checks=%d/%d/%d, want 0/0/2",
			factCount, auditCount, checker.callCount())
	}
}

func TestOperationEntitlementDenialsPersistWithoutBusinessFacts(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	unguardedStore := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "operation-entitlement", 1)
	operation := createSimpleOperation(t, unguardedStore, fixture,
		"operation-entitlement-retryable", 1, fixture.nodeIDs)
	claim := claimForNodes(t, unguardedStore, fixture.actor.ScopeID, "operation-entitlement-worker",
		fixture.nodeIDs, 1, "operation-entitlement-claim")[0]
	reported, err := unguardedStore.Report(context.Background(), reportRequest(
		claim, "operation-entitlement-worker", 1, "operation-entitlement-report", []ItemState{ItemFailed},
	))
	if err != nil || reported.Operation.State != StateFailed {
		t.Fatalf("prepare retryable operation result=%+v err=%v", reported, err)
	}
	guardedStore, err := NewStoreWithEntitlement(
		pool, clock.Now, entitlementguard.NewGuard(pool, clock.Now, nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	createRequest := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/operation-entitlement-denied"},
		NodeIDs: fixture.nodeIDs, IdempotencyKey: "operation-entitlement-denied",
		RequestID: "operation-entitlement-denied-request",
	}
	retryRequest := RetryRequest{
		OperationID: operation.ID, IdempotencyKey: "operation-entitlement-retry-denied",
		RequestID: "operation-entitlement-retry-denied-request",
	}
	assertConcurrentDenials := func(operation func() error) {
		t.Helper()
		start := make(chan struct{})
		outcomes := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				outcomes <- operation()
			}()
		}
		close(start)
		for range 2 {
			if err := <-outcomes; !errors.Is(err, ErrEntitlementDenied) {
				t.Fatalf("operation entitlement error=%v, want %v", err, ErrEntitlementDenied)
			}
		}
	}
	assertConcurrentDenials(func() error {
		_, err := guardedStore.CreateOperation(context.Background(), fixture.actor, createRequest)
		return err
	})
	assertConcurrentDenials(func() error {
		_, err := guardedStore.Retry(context.Background(), fixture.actor, retryRequest)
		return err
	})

	var createFacts, retryFacts, businessAudits, createDenials, retryDenials int
	var state string
	if err := pool.QueryRow(context.Background(), `SELECT
		(SELECT count(*) FROM cache_operations WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM cache_operation_commands
		 WHERE scope_id=$1 AND operation_id=$3 AND idempotency_key=$4),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1
		 AND request_id IN ($5,$6) AND action IN ('cache.operation.create','cache.operation.retry')),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$7
		 AND action='entitlement.guard.reject' AND resource_type='site' AND resource_id=$8::text
		 AND request_id=$5 AND result='denied' AND payload->>'operation'='cache.operation.create'),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND actor_user_id=$7
		 AND action='entitlement.guard.reject' AND resource_type='site' AND resource_id=$8::text
		 AND request_id=$6 AND result='denied' AND payload->>'operation'='cache.operation.retry'),
		(SELECT state FROM cache_operations WHERE scope_id=$1 AND id=$3)`,
		fixture.actor.ScopeID, createRequest.IdempotencyKey, operation.ID, retryRequest.IdempotencyKey,
		createRequest.RequestID, retryRequest.RequestID, fixture.actor.UserID, fixture.siteID,
	).Scan(&createFacts, &retryFacts, &businessAudits, &createDenials, &retryDenials, &state); err != nil {
		t.Fatal(err)
	}
	if createFacts != 0 || retryFacts != 0 || businessAudits != 0 || state != string(StateFailed) {
		t.Fatalf("denied operation facts/commands/business-audits/state=%d/%d/%d/%s, want 0/0/0/%s",
			createFacts, retryFacts, businessAudits, state, StateFailed)
	}
	if createDenials != 1 || retryDenials != 1 {
		t.Fatalf("durable operation entitlement denial audits create/retry=%d/%d, want 1/1",
			createDenials, retryDenials)
	}
}

func TestPlatformActorCannotTargetTenantCacheScope(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "platform-boundary", 1)
	operation := createSimpleOperation(t, store, fixture, "platform-fk-operation", 0, fixture.nodeIDs)
	ctx := context.Background()
	platformScopeID, platformUserID := uuid.New(), uuid.New()

	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
		platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES($1,$2,'Cache platform actor','test-hash','active')`,
		platformUserID, "cache-platform-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, platformScopeID, platformUserID); err != nil {
		t.Fatal(err)
	}

	platformActorTargetingTenant := Actor{
		UserID: platformUserID, ScopeID: fixture.actor.ScopeID, ActorScopeID: platformScopeID,
	}
	if _, err := store.CreateOperation(ctx, platformActorTargetingTenant, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/platform-denied"}, NodeIDs: fixture.nodeIDs,
		IdempotencyKey: "platform-denied", RequestID: "platform-denied-request",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("platform actor targeting tenant cache scope err=%v, want permission denied", err)
	}

	for _, testCase := range []struct {
		name       string
		constraint string
		insert     func() error
	}{
		{
			name: "operation", constraint: "cache_operations_actor_membership_080_fkey",
			insert: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO cache_operations(
					id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
					request_id,actor_scope_id,actor_user_id,state,max_attempts,target_count,node_count,total_count,
					created_at,updated_at
				) VALUES($1,$2,$3,$4,'purge','exact_url',$5,$6,$7,$2,$8,'queued',1,1,1,1,$9,$9)`,
					uuid.New(), fixture.actor.ScopeID, fixture.tenantID, fixture.siteID,
					"platform-forged-operation", make([]byte, 32), "platform-forged-operation-request",
					platformUserID, cacheTestNow)
				return err
			},
		},
		{
			name: "policy write", constraint: "cache_policy_write_requests_actor_membership_080_fkey",
			insert: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO cache_policy_write_requests(
					id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
				) VALUES($1,$2,$2,$3,$4,$5,$6,$7)`, uuid.New(), fixture.actor.ScopeID,
					platformUserID, fixture.siteID, "platform-forged-policy", make([]byte, 32), cacheTestNow)
				return err
			},
		},
		{
			name: "operation command", constraint: "cache_operation_commands_actor_membership_080_fkey",
			insert: func() error {
				_, err := pool.Exec(ctx, `INSERT INTO cache_operation_commands(
					id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
				) VALUES($1,$2,$3,$3,'cancel',$4,$5,$6,$7)`, uuid.New(), operation.ID,
					fixture.actor.ScopeID, "platform-forged-command", make([]byte, 32), platformUserID, cacheTestNow)
				return err
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var pgError *pgconn.PgError
			err := testCase.insert()
			matched := errors.As(err, &pgError)
			constraint := ""
			if pgError != nil {
				constraint = pgError.ConstraintName
			}
			if err == nil || !matched || pgError.Code != "23503" ||
				pgError.ConstraintName != testCase.constraint {
				t.Fatalf("forged platform cache fact err=%v constraint=%q, want 23503/%s",
					err, constraint, testCase.constraint)
			}
		})
	}
}

func TestPublishPolicyAdvancesEdgeConfigurationSourceRevisionExactlyOnce(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "policy-source-revision", 1)
	ctx := context.Background()
	request := PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "policy-source-revision", RequestID: "policy-source-revision-request",
	}

	var before int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1`, fixture.actor.ScopeID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	result, err := store.PublishPolicy(ctx, fixture.actor, request)
	if err != nil || result.Policy.Revision != 1 {
		t.Fatalf("publish policy result=%+v err=%v", result, err)
	}
	var after, policyHead, edgeBinding int64
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1),
		(SELECT current_revision FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$2),
		(SELECT edge_source_revision FROM cache_policy_revisions
		 WHERE scope_id=$1 AND site_id=$2 AND revision=1)`,
		fixture.actor.ScopeID, fixture.siteID).Scan(&after, &policyHead, &edgeBinding); err != nil {
		t.Fatal(err)
	}
	if policyHead != 1 || after != before+1 || edgeBinding != after {
		t.Fatalf("policy/edge head/binding=%d/%d/%d before=%d, want 1/%d/%d",
			policyHead, after, edgeBinding, before, before+1, before+1)
	}
	replay, err := store.PublishPolicy(ctx, fixture.actor, request)
	if err != nil || !replay.Replayed || replay.Policy.Revision != 1 {
		t.Fatalf("policy replay result=%+v err=%v", replay, err)
	}
	rollbackStore := *store
	rollbackStore.auditor = failingAuditor{}
	failedRequest := request
	failedRequest.ExpectedRevision = 1
	failedRequest.IdempotencyKey = "policy-source-revision-audit-failure"
	failedRequest.RequestID = "policy-source-revision-audit-failure-request"
	if _, err := rollbackStore.PublishPolicy(ctx, fixture.actor, failedRequest); err == nil {
		t.Fatal("policy publish unexpectedly survived audit failure")
	}
	var finalEdge, revisionCount int64
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1),
		(SELECT count(*) FROM cache_policy_revisions WHERE scope_id=$1 AND site_id=$2)`,
		fixture.actor.ScopeID, fixture.siteID).Scan(&finalEdge, &revisionCount); err != nil {
		t.Fatal(err)
	}
	if finalEdge != after || revisionCount != 1 {
		t.Fatalf("edge source/revisions after replay and rollback=%d/%d, want %d/1",
			finalEdge, revisionCount, after)
	}
	if _, err := pool.Exec(ctx, `UPDATE cache_policy_revisions
		SET edge_source_revision=edge_source_revision+1
		WHERE scope_id=$1 AND site_id=$2 AND revision=1`, fixture.actor.ScopeID, fixture.siteID); err == nil {
		t.Fatal("immutable cache policy edge binding accepted direct update")
	}
}

func TestCache080WritePathsPersistActorScopeAndEdgeBinding(t *testing.T) {
	pool := openCacheTestDatabase(t, false)
	// Seed through the real migrator: migration 085 requires a verified ledger.
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 34); err != nil {
		t.Fatal(err)
	}
	fixture := seedCacheFixture(t, pool, "cache-080-write-paths", 1)
	// Facts seeded at 034 upgrade through the real migrator to the release head.
	if err := database.Migrate(context.Background(), pool, "up"); err != nil {
		t.Fatalf("migrate seeded 034 schema to release head: %v", err)
	}
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	ctx := context.Background()

	var before int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1`, fixture.actor.ScopeID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	policy, err := store.PublishPolicy(ctx, fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "cache-080-policy", RequestID: "cache-080-policy-request",
	})
	if err != nil {
		t.Fatalf("publish policy at migration 080: %v", err)
	}
	operation, err := store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/cache-080"}, NodeIDs: fixture.nodeIDs,
		IdempotencyKey: "cache-080-operation", RequestID: "cache-080-operation-request",
	})
	if err != nil {
		t.Fatalf("create operation at migration 080: %v", err)
	}

	var policyActorScope, operationActorScope uuid.UUID
	var edgeRevision, after int64
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT actor_scope_id FROM cache_policy_revisions WHERE site_id=$1 AND revision=$2),
		(SELECT edge_source_revision FROM cache_policy_revisions WHERE site_id=$1 AND revision=$2),
		(SELECT actor_scope_id FROM cache_operations WHERE id=$3),
		(SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$4)`,
		fixture.siteID, policy.Policy.Revision, operation.Operation.ID, fixture.actor.ScopeID,
	).Scan(&policyActorScope, &edgeRevision, &operationActorScope, &after); err != nil {
		t.Fatal(err)
	}
	if policyActorScope != fixture.actor.ScopeID || operationActorScope != fixture.actor.ScopeID {
		t.Fatalf("actor scopes policy/operation=%s/%s, want %s",
			policyActorScope, operationActorScope, fixture.actor.ScopeID)
	}
	if edgeRevision != before+1 || after != edgeRevision {
		t.Fatalf("edge source before/revision/head=%d/%d/%d", before, edgeRevision, after)
	}
}

func TestIdempotencyKeysAreBoundToTheAuthenticatedActor(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "actor-idempotency", 1)
	otherActor := seedCacheActor(t, pool, fixture, "actor-idempotency-other")
	targetFixture := seedCacheFixture(t, pool, "actor-idempotency-target", 1)
	ctx := context.Background()

	policyRequest := PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "actor-policy", RequestID: "actor-policy-request",
	}
	policy, err := store.PublishPolicy(ctx, fixture.actor, policyRequest)
	if err != nil || policy.Replayed {
		t.Fatalf("first actor policy=%+v err=%v", policy, err)
	}
	policyReplay, err := store.PublishPolicy(ctx, fixture.actor, policyRequest)
	if err != nil || !policyReplay.Replayed || policyReplay.Policy.Revision != policy.Policy.Revision {
		t.Fatalf("same actor policy replay=%+v err=%v", policyReplay, err)
	}
	changedPolicyRequest := policyRequest
	changedPolicyRequest.Document = validPolicyDocument(61)
	if _, err := store.PublishPolicy(ctx, fixture.actor, changedPolicyRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same actor policy changed payload err=%v", err)
	}
	otherPolicyRequest := policyRequest
	otherPolicyRequest.ExpectedRevision = 1
	otherPolicyRequest.RequestID = "actor-policy-other-request"
	otherPolicy, err := store.PublishPolicy(ctx, otherActor, otherPolicyRequest)
	if err != nil || otherPolicy.Replayed || otherPolicy.Policy.Revision != 2 {
		t.Fatalf("other actor policy=%+v err=%v", otherPolicy, err)
	}
	otherPolicyReplay, err := store.PublishPolicy(ctx, otherActor, otherPolicyRequest)
	if err != nil || !otherPolicyReplay.Replayed || otherPolicyReplay.Policy.Revision != 2 {
		t.Fatalf("other actor policy replay=%+v err=%v", otherPolicyReplay, err)
	}
	otherChangedPolicyRequest := otherPolicyRequest
	otherChangedPolicyRequest.Document = validPolicyDocument(62)
	if _, err := store.PublishPolicy(ctx, otherActor, otherChangedPolicyRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("other actor policy changed payload err=%v", err)
	}
	targetPolicyRequest := policyRequest
	targetPolicyRequest.SiteID = targetFixture.siteID
	targetPolicyRequest.RequestID = "actor-policy-target-request"
	if result, err := store.PublishPolicy(ctx, targetFixture.actor, targetPolicyRequest); err != nil || result.Replayed {
		t.Fatalf("target-isolated policy=%+v err=%v", result, err)
	}
	assertIdempotencyFactCounts(t, pool, 2, 2, `SELECT
		(SELECT count(*) FROM cache_policy_write_requests WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache_policy.publish'
		 AND resource_id=$3 AND result='success')`, fixture.actor.ScopeID, policyRequest.IdempotencyKey,
		fixture.siteID.String())
	assertIdempotencyFactCounts(t, pool, 1, 1, `SELECT
		(SELECT count(*) FROM cache_policy_write_requests WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache_policy.publish'
		 AND resource_id=$3 AND result='success')`, targetFixture.actor.ScopeID, policyRequest.IdempotencyKey,
		targetFixture.siteID.String())

	createRequest := CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/actor-create"}, NodeIDs: fixture.nodeIDs,
		MaxRetries: 1, IdempotencyKey: "actor-create", RequestID: "actor-create-request",
	}
	created, err := store.CreateOperation(ctx, fixture.actor, createRequest)
	if err != nil || created.Replayed {
		t.Fatalf("first actor create=%+v err=%v", created, err)
	}
	createReplay, err := store.CreateOperation(ctx, fixture.actor, createRequest)
	if err != nil || !createReplay.Replayed || createReplay.Operation.ID != created.Operation.ID {
		t.Fatalf("same actor create replay=%+v err=%v", createReplay, err)
	}
	changedCreateRequest := createRequest
	changedCreateRequest.Targets = []string{"http://" + fixture.domain + "/actor-create-changed"}
	if _, err := store.CreateOperation(ctx, fixture.actor, changedCreateRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same actor create changed payload err=%v", err)
	}
	otherCreated, err := store.CreateOperation(ctx, otherActor, createRequest)
	if err != nil || otherCreated.Replayed || otherCreated.Operation.ID == created.Operation.ID {
		t.Fatalf("other actor create=%+v err=%v", otherCreated, err)
	}
	otherCreateReplay, err := store.CreateOperation(ctx, otherActor, createRequest)
	if err != nil || !otherCreateReplay.Replayed || otherCreateReplay.Operation.ID != otherCreated.Operation.ID {
		t.Fatalf("other actor create replay=%+v err=%v", otherCreateReplay, err)
	}
	if _, err := store.CreateOperation(ctx, otherActor, changedCreateRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("other actor create changed payload err=%v", err)
	}
	targetCreateRequest := createRequest
	targetCreateRequest.SiteID = targetFixture.siteID
	targetCreateRequest.Targets = []string{"http://" + targetFixture.domain + "/actor-create"}
	targetCreateRequest.NodeIDs = targetFixture.nodeIDs
	targetCreateRequest.RequestID = "actor-create-target-request"
	if result, err := store.CreateOperation(ctx, targetFixture.actor, targetCreateRequest); err != nil || result.Replayed {
		t.Fatalf("target-isolated create=%+v err=%v", result, err)
	}
	assertIdempotencyFactCounts(t, pool, 2, 2, `SELECT
		(SELECT count(*) FROM cache_operations WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache.operation.create'
		 AND request_id IN ($3,$4) AND result='success')`, fixture.actor.ScopeID, createRequest.IdempotencyKey,
		createRequest.RequestID, createRequest.RequestID)
	assertIdempotencyFactCounts(t, pool, 1, 1, `SELECT
		(SELECT count(*) FROM cache_operations WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache.operation.create'
		 AND request_id=$3 AND result='success')`, targetFixture.actor.ScopeID, createRequest.IdempotencyKey,
		targetCreateRequest.RequestID)

	commandFixture := seedCacheFixture(t, pool, "actor-command-idempotency", 1)
	otherCommandActor := seedCacheActor(t, pool, commandFixture, "actor-command-idempotency-other")
	retryOperation := createSimpleOperation(t, store, commandFixture,
		"actor-retry-operation", 1, commandFixture.nodeIDs)
	claim := claimForNodes(t, store, commandFixture.actor.ScopeID, "actor-retry-worker",
		commandFixture.nodeIDs, 1, "actor-retry-claim")[0]
	failed, err := store.Report(ctx, reportRequest(claim, "actor-retry-worker", 1,
		"actor-retry-report", []ItemState{ItemFailed}))
	if err != nil || failed.Operation.State != StateFailed {
		t.Fatalf("prepare actor retry=%+v err=%v", failed, err)
	}
	retryRequest := RetryRequest{
		OperationID: retryOperation.ID, IdempotencyKey: "actor-retry", RequestID: "actor-retry-request",
	}
	retried, err := store.Retry(ctx, commandFixture.actor, retryRequest)
	if err != nil || retried.Replayed {
		t.Fatalf("first actor retry=%+v err=%v", retried, err)
	}
	retryReplay, err := store.Retry(ctx, commandFixture.actor, retryRequest)
	if err != nil || !retryReplay.Replayed {
		t.Fatalf("same actor retry replay=%+v err=%v", retryReplay, err)
	}
	if _, err := store.Retry(ctx, otherCommandActor, retryRequest); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cross-actor retry transition err=%v, want non-replay transition error", err)
	}
	assertIdempotencyFactCounts(t, pool, 1, 1, `SELECT
		(SELECT count(*) FROM cache_operation_commands WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache.operation.retry'
		 AND resource_id=$3 AND result='success')`, commandFixture.actor.ScopeID, retryRequest.IdempotencyKey,
		retryOperation.ID.String())

	cancelOperation := createSimpleOperation(t, store, commandFixture,
		"actor-cancel-operation", 0, commandFixture.nodeIDs)
	cancelRequest := CancelRequest{
		OperationID: cancelOperation.ID, IdempotencyKey: "actor-cancel", RequestID: "actor-cancel-request",
	}
	cancelled, err := store.Cancel(ctx, commandFixture.actor, cancelRequest)
	if err != nil || cancelled.Replayed {
		t.Fatalf("first actor cancel=%+v err=%v", cancelled, err)
	}
	cancelReplay, err := store.Cancel(ctx, commandFixture.actor, cancelRequest)
	if err != nil || !cancelReplay.Replayed {
		t.Fatalf("same actor cancel replay=%+v err=%v", cancelReplay, err)
	}
	if _, err := store.Cancel(ctx, otherCommandActor, cancelRequest); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cross-actor cancel transition err=%v, want non-replay transition error", err)
	}
	assertIdempotencyFactCounts(t, pool, 1, 1, `SELECT
		(SELECT count(*) FROM cache_operation_commands WHERE scope_id=$1 AND idempotency_key=$2),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='cache.operation.cancel'
		 AND resource_id=$3 AND result='success')`, commandFixture.actor.ScopeID, cancelRequest.IdempotencyKey,
		cancelOperation.ID.String())
}

func TestTenantAuthorizationRevocationLocksAndStatus(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "authorization", 1)
	operation := createSimpleOperation(t, store, fixture, "authorization-operation", 0, fixture.nodeIDs)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.actor.ScopeID,
		fixture.actor.UserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/denied"}, NodeIDs: fixture.nodeIDs,
		IdempotencyKey: "permission-denied", RequestID: "permission-denied-request",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("write after sites.manage revoke: %v", err)
	}
	if _, err := store.GetOperation(ctx, fixture.actor, operation.ID); err != nil {
		t.Fatalf("sites.read should remain effective: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.actor.ScopeID, fixture.actor.UserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}

	for _, statusTest := range []struct {
		name       string
		disableSQL string
		enableSQL  string
		arguments  []any
	}{
		{"user", `UPDATE users SET status='disabled' WHERE id=$1`,
			`UPDATE users SET status='active' WHERE id=$1`, []any{fixture.actor.UserID}},
		{"membership", `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`,
			`UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`,
			[]any{fixture.actor.ScopeID, fixture.actor.UserID}},
	} {
		if _, err := pool.Exec(ctx, statusTest.disableSQL, statusTest.arguments...); err != nil {
			t.Fatal(err)
		}
		if _, err := store.GetOperation(ctx, fixture.actor, operation.ID); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("%s disable did not revoke read: %v", statusTest.name, err)
		}
		if _, err := pool.Exec(ctx, statusTest.enableSQL, statusTest.arguments...); err != nil {
			t.Fatal(err)
		}
	}

	authorizationTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = authorizationTx.Rollback(context.Background()) }()
	if _, err := authorizeTenantActor(ctx, authorizationTx, fixture.actor, "sites.read"); err != nil {
		t.Fatal(err)
	}
	tenantUpdate := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := pool.Exec(context.Background(), `UPDATE tenants SET status='suspended' WHERE id=$1`, fixture.tenantID)
		tenantUpdate <- err
	}()
	<-started
	select {
	case err := <-tenantUpdate:
		t.Fatalf("tenant suspension bypassed authorization lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := authorizationTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-tenantUpdate:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tenant suspension remained blocked after authorization commit")
	}
	if _, err := store.GetOperation(ctx, fixture.actor, operation.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended tenant retained cache read: %v", err)
	}
	if _, err := store.Claim(ctx, ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "suspended-worker", OnlineNodeIDs: fixture.nodeIDs,
		Limit: 1, LeaseDuration: time.Minute, RequestID: "suspended-worker-claim",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended tenant retained worker claim: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenants SET status='active' WHERE id=$1`, fixture.tenantID); err != nil {
		t.Fatal(err)
	}

	permissionTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = permissionTx.Rollback(context.Background()) }()
	if _, err := authorizeTenantActor(ctx, permissionTx, fixture.actor, "sites.manage"); err != nil {
		t.Fatal(err)
	}
	permissionDelete := make(chan error, 1)
	started = make(chan struct{})
	go func() {
		close(started)
		_, err := pool.Exec(context.Background(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.actor.ScopeID,
			fixture.actor.UserID, fixture.roleID)
		permissionDelete <- err
	}()
	<-started
	select {
	case err := <-permissionDelete:
		t.Fatalf("permission revoke bypassed authorization lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := permissionTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-permissionDelete:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("permission revoke remained blocked after authorization commit")
	}
	if _, err := authorizeWriteProbe(ctx, store, fixture, "revoked-after-lock"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("committed standard RBAC revoke retained write: %v", err)
	}
}

func TestCustomRBACRevocationSharesAuthorizationWatermark(t *testing.T) {
	pool := openCacheTestDatabase(t, false)
	// Seed through the real migrator: migration 085 requires a verified ledger.
	if err := databasetest.MigrateThrough(context.Background(), pool, "up", 34); err != nil {
		t.Fatal(err)
	}
	fixture := seedCacheFixture(t, pool, "custom-authorization", 1)
	// Facts seeded at 034 upgrade through the real migrator to the release head.
	if err := database.Migrate(context.Background(), pool, "up"); err != nil {
		t.Fatalf("migrate seeded 034 schema to release head: %v", err)
	}
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.actor.ScopeID,
		fixture.actor.UserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}

	managerUserID, managerRoleID, managerSessionID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES($1,$2,'Cache RBAC manager','test-hash','active')`,
		managerUserID, "cache-rbac-manager-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`,
		fixture.actor.ScopeID, managerUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'cache RBAC manager',true)`, managerRoleID, fixture.actor.ScopeID,
		"cache-rbac-manager-role-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,'identity.roles.manage'),($1,'sites.read'),($1,'sites.manage')`, managerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.actor.ScopeID, managerUserID, managerRoleID); err != nil {
		t.Fatal(err)
	}
	refreshHash := make([]byte, 32)
	refreshHash[0] = 0x65
	if _, err := pool.Exec(ctx, `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, managerSessionID, uuid.New(), managerUserID,
		fixture.actor.ScopeID, refreshHash, cacheTestNow.Add(-time.Minute), cacheTestNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	manager := rbacmanager.Actor{
		UserID: managerUserID, ScopeID: fixture.actor.ScopeID, SessionID: managerSessionID,
		ScopeKind: "tenant", IdentityDomain: rbacmanager.CustomerControlIdentityDomain,
	}
	rbacService, err := rbacmanager.NewServiceWithDependencies(
		pool, audit.New(pool), cacheControlStepUp{}, func() time.Time { return cacheTestNow })
	if err != nil {
		t.Fatal(err)
	}
	role, err := rbacService.CreateRole(ctx, manager, rbacmanager.CreateRoleRequest{
		Name: "cache-manager", Permissions: []string{"sites.manage"},
		Mutation: cacheRBACMutation("cache-role-create"),
	})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := rbacService.AssignRole(ctx, manager, rbacmanager.AssignRoleRequest{
		RoleID: role.ID, ExpectedRoleRevision: role.CurrentRevision,
		SubjectUserID: fixture.actor.UserID, Mutation: cacheRBACMutation("cache-role-assign"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorizeWriteProbe(ctx, store, fixture, "custom-granted"); err != nil {
		t.Fatalf("custom sites.manage grant was not effective: %v", err)
	}

	authorizationTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = authorizationTx.Rollback(context.Background()) }()
	if _, err := authorizeTenantActor(ctx, authorizationTx, fixture.actor, "sites.manage"); err != nil {
		t.Fatal(err)
	}
	revoked := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := rbacService.RevokeGrant(context.Background(), manager, rbacmanager.RevokeGrantRequest{
			GrantID: grant.ID, Mutation: cacheRBACMutation("cache-role-revoke"),
		})
		revoked <- err
	}()
	<-started
	select {
	case err := <-revoked:
		t.Fatalf("custom RBAC revoke bypassed authorization watermark: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := authorizationTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-revoked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("custom RBAC revoke remained blocked after authorization commit")
	}
	if _, err := authorizeWriteProbe(ctx, store, fixture, "custom-revoked"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("committed custom RBAC revoke retained write: %v", err)
	}
}

func TestOperationLifecycleIsolationPartialRetryCancellationAndReplay(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixtureA := seedCacheFixture(t, pool, "operation-a", 3)
	fixtureB := seedCacheFixture(t, pool, "operation-b", 1)

	request := CreateOperationRequest{
		SiteID: fixtureA.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{
			"HTTP://OPERATION-A.EXAMPLE:80/assets/%7e.css?b=2&a=1",
			"http://operation-a.example/api/data",
		},
		NodeIDs: fixtureA.nodeIDs[:2], MaxRetries: 1,
		IdempotencyKey: "operation-main", RequestID: "operation-main-request",
	}
	created, err := store.CreateOperation(context.Background(), fixtureA.actor, request)
	if err != nil || created.Replayed || created.Operation.State != StateQueued ||
		created.Operation.Progress.Total != 4 || created.Operation.Targets[0].CanonicalURL !=
		"http://operation-a.example/assets/~.css?b=2&a=1" {
		t.Fatalf("create operation: result=%+v err=%v", created, err)
	}
	replay, err := store.CreateOperation(context.Background(), fixtureA.actor, request)
	if err != nil || !replay.Replayed || replay.Operation.ID != created.Operation.ID {
		t.Fatalf("operation replay: result=%+v err=%v", replay, err)
	}
	conflict := request
	conflict.Targets = []string{"http://operation-a.example/different"}
	if _, err := store.CreateOperation(context.Background(), fixtureA.actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("same operation key with different targets: %v", err)
	}
	crossTenant := request
	crossTenant.IdempotencyKey = "operation-cross-tenant"
	crossTenant.RequestID = "operation-cross-tenant-request"
	crossTenant.NodeIDs = fixtureB.nodeIDs
	if _, err := store.CreateOperation(context.Background(), fixtureA.actor, crossTenant); !errors.Is(err, ErrTargetNodeUnavailable) {
		t.Fatalf("cross-tenant node write: %v", err)
	}

	claims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixtureA.actor.ScopeID, WorkerID: "worker-a", OnlineNodeIDs: fixtureA.nodeIDs[:1],
		Limit: 10, LeaseDuration: time.Minute, RequestID: "claim-node-a",
	})
	if err != nil || len(claims) != 1 || claims[0].NodeID != fixtureA.nodeIDs[0] || len(claims[0].Targets) != 2 {
		t.Fatalf("claim online node A: claims=%+v err=%v", claims, err)
	}
	firstReport := reportRequest(claims[0], "worker-a", 1, "report-node-a",
		[]ItemState{ItemSucceeded, ItemFailed})
	reported, err := store.Report(context.Background(), firstReport)
	if err != nil || !reported.Applied || reported.Operation.State != StateRunning ||
		reported.Operation.Progress.Succeeded != 1 || reported.Operation.Progress.Failed != 1 {
		t.Fatalf("partial node report: result=%+v err=%v", reported, err)
	}

	claims, err = store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixtureA.actor.ScopeID, WorkerID: "worker-b", OnlineNodeIDs: fixtureA.nodeIDs[1:2],
		Limit: 10, LeaseDuration: time.Minute, RequestID: "claim-node-b",
	})
	if err != nil || len(claims) != 1 || claims[0].NodeID != fixtureA.nodeIDs[1] {
		t.Fatalf("claim online node B: claims=%+v err=%v", claims, err)
	}
	secondReport := reportRequest(claims[0], "worker-b", 1, "report-node-b",
		[]ItemState{ItemSucceeded, ItemSucceeded})
	reported, err = store.Report(context.Background(), secondReport)
	if err != nil || reported.Operation.State != StatePartialFailed ||
		reported.Operation.Progress.Succeeded != 3 || reported.Operation.Progress.Failed != 1 {
		t.Fatalf("operation partial failure: result=%+v err=%v", reported, err)
	}

	retried, err := store.Retry(context.Background(), fixtureA.actor, RetryRequest{
		OperationID: created.Operation.ID, IdempotencyKey: "retry-main", RequestID: "retry-main-request",
	})
	if err != nil || retried.Operation.State != StateQueued || retried.Operation.Progress.Completed != 3 {
		t.Fatalf("retry partial operation: result=%+v err=%v", retried, err)
	}
	claims, err = store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixtureA.actor.ScopeID, WorkerID: "worker-a", OnlineNodeIDs: fixtureA.nodeIDs[:1],
		Limit: 1, LeaseDuration: time.Minute, RequestID: "claim-node-a-retry",
	})
	if err != nil || len(claims) != 1 || claims[0].Attempt != 2 || len(claims[0].Targets) != 1 ||
		claims[0].Targets[0].Ordinal != 2 {
		t.Fatalf("retry claim: claims=%+v err=%v", claims, err)
	}
	finalReport := reportRequest(claims[0], "worker-a", 2, "report-node-a-retry", []ItemState{ItemSucceeded})
	reported, err = store.Report(context.Background(), finalReport)
	if err != nil || reported.Operation.State != StateSucceeded || reported.Operation.Progress.Succeeded != 4 {
		t.Fatalf("retry completion: result=%+v err=%v", reported, err)
	}
	if _, err := store.Retry(context.Background(), fixtureA.actor, RetryRequest{
		OperationID: created.Operation.ID, IdempotencyKey: "retry-after-success", RequestID: "retry-after-success-request",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("retry succeeded operation with new key: %v", err)
	}
	duplicate, err := store.Report(context.Background(), finalReport)
	if err != nil || !duplicate.Replayed || duplicate.Applied || duplicate.Operation.State != StateSucceeded {
		t.Fatalf("duplicate report: result=%+v err=%v", duplicate, err)
	}
	late := firstReport
	late.Sequence = 2
	late.Results[0].State = ItemFailed
	late.Results[0].ErrorCode = "late_failure"
	late.Results[1].State = ItemSucceeded
	late.Results[1].ErrorCode = ""
	late.RequestID = "late-report"
	lateResult, err := store.Report(context.Background(), late)
	if err != nil || lateResult.Applied || lateResult.Operation.State != StateSucceeded {
		t.Fatalf("late report regressed terminal state: result=%+v err=%v", lateResult, err)
	}
	conflictingReport := firstReport
	conflictingReport.Results[0].State = ItemFailed
	conflictingReport.Results[0].ErrorCode = "conflicting_failure"
	conflictingReport.Results[1].State = ItemSucceeded
	conflictingReport.Results[1].ErrorCode = ""
	conflictingReport.RequestID = "conflicting-report"
	if _, err := store.Report(context.Background(), conflictingReport); !errors.Is(err, ErrReportConflict) {
		t.Fatalf("same sequence conflicting report: %v", err)
	}

	cancelledOperation := createSimpleOperation(t, store, fixtureA, "cancel-operation", 1, fixtureA.nodeIDs[:1])
	cancelClaims := claimForNodes(t, store, fixtureA.actor.ScopeID, "cancel-worker", fixtureA.nodeIDs[:1], 1, "cancel-claim")
	if cancelClaims[0].OperationID != cancelledOperation.ID {
		t.Fatalf("claimed operation=%s, want cancel operation=%s", cancelClaims[0].OperationID, cancelledOperation.ID)
	}
	cancelled, err := store.Cancel(context.Background(), fixtureA.actor, CancelRequest{
		OperationID: cancelledOperation.ID, IdempotencyKey: "cancel-command", RequestID: "cancel-command-request",
	})
	if err != nil || cancelled.Operation.State != StateCancelled {
		t.Fatalf("cancel running operation: result=%+v err=%v", cancelled, err)
	}
	cancelReplay, err := store.Cancel(context.Background(), fixtureA.actor, CancelRequest{
		OperationID: cancelledOperation.ID, IdempotencyKey: "cancel-command", RequestID: "cancel-command-replay",
	})
	if err != nil || !cancelReplay.Replayed || cancelReplay.Operation.State != StateCancelled {
		t.Fatalf("cancel replay: result=%+v err=%v", cancelReplay, err)
	}
	if _, err := store.Cancel(context.Background(), fixtureA.actor, CancelRequest{
		OperationID: cancelledOperation.ID, IdempotencyKey: "cancel-after-terminal", RequestID: "cancel-after-terminal-request",
	}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("cancel terminal operation with new key: %v", err)
	}
	var rejectedCommandCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM cache_operation_commands
		WHERE scope_id=$1 AND operation_id IN ($2,$3)
		  AND idempotency_key IN ('retry-after-success','cancel-after-terminal')`,
		fixtureA.actor.ScopeID, created.Operation.ID, cancelledOperation.ID).Scan(&rejectedCommandCount); err != nil {
		t.Fatal(err)
	}
	if rejectedCommandCount != 0 {
		t.Fatalf("rejected terminal commands persisted=%d, want 0", rejectedCommandCount)
	}
	lateCancelled := reportRequest(cancelClaims[0], "cancel-worker", 1, "cancel-late-report", []ItemState{ItemSucceeded})
	cancelLateResult, err := store.Report(context.Background(), lateCancelled)
	if err != nil || cancelLateResult.Applied || cancelLateResult.Operation.State != StateCancelled {
		t.Fatalf("cancelled late report: result=%+v err=%v", cancelLateResult, err)
	}

	exhaustedOperation := createSimpleOperation(t, store, fixtureA, "exhausted-operation", 0, fixtureA.nodeIDs[:1])
	exhaustedClaim := claimForNodes(t, store, fixtureA.actor.ScopeID, "exhausted-worker", fixtureA.nodeIDs[:1], 1, "exhausted-claim")[0]
	if exhaustedClaim.OperationID != exhaustedOperation.ID {
		t.Fatalf("claimed operation=%s, want exhausted operation=%s", exhaustedClaim.OperationID, exhaustedOperation.ID)
	}
	exhaustedReport := reportRequest(exhaustedClaim, "exhausted-worker", 1, "exhausted-report", []ItemState{ItemFailed})
	exhaustedResult, err := store.Report(context.Background(), exhaustedReport)
	if err != nil || exhaustedResult.Operation.State != StateFailed {
		t.Fatalf("exhausted failure: result=%+v err=%v", exhaustedResult, err)
	}
	if _, err := store.Retry(context.Background(), fixtureA.actor, RetryRequest{
		OperationID: exhaustedOperation.ID, IdempotencyKey: "exhausted-retry", RequestID: "exhausted-retry-request",
	}); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("retry exhausted operation: %v", err)
	}

	rollbackStore := *store
	rollbackStore.auditor = failingAuditor{}
	rollbackRequest := request
	rollbackRequest.IdempotencyKey = "operation-audit-failure"
	rollbackRequest.RequestID = "operation-audit-failure-request"
	if _, err := rollbackStore.CreateOperation(context.Background(), fixtureA.actor, rollbackRequest); err == nil {
		t.Fatal("operation create unexpectedly survived audit failure")
	}
	var rollbackCount int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM cache_operations WHERE scope_id=$1 AND idempotency_key=$2`,
		fixtureA.actor.ScopeID, rollbackRequest.IdempotencyKey).Scan(&rollbackCount); err != nil {
		t.Fatal(err)
	}
	if rollbackCount != 0 {
		t.Fatalf("audit-failed operations=%d, want 0", rollbackCount)
	}
}

func TestOfflineRecoveryFairAndConcurrentClaims(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "claim", 6)

	offlineOperation := createSimpleOperation(t, store, fixture, "offline-operation", 1, fixture.nodeIDs[:1])
	firstClaims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "offline-worker", OnlineNodeIDs: fixture.nodeIDs[:1],
		Limit: 1, LeaseDuration: time.Second, RequestID: "offline-first-claim",
	})
	if err != nil || len(firstClaims) != 1 {
		t.Fatalf("offline first claim: claims=%+v err=%v", firstClaims, err)
	}
	firstClaim := firstClaims[0]
	if firstClaim.OperationID != offlineOperation.ID || firstClaim.Attempt != 1 {
		t.Fatalf("offline first claim=%+v", firstClaim)
	}
	clock.Add(2 * time.Second)
	claims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "reaper", OnlineNodeIDs: fixture.nodeIDs[1:2],
		Limit: 10, LeaseDuration: time.Minute, RequestID: "offline-reap",
	})
	if err != nil || len(claims) != 0 {
		t.Fatalf("offline reaper claims=%+v err=%v", claims, err)
	}
	operation, err := store.GetOperation(context.Background(), fixture.actor, offlineOperation.ID)
	if err != nil || operation.State != StateRunning || operation.Nodes[0].State != StateQueued ||
		operation.Nodes[0].Attempt != 1 {
		t.Fatalf("offline projection was not retained: operation=%+v err=%v", operation, err)
	}
	claims, err = store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "offline-worker-2", OnlineNodeIDs: fixture.nodeIDs[:1],
		Limit: 1, LeaseDuration: time.Minute, RequestID: "offline-backoff-claim",
	})
	if err != nil || len(claims) != 0 {
		t.Fatalf("offline claim bypassed retry backoff: claims=%+v err=%v", claims, err)
	}
	clock.Add(time.Second)
	secondClaim := claimForNodes(t, store, fixture.actor.ScopeID, "offline-worker-2", fixture.nodeIDs[:1], 1, "offline-second-claim")[0]
	if secondClaim.OperationID != offlineOperation.ID || secondClaim.Attempt != 2 {
		t.Fatalf("offline compensation claim=%+v", secondClaim)
	}
	offlineFailure := reportRequest(secondClaim, "offline-worker-2", 1, "offline-failure", []ItemState{ItemFailed})
	failed, err := store.Report(context.Background(), offlineFailure)
	if err != nil || failed.Operation.State != StateFailed {
		t.Fatalf("offline retry exhaustion: result=%+v err=%v", failed, err)
	}
	if _, err := store.Retry(context.Background(), fixture.actor, RetryRequest{
		OperationID: offlineOperation.ID, IdempotencyKey: "offline-retry", RequestID: "offline-retry-request",
	}); !errors.Is(err, ErrRetriesExhausted) {
		t.Fatalf("offline retry budget: %v", err)
	}

	fairA := createSimpleOperation(t, store, fixture, "fair-a", 0, fixture.nodeIDs[:2])
	fairB := createSimpleOperation(t, store, fixture, "fair-b", 0, fixture.nodeIDs[:2])
	fairClaims := claimForNodes(t, store, fixture.actor.ScopeID, "fair-worker", fixture.nodeIDs[:2], 4, "fair-claim")
	if len(fairClaims) != 4 || fairClaims[0].OperationID == fairClaims[1].OperationID ||
		fairClaims[2].OperationID == fairClaims[3].OperationID {
		t.Fatalf("claim order is not operation-fair: %+v", fairClaims)
	}
	fairSeen := map[uuid.UUID]int{}
	for _, claim := range fairClaims {
		fairSeen[claim.OperationID]++
	}
	if fairSeen[fairA.ID] != 2 || fairSeen[fairB.ID] != 2 {
		t.Fatalf("fair claim counts=%v", fairSeen)
	}

	concurrent := createSimpleOperation(t, store, fixture, "concurrent", 0, fixture.nodeIDs[2:6])
	start := make(chan struct{})
	results := make(chan []Claim, 2)
	errorsOut := make(chan error, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			claims, err := store.Claim(context.Background(), ClaimRequest{
				ScopeID: fixture.actor.ScopeID, WorkerID: fmt.Sprintf("race-worker-%d", index),
				OnlineNodeIDs: fixture.nodeIDs[2:6], Limit: 4, LeaseDuration: time.Minute,
				RequestID: fmt.Sprintf("race-claim-%d", index),
			})
			results <- claims
			errorsOut <- err
		}()
	}
	close(start)
	seenNodes := map[uuid.UUID]struct{}{}
	total := 0
	for range 2 {
		claims := <-results
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
		for _, claim := range claims {
			if claim.OperationID != concurrent.ID {
				t.Fatalf("race claimed unrelated operation: %+v", claim)
			}
			if _, exists := seenNodes[claim.NodeID]; exists {
				t.Fatalf("node %s claimed twice", claim.NodeID)
			}
			seenNodes[claim.NodeID] = struct{}{}
			total++
		}
	}
	if total != 4 {
		t.Fatalf("concurrent claims=%d, want 4", total)
	}
}

func TestLargeMultiBatchProgressionFairWithoutStarvation(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "large-batch", 3)
	operations := make([]Operation, 101)
	for index := range operations {
		operations[index] = createSimpleOperation(t, store, fixture,
			fmt.Sprintf("large-%03d", index), 1, fixture.nodeIDs)
	}

	first, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "large-first-worker", OnlineNodeIDs: fixture.nodeIDs,
		Limit: maxClaimBatch, LeaseDuration: time.Second, RequestID: "large-first-claim",
	})
	if err != nil || len(first) != maxClaimBatch {
		t.Fatalf("first large claim count=%d err=%v", len(first), err)
	}
	counts := make(map[uuid.UUID]int, len(operations))
	for _, claim := range first {
		counts[claim.OperationID]++
	}
	var omittedOperationID uuid.UUID
	for _, operation := range operations {
		if counts[operation.ID] == 0 {
			if omittedOperationID != uuid.Nil {
				t.Fatalf("more than one operation omitted from first fairness round: %s and %s",
					omittedOperationID, operation.ID)
			}
			omittedOperationID = operation.ID
		}
	}
	if omittedOperationID == uuid.Nil {
		t.Fatal("first bounded batch unexpectedly covered all 101 operations")
	}
	cancelOperationID := first[0].OperationID
	leaseOperationID := first[1].OperationID
	type claimKey struct {
		operationID uuid.UUID
		nodeID      uuid.UUID
		attempt     uint32
	}
	seen := make(map[claimKey]struct{}, len(operations)*len(fixture.nodeIDs)+1)
	for _, claim := range first {
		key := claimKey{claim.OperationID, claim.NodeID, claim.Attempt}
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate first-batch claim: %+v", claim)
		}
		seen[key] = struct{}{}
		if claim.OperationID == cancelOperationID || claim.OperationID == leaseOperationID {
			continue
		}
		result, err := store.Report(context.Background(),
			reportRequest(claim, "large-first-worker", 1,
				"large-first-report-"+claim.NodeID.String(), []ItemState{ItemSucceeded}))
		if err != nil || !result.Applied {
			t.Fatalf("first-batch report claim=%+v result=%+v err=%v", claim, result, err)
		}
	}
	second, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "large-second-worker", OnlineNodeIDs: fixture.nodeIDs,
		Limit: maxClaimBatch, LeaseDuration: time.Second, RequestID: "large-second-claim",
	})
	if err != nil || len(second) != maxClaimBatch {
		t.Fatalf("second large claim count=%d err=%v", len(second), err)
	}
	omittedAdvanced := false
	for _, claim := range second {
		if claim.OperationID == omittedOperationID {
			omittedAdvanced = true
		}
		key := claimKey{claim.OperationID, claim.NodeID, claim.Attempt}
		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate second-batch claim: %+v", claim)
		}
		seen[key] = struct{}{}
		if claim.OperationID == cancelOperationID || claim.OperationID == leaseOperationID {
			continue
		}
		result, err := store.Report(context.Background(),
			reportRequest(claim, "large-second-worker", 1,
				"large-second-report-"+claim.LeaseID.String(), []ItemState{ItemSucceeded}))
		if err != nil || !result.Applied {
			t.Fatalf("second-batch report claim=%+v result=%+v err=%v", claim, result, err)
		}
	}
	if !omittedAdvanced {
		t.Fatalf("operation %s was starved from second bounded batch", omittedOperationID)
	}
	if result, err := store.Cancel(context.Background(), fixture.actor, CancelRequest{
		OperationID: cancelOperationID, IdempotencyKey: "large-cancel", RequestID: "large-cancel-request",
	}); err != nil || result.Operation.State != StateCancelled {
		t.Fatalf("large cancellation result=%+v err=%v", result, err)
	}
	for _, batch := range [][]Claim{first, second} {
		for _, claim := range batch {
			if claim.OperationID != cancelOperationID {
				continue
			}
			worker := "large-first-worker"
			if batch[0].LeaseID == second[0].LeaseID {
				worker = "large-second-worker"
			}
			late, err := store.Report(context.Background(),
				reportRequest(claim, worker, 1,
					"large-late-"+claim.LeaseID.String(), []ItemState{ItemSucceeded}))
			if err != nil || late.Applied || late.Operation.State != StateCancelled {
				t.Fatalf("large late report result=%+v err=%v", late, err)
			}
		}
	}

	clock.Add(2 * time.Second)
	if err := store.ReconcileExpired(context.Background(), fixture.actor.ScopeID, "large-reconcile-expired"); err != nil {
		t.Fatal(err)
	}
	clock.Add(time.Second)
	batches := 2
	for {
		claims, err := store.Claim(context.Background(), ClaimRequest{
			ScopeID: fixture.actor.ScopeID, WorkerID: "large-drain-worker", OnlineNodeIDs: fixture.nodeIDs,
			Limit: maxClaimBatch, LeaseDuration: time.Minute,
			RequestID: fmt.Sprintf("large-drain-claim-%d", batches),
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(claims) == 0 {
			break
		}
		batches++
		if batches > 6 {
			t.Fatalf("large progression did not drain after %d batches", batches)
		}
		for _, claim := range claims {
			key := claimKey{claim.OperationID, claim.NodeID, claim.Attempt}
			if _, exists := seen[key]; exists {
				t.Fatalf("duplicate multi-batch claim: %+v", claim)
			}
			seen[key] = struct{}{}
			result, err := store.Report(context.Background(),
				reportRequest(claim, "large-drain-worker", 1,
					"large-drain-report-"+claim.LeaseID.String(), []ItemState{ItemSucceeded}))
			if err != nil || !result.Applied {
				t.Fatalf("drain report claim=%+v result=%+v err=%v", claim, result, err)
			}
		}
	}
	if batches < 2 {
		t.Fatalf("large progression used %d batch, want multiple batches", batches)
	}
	for _, operation := range operations {
		stored, err := store.GetOperation(context.Background(), fixture.actor, operation.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := StateSucceeded
		if operation.ID == cancelOperationID {
			want = StateCancelled
		}
		if stored.State != want || stored.Progress.Completed != stored.Progress.Total {
			t.Fatalf("operation %s final state=%s progress=%+v want=%s", operation.ID,
				stored.State, stored.Progress, want)
		}
	}
}

func TestOpenClaimsReconstructsPublishUnknownCommandFacts(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	clock := &testClock{value: cacheTestNow}
	store := mustCacheStore(t, pool, clock.Now)
	fixture := seedCacheFixture(t, pool, "open-claim", 1)
	operation := createSimpleOperation(t, store, fixture, "open-claim-operation", 1, fixture.nodeIDs)
	configID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,
		created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-test','1','releasable',$5,$4,$6,$6)`, configID,
		fixture.actor.ScopeID, []byte("active-config"), make([]byte, 32),
		"cache-open-claim-"+configID.String(), cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,revision,updated_at
	) VALUES($1,$2,$3,7,$4)`, fixture.nodeIDs[0], fixture.actor.ScopeID, configID,
		cacheTestNow); err != nil {
		t.Fatal(err)
	}

	claims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: fixture.actor.ScopeID, WorkerID: "stable-cache-worker",
		OnlineNodeIDs: fixture.nodeIDs, Limit: 1, LeaseDuration: time.Minute,
		RequestID: "open-claim-initial", RequireActiveConfig: true,
	})
	if err != nil || len(claims) != 1 {
		t.Fatalf("initial production claim=%+v err=%v", claims, err)
	}
	claimed := claims[0]
	if claimed.OperationID != operation.ID {
		t.Fatalf("initial claim operation=%s want=%s", claimed.OperationID, operation.ID)
	}
	if claimed.ConfigVersionID != configID || claimed.ConfigRevision != 7 {
		t.Fatalf("initial claim config=%s/%d want=%s/7", claimed.ConfigVersionID,
			claimed.ConfigRevision, configID)
	}
	replacementID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,
		created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-test','1','releasable',$5,$4,$6,$6)`, replacementID,
		fixture.actor.ScopeID, []byte("replacement-config"), make([]byte, 32),
		"cache-open-claim-"+replacementID.String(), cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE node_config_state
		SET previous_config_version_id=current_config_version_id,current_config_version_id=$2,
			revision=8,updated_at=$3 WHERE node_id=$1`, fixture.nodeIDs[0], replacementID,
		cacheTestNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.OpenClaims(context.Background(), OpenClaimsRequest{
		WorkerID: "stable-cache-worker", Limit: 10,
	})
	if err != nil || len(recovered) != 1 {
		t.Fatalf("open claims=%+v err=%v", recovered, err)
	}
	got := recovered[0]
	if got.OperationID != claimed.OperationID || got.ScopeID != claimed.ScopeID ||
		got.SiteID != claimed.SiteID || got.Action != claimed.Action ||
		got.TargetType != claimed.TargetType || got.NodeID != claimed.NodeID ||
		got.Attempt != claimed.Attempt || got.LeaseID != claimed.LeaseID ||
		!got.ClaimedAt.Equal(claimed.ClaimedAt) || !got.LeaseExpiresAt.Equal(claimed.LeaseExpiresAt) ||
		got.RequestDigest != claimed.RequestDigest || got.Priority != claimed.Priority ||
		len(got.Targets) != len(claimed.Targets) {
		t.Fatalf("recovered claim changed immutable facts:\n got=%+v\nwant=%+v", got, claimed)
	}
	for index := range claimed.Targets {
		if got.Targets[index] != claimed.Targets[index] {
			t.Fatalf("recovered target[%d]=%+v want=%+v", index, got.Targets[index], claimed.Targets[index])
		}
	}

	clock.Add(2 * time.Minute)
	recovered, err = store.OpenClaims(context.Background(), OpenClaimsRequest{
		WorkerID: "stable-cache-worker", Limit: 10,
	})
	if err != nil || len(recovered) != 0 {
		t.Fatalf("expired open claims=%+v err=%v", recovered, err)
	}
}

func TestLeaseRetryBackoffIsBoundedExponential(t *testing.T) {
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{
		{attempt: 1, want: time.Second},
		{attempt: 2, want: 2 * time.Second},
		{attempt: 3, want: 4 * time.Second},
		{attempt: 7, want: time.Minute},
		{attempt: 100, want: time.Minute},
	} {
		if got := leaseRetryBackoff(test.attempt); got != test.want {
			t.Fatalf("leaseRetryBackoff(%d)=%s want=%s", test.attempt, got, test.want)
		}
	}
}

func TestCacheControlSQLMutationGuards(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "sql-guards", 1)
	ctx := context.Background()
	digest := make([]byte, 32)

	policy, err := store.PublishPolicy(ctx, fixture.actor, PublishPolicyRequest{
		SiteID: fixture.siteID, ExpectedRevision: 0, Document: validPolicyDocument(60),
		IdempotencyKey: "guard-policy", RequestID: "guard-policy-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	operation := createSimpleOperation(t, store, fixture, "guard-operation", 0, fixture.nodeIDs)
	claim := claimForNodes(t, store, fixture.actor.ScopeID, "guard-worker", fixture.nodeIDs, 1, "guard-claim")[0]
	settled, err := store.Report(ctx, reportRequest(claim, "guard-worker", 1, "guard-report", []ItemState{ItemSucceeded}))
	if err != nil || settled.Operation.State != StateSucceeded {
		t.Fatalf("settle guarded operation: result=%+v err=%v", settled, err)
	}

	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_policy_revisions SET disk_quota_bytes=disk_quota_bytes+1
			WHERE site_id=$1 AND revision=$2`, fixture.siteID, policy.Policy.Revision)
		return err
	}, "cache control history is append-only")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_policy_revisions WHERE site_id=$1 AND revision=$2`,
			fixture.siteID, policy.Policy.Revision)
		return err
	}, "cache control history is append-only")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_operation_targets SET canonical_path='/changed/'
			WHERE operation_id=$1 AND ordinal=1`, operation.ID)
		return err
	}, "cache control history is append-only")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_targets WHERE operation_id=$1`, operation.ID)
		return err
	}, "cache control history is append-only")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_operation_node_attempts
			SET state='failed',error_code='direct_failure'
			WHERE operation_id=$1 AND node_id=$2 AND attempt=1`, operation.ID, fixture.nodeIDs[0])
		return err
	}, "invalid cache operation attempt transition")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_node_attempts
			WHERE operation_id=$1 AND node_id=$2 AND attempt=1`, operation.ID, fixture.nodeIDs[0])
		return err
	}, "invalid cache operation attempt transition")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_operation_target_results
			SET error_code='tampered' WHERE operation_id=$1`, operation.ID)
		return err
	}, "cache control history is append-only")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_target_results WHERE operation_id=$1`, operation.ID)
		return err
	}, "cache control history is append-only")
	var auditEventID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT audit_event_id FROM cache_operation_target_results
		WHERE operation_id=$1 LIMIT 1`, operation.ID).Scan(&auditEventID); err != nil {
		t.Fatal(err)
	}
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `INSERT INTO cache_operation_target_results (
			id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,
			sequence,report_digest,audit_event_id,created_at
		) VALUES ($1,$2,$3,$4,1,1,'report','succeeded',1,$5,$6,$7)`,
			uuid.New(), operation.ID, fixture.actor.ScopeID, fixture.nodeIDs[0], digest, auditEventID, cacheTestNow)
		return err
	}, "cache operation support facts cannot be added after completion")
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		return audit.New(pool).Append(ctx, tx, audit.Event{
			ScopeID: fixture.actor.ScopeID, Action: "cache.operation.report",
			ResourceType: "cache_operation", ResourceID: operation.ID.String(),
			RequestID: "late-audit", Result: "success",
			Payload: map[string]any{"node_id": fixture.nodeIDs[0], "attempt": 1, "sequence": 2},
		})
	}, "cache operation terminal audit cannot be added after completion")
	for _, lateAudit := range []struct {
		action  string
		payload map[string]any
	}{
		{"cache.operation.create", map[string]any{"targets": 1, "nodes": 1}},
		{"cache.operation.claim", map[string]any{
			"node_id": claim.NodeID, "attempt": claim.Attempt,
			"lease_id": claim.LeaseID, "target_count": len(claim.Targets),
		}},
		{"cache.operation.retry", map[string]any{"command_id": uuid.New(), "node_count": 1}},
	} {
		expectDatabaseGuard(t, func() error {
			tx, err := pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			return audit.New(pool).Append(ctx, tx, audit.Event{
				ScopeID: fixture.actor.ScopeID, ActorUserID: &fixture.actor.UserID,
				Action: lateAudit.action, ResourceType: "cache_operation",
				ResourceID: operation.ID.String(), RequestID: "late-support-audit",
				Result: "success", Payload: lateAudit.payload,
			})
		}, "cache operation terminal audit cannot be added after completion")
	}
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `INSERT INTO cache_operation_commands (
			id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
		) VALUES($1,$2,$3,$3,'cancel','late-terminal-command',$4,$5,$6)`,
			uuid.New(), operation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow)
		return err
	}, "cache operation commands must be inserted unfinished")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_operations
			SET state='running',completed_at=NULL WHERE id=$1`, operation.ID)
		return err
	}, "invalid cache operation transition")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operations WHERE id=$1`, operation.ID)
		return err
	}, "invalid cache operation transition")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_nodes
			WHERE operation_id=$1 AND node_id=$2`, operation.ID, fixture.nodeIDs[0])
		return err
	}, "cache operation projections cannot be deleted")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_node_targets
			WHERE operation_id=$1 AND node_id=$2`, operation.ID, fixture.nodeIDs[0])
		return err
	}, "cache operation projections cannot be deleted")

	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO cache_policy_write_requests (
				id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,
				response_revision,created_at,completed_at
			) VALUES ($1,$2,$2,$3,$4,'guard-policy-fake-complete',$5,$6,$7,$7)`,
			uuid.New(), fixture.actor.ScopeID, fixture.actor.UserID, fixture.siteID,
			digest, policy.Policy.Revision, cacheTestNow)
		return err
	}, "cache policy write requests must be inserted unfinished")
	policyWriteID := uuid.New()
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO cache_policy_write_requests (
				id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
			) VALUES ($1,$2,$2,$3,$4,'guard-policy-direct',$5,$6)`,
			policyWriteID, fixture.actor.ScopeID, fixture.actor.UserID, fixture.siteID, digest, cacheTestNow)
		return err
	}, "cache control idempotency fact must complete atomically")
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err = tx.Exec(ctx, `
			INSERT INTO cache_policy_write_requests (
				id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
			) VALUES ($1,$2,$2,$3,$4,'guard-policy-direct-tx',$5,$6)`,
			policyWriteID, fixture.actor.ScopeID, fixture.actor.UserID, fixture.siteID, digest, cacheTestNow); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cache_policy_write_requests
			SET response_revision=$2,completed_at=$3 WHERE id=$1`,
			policyWriteID, policy.Policy.Revision, cacheTestNow)
		return err
	}, "invalid cache policy write request completion")
	var completedPolicyWriteID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM cache_policy_write_requests
		WHERE scope_id=$1 AND idempotency_key='guard-policy'`, fixture.actor.ScopeID).
		Scan(&completedPolicyWriteID); err != nil {
		t.Fatal(err)
	}
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_policy_write_requests SET completed_at=$2 WHERE id=$1`,
			completedPolicyWriteID, cacheTestNow.Add(time.Second))
		return err
	}, "invalid cache policy write request completion")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_policy_write_requests WHERE id=$1`, completedPolicyWriteID)
		return err
	}, "invalid cache policy write request completion")

	commandOperation := createSimpleOperation(t, store, fixture, "guard-command-operation", 0, fixture.nodeIDs)
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO cache_operation_commands (
				id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,
				actor_user_id,created_at,completed_at
			) VALUES ($1,$2,$3,$3,'cancel','guard-command-fake-complete',$4,$5,$6,$6)`,
			uuid.New(), commandOperation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow)
		return err
	}, "cache operation commands must be inserted unfinished")
	commandID := uuid.New()
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `
			INSERT INTO cache_operation_commands (
				id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
			) VALUES ($1,$2,$3,$3,'cancel','guard-command-direct',$4,$5,$6)`,
			commandID, commandOperation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow)
		return err
	}, "cache operation actor scope integrity violation")
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err = tx.Exec(ctx, `
			INSERT INTO cache_operation_commands (
				id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
			) VALUES ($1,$2,$3,$3,'cancel','guard-command-direct-tx',$4,$5,$6)`,
			commandID, commandOperation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cache_operation_commands SET completed_at=$2 WHERE id=$1`,
			commandID, cacheTestNow)
		return err
	}, "invalid cache operation command completion")
	if _, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: commandOperation.ID, IdempotencyKey: "guard-real-cancel",
		RequestID: "guard-real-cancel-request",
	}); err != nil {
		t.Fatal(err)
	}
	var completedCommandID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM cache_operation_commands
		WHERE operation_id=$1 AND idempotency_key='guard-real-cancel'`, commandOperation.ID).
		Scan(&completedCommandID); err != nil {
		t.Fatal(err)
	}
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `UPDATE cache_operation_commands SET completed_at=$2 WHERE id=$1`,
			completedCommandID, cacheTestNow.Add(time.Second))
		return err
	}, "invalid cache operation command completion")
	expectDatabaseGuard(t, func() error {
		_, err := pool.Exec(ctx, `DELETE FROM cache_operation_commands WHERE id=$1`, completedCommandID)
		return err
	}, "invalid cache operation command completion")

	for _, table := range []struct {
		name string
		want string
	}{
		{"cache_policy_heads", "cache control tables cannot be truncated"},
		{"cache_policy_revisions", "cache control tables cannot be truncated"},
		{"cache_policy_write_requests", "cache control tables cannot be truncated"},
		{"cache_operations", "cache control tables cannot be truncated"},
		{"cache_operation_commands", "cache control tables cannot be truncated"},
		{"cache_operation_targets", "cache control tables cannot be truncated"},
		{"cache_operation_nodes", "cache control tables cannot be truncated"},
		{"cache_operation_node_targets", "cache control tables cannot be truncated"},
		{"cache_operation_node_attempts", "cache control tables cannot be truncated"},
		{"cache_operation_target_results", "cache control tables cannot be truncated"},
		// Since 094 audit_events_job_command_no_truncate_094 sorts (and fires)
		// before audit_events_no_truncate, so its message is the one raised.
		{"audit_events", "job command audit events cannot be truncated"},
	} {
		t.Run("truncate "+table.name, func(t *testing.T) {
			expectDatabaseGuard(t, func() error {
				_, err := pool.Exec(ctx, "TRUNCATE "+table.name+" CASCADE")
				return err
			}, table.want)
		})
	}
}

func TestCacheControlDeferredIntegrityRejectsForgedTerminalProjections(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "forged-terminal", 1)
	operation := createSimpleOperation(t, store, fixture, "forged-operation", 0, fixture.nodeIDs)
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	leaseID := uuid.New()
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_node_targets
		SET state='running',attempt=1 WHERE operation_id=$1 AND node_id=$2`,
		operation.ID, fixture.nodeIDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_nodes SET state='running',attempt=1,
		lease_id=$3,lease_owner='forged-worker',lease_expires_at=$4,next_attempt_at=NULL,
		updated_at=$5 WHERE operation_id=$1 AND node_id=$2`, operation.ID, fixture.nodeIDs[0],
		leaseID, cacheTestNow.Add(time.Minute), cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operations SET state='running',started_at=$2,updated_at=$2
		WHERE id=$1`, operation.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_node_targets SET state='succeeded',
		sequence=1,completed_at=$3 WHERE operation_id=$1 AND node_id=$2`,
		operation.ID, fixture.nodeIDs[0], cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_nodes SET state='succeeded',lease_id=NULL,
		lease_owner=NULL,lease_expires_at=NULL,completed_count=1,succeeded_count=1,
		failed_count=0,cancelled_count=0,updated_at=$3,completed_at=$3
		WHERE operation_id=$1 AND node_id=$2`, operation.ID, fixture.nodeIDs[0], cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operations SET state='succeeded',completed_count=1,
		succeeded_count=1,failed_count=0,cancelled_count=0,updated_at=$2,completed_at=$2
		WHERE id=$1`, operation.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "cache operation integrity violation") {
		t.Fatalf("forged terminal commit error=%v, want deferred integrity rejection", err)
	}

	stored, err := store.GetOperation(ctx, fixture.actor, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != StateQueued || stored.Progress.Completed != 0 || stored.Nodes[0].State != StateQueued {
		t.Fatalf("forged terminal transaction was not rolled back: %+v", stored)
	}
}

func TestCachePolicyHeadIntegrityGuards(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "policy-head-guards", 1)
	ctx := context.Background()

	for revision := int64(0); revision < 2; revision++ {
		if _, err := store.PublishPolicy(ctx, fixture.actor, PublishPolicyRequest{
			SiteID: fixture.siteID, ExpectedRevision: revision,
			Document:       validPolicyDocument(60 + revision),
			IdempotencyKey: fmt.Sprintf("policy-head-%d", revision+1),
			RequestID:      fmt.Sprintf("policy-head-request-%d", revision+1),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, query := range []string{
		`UPDATE cache_policy_heads SET current_revision=1 WHERE site_id=$1`,
		`UPDATE cache_policy_heads SET current_revision=999 WHERE site_id=$1`,
		`DELETE FROM cache_policy_heads WHERE site_id=$1`,
	} {
		expectDatabaseGuard(t, func() error {
			_, err := pool.Exec(ctx, query, fixture.siteID)
			return err
		}, "invalid cache policy head transition")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	forgedAt := cacheTestNow.Add(time.Second)
	if _, err = tx.Exec(ctx, `UPDATE cache_policy_heads
		SET current_revision=3,updated_at=$2 WHERE site_id=$1`, fixture.siteID, forgedAt); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1`,
		fixture.actor.ScopeID, forgedAt); err != nil {
		t.Fatal(err)
	}
	// The forged revision reuses revision 2's definition binding (migration 143)
	// so that only the deferred head integrity check can reject it.
	if _, err = tx.Exec(ctx, `INSERT INTO cache_policy_revisions (
		site_id,scope_id,tenant_id,revision,mode,rules,query_mode,query_names,vary_headers,
		disk_quota_bytes,request_digest,actor_scope_id,created_by_user_id,edge_source_revision,
		request_id,created_at,schema_version,binding_mode,definition_id,definition_revision
	) SELECT revision.site_id,revision.scope_id,revision.tenant_id,3,revision.mode,revision.rules,
		revision.query_mode,revision.query_names,revision.vary_headers,
		revision.disk_quota_bytes,revision.request_digest,revision.actor_scope_id,revision.created_by_user_id,
		edge_scope.source_revision,'forged-policy-head',$2,revision.schema_version,revision.binding_mode,
		revision.definition_id,revision.definition_revision
	  FROM cache_policy_revisions revision
	  JOIN edge_configuration_scopes edge_scope ON edge_scope.scope_id=revision.scope_id
	  WHERE revision.site_id=$1 AND revision.revision=2`, fixture.siteID, forgedAt); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "cache policy integrity violation") {
		t.Fatalf("unsupported policy head commit error=%v, want deferred integrity rejection", err)
	}

	var head, maximum, count int64
	if err := pool.QueryRow(ctx, `SELECT head.current_revision,max(revision.revision),count(*)
		FROM cache_policy_heads head JOIN cache_policy_revisions revision ON revision.site_id=head.site_id
		WHERE head.site_id=$1 GROUP BY head.current_revision`, fixture.siteID).Scan(&head, &maximum, &count); err != nil {
		t.Fatal(err)
	}
	if head != 2 || maximum != 2 || count != 2 {
		t.Fatalf("policy facts changed after forged head rollback: head=%d max=%d count=%d", head, maximum, count)
	}

	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		return audit.New(pool).Append(ctx, tx, audit.Event{
			ScopeID: fixture.actor.ScopeID, ActorUserID: &fixture.actor.UserID,
			Action: "cache_policy.publish", ResourceType: "cache_policy",
			ResourceID: fixture.siteID.String(), RequestID: "policy-head-request-2", Result: "success",
			Payload: map[string]any{"revision": 2, "mode": PolicyOverride},
		})
	}, "cache policy audit cannot be added without an unfinished matching write")
}

func TestCacheOperationReverseIntegrityGuards(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "operation-reverse-guards", 1)
	ctx := context.Background()

	leaseMismatch := createSimpleOperation(t, store, fixture, "lease-mismatch", 0, fixture.nodeIDs)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	nodeLeaseID, attemptLeaseID := uuid.New(), uuid.New()
	leaseExpiry := cacheTestNow.Add(time.Minute)
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_node_targets
		SET state='running',attempt=1 WHERE operation_id=$1 AND node_id=$2`,
		leaseMismatch.ID, fixture.nodeIDs[0]); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_nodes SET state='running',attempt=1,
		lease_id=$3,lease_owner='lease-node-worker',lease_expires_at=$4,next_attempt_at=NULL,updated_at=$5
		WHERE operation_id=$1 AND node_id=$2`, leaseMismatch.ID, fixture.nodeIDs[0],
		nodeLeaseID, leaseExpiry, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cache_operation_node_attempts (
		operation_id,scope_id,node_id,attempt,lease_id,worker_id,state,target_count,started_at,lease_expires_at
	) VALUES ($1,$2,$3,1,$4,'lease-attempt-worker','running',1,$5,$6)`,
		leaseMismatch.ID, fixture.actor.ScopeID, fixture.nodeIDs[0], attemptLeaseID,
		cacheTestNow, leaseExpiry); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operations
		SET state='running',started_at=$2,updated_at=$2 WHERE id=$1`, leaseMismatch.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = store.appendAudit(ctx, tx, fixture.actor.ScopeID, nil,
		"cache.operation.claim", leaseMismatch.ID, "lease-mismatch-claim", map[string]any{
			"node_id": fixture.nodeIDs[0], "attempt": 1,
			"lease_id": attemptLeaseID, "target_count": 1,
		}); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "cache operation integrity violation") {
		t.Fatalf("mismatched running lease commit error=%v, want deferred integrity rejection", err)
	}
	if cancelled, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: leaseMismatch.ID, IdempotencyKey: "lease-mismatch-cleanup",
		RequestID: "lease-mismatch-cleanup-request",
	}); err != nil || cancelled.Operation.State != StateCancelled {
		t.Fatalf("close rolled-back lease fixture: result=%+v err=%v", cancelled, err)
	}

	stuckRunning := createSimpleOperation(t, store, fixture, "stuck-running", 0, fixture.nodeIDs)
	claim := claimForNodes(t, store, fixture.actor.ScopeID, "stuck-worker", fixture.nodeIDs, 1, "stuck-claim")[0]
	if claim.OperationID != stuckRunning.ID {
		t.Fatalf("claimed operation=%s, want stuck operation=%s", claim.OperationID, stuckRunning.ID)
	}
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = store.appendAudit(ctx, tx, fixture.actor.ScopeID, nil,
			"cache.operation.claim", stuckRunning.ID, "stuck-duplicate-claim", map[string]any{
				"node_id": claim.NodeID, "attempt": claim.Attempt,
				"lease_id": claim.LeaseID, "target_count": len(claim.Targets),
			})
		return err
	}, "cache operation terminal audit cannot be added after completion")
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	reportDigest := make([]byte, 32)
	reportDigest[0] = 1
	auditEventID, err := store.appendAudit(ctx, tx, fixture.actor.ScopeID, nil,
		"cache.operation.report", stuckRunning.ID, "stuck-report", map[string]any{
			"node_id": claim.NodeID, "attempt": claim.Attempt, "sequence": 1, "state": StateSucceeded,
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO cache_operation_target_results (
		id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,sequence,
		report_digest,audit_event_id,created_at
	) VALUES ($1,$2,$3,$4,1,1,'report','succeeded',1,$5,$6,$7)`, uuid.New(),
		stuckRunning.ID, fixture.actor.ScopeID, claim.NodeID, reportDigest, auditEventID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_node_targets
		SET state='succeeded',sequence=1,completed_at=$3 WHERE operation_id=$1 AND node_id=$2`,
		stuckRunning.ID, claim.NodeID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_node_attempts
		SET state='succeeded',report_sequence=1,report_digest=$3,completed_at=$4
		WHERE operation_id=$1 AND node_id=$2 AND attempt=1`,
		stuckRunning.ID, claim.NodeID, reportDigest, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_nodes SET state='succeeded',lease_id=NULL,
		lease_owner=NULL,lease_expires_at=NULL,completed_count=1,succeeded_count=1,
		updated_at=$3,completed_at=$3 WHERE operation_id=$1 AND node_id=$2`,
		stuckRunning.ID, claim.NodeID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operations
		SET completed_count=1,succeeded_count=1,updated_at=$2 WHERE id=$1`, stuckRunning.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "completed projections require a terminal operation") {
		t.Fatalf("stuck running commit error=%v, want reverse terminal rejection", err)
	}

	stuckRetry := createSimpleOperation(t, store, fixture, "stuck-retry", 0, fixture.nodeIDs)
	retryClaim := claimForNodes(t, store, fixture.actor.ScopeID, "retry-worker", fixture.nodeIDs, 1, "retry-claim")[0]
	if retryClaim.OperationID != stuckRetry.ID {
		t.Fatalf("claimed operation=%s, want retry operation=%s", retryClaim.OperationID, stuckRetry.ID)
	}
	failed, err := store.Report(ctx,
		reportRequest(retryClaim, "retry-worker", 1, "retry-report", []ItemState{ItemFailed}))
	if err != nil || failed.Operation.State != StateFailed {
		t.Fatalf("prepare failed operation: result=%+v err=%v", failed, err)
	}
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	commandID := uuid.New()
	commandDigest := make([]byte, 32)
	if _, err = tx.Exec(ctx, `INSERT INTO cache_operation_commands (
		id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
	) VALUES ($1,$2,$3,$3,'retry','stuck-retry-command',$4,$5,$6)`, commandID,
		stuckRetry.ID, fixture.actor.ScopeID, commandDigest, fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operations
		SET state='queued',completed_at=NULL,updated_at=$2 WHERE id=$1`, stuckRetry.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = store.appendAudit(ctx, tx, fixture.actor.ScopeID, &fixture.actor.UserID,
		"cache.operation.retry", stuckRetry.ID, "stuck-retry-audit",
		map[string]any{"command_id": commandID, "node_count": 0}); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE cache_operation_commands SET completed_at=$2 WHERE id=$1`,
		commandID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	err = tx.Commit(ctx)
	if err == nil || !strings.Contains(err.Error(), "cache operation integrity violation") {
		t.Fatalf("stuck retry commit error=%v, want deferred integrity rejection", err)
	}
}

func TestDuplicateCommandsCannotShareEffectGeneration(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "duplicate-command-effects", 1)
	ctx := context.Background()
	digest := make([]byte, 32)

	cancelOperation := createSimpleOperation(t, store, fixture, "duplicate-cancel", 0, fixture.nodeIDs)
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		firstCommandID := uuid.New()
		if _, err = tx.Exec(ctx, `INSERT INTO cache_operation_commands (
			id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
		) VALUES ($1,$2,$3,$3,'cancel','duplicate-cancel-1',$4,$5,$6)`, firstCommandID,
			cancelOperation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow); err != nil {
			return err
		}
		if _, err = store.appendAudit(ctx, tx, fixture.actor.ScopeID, &fixture.actor.UserID,
			"cache.operation.cancel", cancelOperation.ID, "duplicate-cancel-audit-1",
			map[string]any{"command_id": firstCommandID, "cancelled_nodes": 1}); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE cache_operation_commands SET completed_at=$2 WHERE id=$1`,
			firstCommandID, cacheTestNow); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO cache_operation_commands (
			id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
		) VALUES ($1,$2,$3,$3,'cancel','duplicate-cancel-2',$4,$5,$6)`, uuid.New(),
			cancelOperation.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow)
		return err
	}, "cache operation command already exists for current effect")
	if cancelled, err := store.Cancel(ctx, fixture.actor, CancelRequest{
		OperationID: cancelOperation.ID, IdempotencyKey: "duplicate-cancel-real",
		RequestID: "duplicate-cancel-real-request",
	}); err != nil || cancelled.Operation.State != StateCancelled {
		t.Fatalf("cancel after duplicate rollback: result=%+v err=%v", cancelled, err)
	}

	concurrentCancel := createSimpleOperation(t, store, fixture, "concurrent-cancel", 0, fixture.nodeIDs)
	firstTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstTx.Rollback(context.Background()) }()
	firstCommandID := uuid.New()
	if _, err = firstTx.Exec(ctx, `INSERT INTO cache_operation_commands (
		id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
	) VALUES ($1,$2,$3,$3,'cancel','concurrent-cancel-1',$4,$5,$6)`, firstCommandID,
		concurrentCancel.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	secondCommandResult := make(chan error, 1)
	go func() {
		_, err := pool.Exec(ctx, `INSERT INTO cache_operation_commands (
			id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
		) VALUES ($1,$2,$3,$3,'cancel','concurrent-cancel-2',$4,$5,$6)`, uuid.New(),
			concurrentCancel.ID, fixture.actor.ScopeID, digest, fixture.actor.UserID, cacheTestNow)
		secondCommandResult <- err
	}()
	select {
	case err := <-secondCommandResult:
		t.Fatalf("concurrent command did not wait for operation lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	auditEventID, err := store.appendAudit(ctx, firstTx, fixture.actor.ScopeID, &fixture.actor.UserID,
		"cache.operation.cancel", concurrentCancel.ID, "concurrent-cancel-audit",
		map[string]any{"command_id": firstCommandID, "cancelled_nodes": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `INSERT INTO cache_operation_target_results (
		id,operation_id,scope_id,node_id,target_ordinal,attempt,source,state,sequence,error_code,
		command_id,audit_event_id,created_at
	) VALUES ($1,$2,$3,$4,1,NULL,'cancel','cancelled',0,'cancelled',$5,$6,$7)`, uuid.New(),
		concurrentCancel.ID, fixture.actor.ScopeID, fixture.nodeIDs[0], firstCommandID,
		auditEventID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `UPDATE cache_operation_node_targets
		SET state='cancelled',error_code='cancelled',completed_at=$3
		WHERE operation_id=$1 AND node_id=$2`, concurrentCancel.ID, fixture.nodeIDs[0], cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `UPDATE cache_operation_nodes SET state='cancelled',
		next_attempt_at=NULL,completed_count=1,cancelled_count=1,last_error_code='cancelled',
		updated_at=$3,completed_at=$3 WHERE operation_id=$1 AND node_id=$2`,
		concurrentCancel.ID, fixture.nodeIDs[0], cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `UPDATE cache_operation_commands SET completed_at=$2 WHERE id=$1`,
		firstCommandID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err = firstTx.Exec(ctx, `UPDATE cache_operations SET state='cancelled',cancel_requested_at=$2,
		completed_count=1,cancelled_count=1,updated_at=$2,completed_at=$2 WHERE id=$1`,
		concurrentCancel.ID, cacheTestNow); err != nil {
		t.Fatal(err)
	}
	if err = firstTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondCommandResult:
		if err == nil || !strings.Contains(err.Error(), "cache operation commands must be inserted unfinished") {
			t.Fatalf("concurrent duplicate command error=%v, want state rejection", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent duplicate command remained blocked after first commit")
	}
	var concurrentCommandCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cache_operation_commands
		WHERE operation_id=$1 AND command='cancel'`, concurrentCancel.ID).Scan(&concurrentCommandCount); err != nil {
		t.Fatal(err)
	}
	if concurrentCommandCount != 1 {
		t.Fatalf("concurrent cancel command count=%d, want 1", concurrentCommandCount)
	}

	retryOperation := createSimpleOperation(t, store, fixture, "duplicate-retry", 2, fixture.nodeIDs)
	firstClaim := claimForNodes(t, store, fixture.actor.ScopeID, "duplicate-retry-worker-1",
		fixture.nodeIDs, 1, "duplicate-retry-claim-1")[0]
	firstFailure, err := store.Report(ctx, reportRequest(firstClaim, "duplicate-retry-worker-1", 1,
		"duplicate-retry-report-1", []ItemState{ItemFailed}))
	if err != nil || firstFailure.Operation.State != StateFailed {
		t.Fatalf("prepare first retry generation: result=%+v err=%v", firstFailure, err)
	}
	expectDatabaseGuard(t, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		for index := 1; index <= 2; index++ {
			if _, err = tx.Exec(ctx, `INSERT INTO cache_operation_commands (
				id,operation_id,scope_id,actor_scope_id,command,idempotency_key,request_digest,actor_user_id,created_at
			) VALUES ($1,$2,$3,$3,'retry',$4,$5,$6,$7)`, uuid.New(), retryOperation.ID,
				fixture.actor.ScopeID, fmt.Sprintf("duplicate-retry-direct-%d", index),
				digest, fixture.actor.UserID, cacheTestNow); err != nil {
				return err
			}
		}
		return nil
	}, "cache operation command already exists for current effect")

	for attempt := uint32(1); attempt <= 2; attempt++ {
		if _, err := store.Retry(ctx, fixture.actor, RetryRequest{
			OperationID:    retryOperation.ID,
			IdempotencyKey: fmt.Sprintf("duplicate-retry-real-%d", attempt),
			RequestID:      fmt.Sprintf("duplicate-retry-real-request-%d", attempt),
		}); err != nil {
			t.Fatalf("retry generation %d: %v", attempt, err)
		}
		claim := claimForNodes(t, store, fixture.actor.ScopeID,
			fmt.Sprintf("duplicate-retry-worker-%d", attempt+1), fixture.nodeIDs, 1,
			fmt.Sprintf("duplicate-retry-claim-%d", attempt+1))[0]
		state := ItemFailed
		if attempt == 2 {
			state = ItemSucceeded
		}
		result, err := store.Report(ctx, reportRequest(claim,
			fmt.Sprintf("duplicate-retry-worker-%d", attempt+1), 1,
			fmt.Sprintf("duplicate-retry-report-%d", attempt+1), []ItemState{state}))
		want := StateFailed
		if attempt == 2 {
			want = StateSucceeded
		}
		if err != nil || result.Operation.State != want {
			t.Fatalf("retry generation %d result=%+v err=%v", attempt, result, err)
		}
	}
}

func TestTerminalProjectionCannotRegressToPriorAttemptResult(t *testing.T) {
	pool := openCacheTestDatabase(t, true)
	store := mustCacheStore(t, pool, func() time.Time { return cacheTestNow })
	fixture := seedCacheFixture(t, pool, "terminal-regression", 1)
	created, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{
			"http://" + fixture.domain + "/one",
			"http://" + fixture.domain + "/two",
			"http://" + fixture.domain + "/three",
		},
		NodeIDs: fixture.nodeIDs, MaxRetries: 1,
		IdempotencyKey: "terminal-regression", RequestID: "terminal-regression-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	first := claimForNodes(t, store, fixture.actor.ScopeID, "terminal-worker-1",
		fixture.nodeIDs, 1, "terminal-claim-1")[0]
	firstResult, err := store.Report(context.Background(),
		reportRequest(first, "terminal-worker-1", 1, "terminal-report-1",
			[]ItemState{ItemSucceeded, ItemFailed, ItemFailed}))
	if err != nil || firstResult.Operation.State != StatePartialFailed {
		t.Fatalf("first partial result=%+v err=%v", firstResult, err)
	}
	if _, err := store.Retry(context.Background(), fixture.actor, RetryRequest{
		OperationID: created.Operation.ID, IdempotencyKey: "terminal-retry",
		RequestID: "terminal-retry-request",
	}); err != nil {
		t.Fatal(err)
	}
	second := claimForNodes(t, store, fixture.actor.ScopeID, "terminal-worker-2",
		fixture.nodeIDs, 1, "terminal-claim-2")[0]
	secondResult, err := store.Report(context.Background(),
		reportRequest(second, "terminal-worker-2", 1, "terminal-report-2",
			[]ItemState{ItemSucceeded, ItemFailed}))
	if err != nil || secondResult.Operation.State != StatePartialFailed {
		t.Fatalf("second partial result=%+v err=%v", secondResult, err)
	}

	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	_, err = tx.Exec(ctx, `UPDATE cache_operation_node_targets
		SET state='failed',attempt=1,sequence=1,error_code='node_failure',completed_at=$4
		WHERE operation_id=$1 AND node_id=$2 AND target_ordinal=$3`,
		created.Operation.ID, fixture.nodeIDs[0], 2, cacheTestNow)
	if err == nil || !strings.Contains(err.Error(), "invalid cache operation target transition") {
		t.Fatalf("terminal projection regression error=%v, want transition rejection", err)
	}
	_ = tx.Rollback(ctx)

	stored, err := store.GetOperation(ctx, fixture.actor, created.Operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Nodes[0].Targets[1].State != ItemSucceeded || stored.Nodes[0].Targets[1].Attempt != 2 {
		t.Fatalf("terminal projection regressed despite rollback: %+v", stored.Nodes[0].Targets[1])
	}
}

type cacheFixture struct {
	actor      Actor
	tenantID   uuid.UUID
	siteID     uuid.UUID
	roleID     uuid.UUID
	readRoleID uuid.UUID
	domain     string
	nodeIDs    []uuid.UUID
}

func seedCacheFixture(t *testing.T, pool *pgxpool.Pool, slug string, nodeCount int) cacheFixture {
	t.Helper()
	ctx := context.Background()
	fixture := cacheFixture{
		actor:    Actor{UserID: uuid.New(), ScopeID: uuid.New()},
		tenantID: uuid.New(), siteID: uuid.New(), roleID: uuid.New(), readRoleID: uuid.New(),
	}
	fixture.actor.ActorScopeID = fixture.actor.ScopeID
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id,display_name,status) VALUES ($1,$2,'active')`,
		fixture.tenantID, "Cache "+slug); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes (id,kind,tenant_id) VALUES ($1,'tenant',$2)`,
		fixture.actor.ScopeID, fixture.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,username,display_name,password_hash,status)
		VALUES ($1,$2,$3,'test-hash','active')`, fixture.actor.UserID,
		"cache-"+slug, "Cache "+slug); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships (scope_id,user_id,status) VALUES ($1,$2,'active')`,
		fixture.actor.ScopeID, fixture.actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles (id,scope_id,name,description,system_role)
		VALUES ($1,$2,$3,'cache control integration manage role',true),
		       ($4,$2,$5,'cache control integration read role',true)`, fixture.roleID,
		fixture.actor.ScopeID, "cache-manage-role-"+slug, fixture.readRoleID,
		"cache-read-role-"+slug); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions (role_id,permission_name)
		VALUES ($1,'sites.manage'),($2,'sites.read')`, fixture.roleID, fixture.readRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (scope_id,user_id,role_id)
		VALUES ($1,$2,$3),($1,$2,$4)`, fixture.actor.ScopeID, fixture.actor.UserID,
		fixture.roleID, fixture.readRoleID); err != nil {
		t.Fatal(err)
	}
	fixture.domain = slug + ".example"
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// display_id is required from migration 210 on; earlier schemas lack it.
		displayColumn, displayValue := "", ""
		if hasDisplayID(t, pool, "sites") {
			displayColumn, displayValue = ",display_id", ",(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2)"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sites (
				id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,created_by_user_id,updated_by_user_id`+displayColumn+`
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,true,'active',$3,$3`+displayValue+`)`,
			fixture.siteID, fixture.actor.ScopeID, fixture.actor.UserID, fixture.domain,
			[]string{"80", "8080"}, []string{"443"}, []string{"192.0.2.1"}, []string{"192.0.2.1"}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools (site_id) VALUES ($1)`, fixture.siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO site_origins (site_id,position,host,port,weight,enabled)
			VALUES ($1,1,'192.0.2.1',80,1,true)`, fixture.siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < nodeCount; index++ {
		nodeID := uuid.New()
		fixture.nodeIDs = append(fixture.nodeIDs, nodeID)
		insertCacheNode(t, pool, nodeID, fixture.actor.ScopeID, fixture.actor.UserID,
			fmt.Sprintf("%s-node-%d", slug, index))
	}
	return fixture
}

// insertCacheNode inserts an active node; display_id is required from
// migration 211 on and is allocated per scope.
func insertCacheNode(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID, userID uuid.UUID, name string) {
	t.Helper()
	displayColumn, displayValue := "", ""
	if hasDisplayID(t, pool, "nodes") {
		displayColumn, displayValue = ",display_id", ",(SELECT COALESCE(max(display_id),0)+1 FROM nodes WHERE scope_id=$2)"
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO nodes (id,scope_id,name,admin_state,created_by_user_id`+displayColumn+`)
		VALUES ($1,$2,$3,'active',$4`+displayValue+`)`, nodeID, scopeID, name, userID); err != nil {
		t.Fatal(err)
	}
}

func hasDisplayID(t *testing.T, pool *pgxpool.Pool, table string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name=$1 AND column_name='display_id')`,
		table).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func seedCacheActor(t *testing.T, pool *pgxpool.Pool, fixture cacheFixture, slug string) Actor {
	t.Helper()
	actor := Actor{
		UserID: uuid.New(), ScopeID: fixture.actor.ScopeID, ActorScopeID: fixture.actor.ScopeID,
	}
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash,status)
		VALUES($1,$2,$3,'test-hash','active')`, actor.UserID, slug+"-"+uuid.NewString(), slug); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, actor.ScopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3),($1,$2,$4)`, actor.ScopeID, actor.UserID,
		fixture.roleID, fixture.readRoleID); err != nil {
		t.Fatal(err)
	}
	return actor
}

func assertIdempotencyFactCounts(
	t *testing.T,
	pool *pgxpool.Pool,
	wantFacts, wantAudits int,
	query string,
	arguments ...any,
) {
	t.Helper()
	var factCount, auditCount int
	if err := pool.QueryRow(context.Background(), query, arguments...).Scan(&factCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	if factCount != wantFacts || auditCount != wantAudits {
		t.Fatalf("idempotency facts=%d audits=%d, want %d/%d",
			factCount, auditCount, wantFacts, wantAudits)
	}
}

func validPolicyDocument(ttl int64) PolicyDocument {
	return PolicyDocument{
		Mode:      PolicyOverride,
		Rules:     []Rule{{Order: 1, Extensions: []string{".css"}, StatusCodes: []int{200}, TTLSeconds: ttl}},
		QueryMode: QueryPreserve, VaryHeaders: []string{"Accept-Encoding"},
		DiskQuotaBytes: minDiskQuotaBytes,
	}
}

func validPolicyV2Document(ttl, browserTTL int64) PolicyDocument {
	return PolicyDocument{
		SchemaVersion: PolicySchemaV2,
		Mode:          PolicyOverride,
		Rules: []Rule{{
			Order: 1, Extensions: []string{".js"}, StatusCodes: []int{200},
			Action: RuleActionCache, TTLSeconds: ttl, BrowserTTLSeconds: browserTTL,
		}, {
			Order: 2, PathPrefix: "/private/", Action: RuleActionNoCache,
		}},
		QueryMode: QueryPreserve, QueryNames: []string{},
		VaryHeaders: []string{"accept-encoding"}, DiskQuotaBytes: minDiskQuotaBytes,
	}
}

func createSimpleOperation(
	t *testing.T,
	store *Store,
	fixture cacheFixture,
	key string,
	maxRetries uint32,
	nodeIDs []uuid.UUID,
) Operation {
	t.Helper()
	result, err := store.CreateOperation(context.Background(), fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/" + key},
		NodeIDs: nodeIDs, MaxRetries: maxRetries, IdempotencyKey: key, RequestID: key + "-request",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Operation
}

func authorizeWriteProbe(
	ctx context.Context,
	store *Store,
	fixture cacheFixture,
	key string,
) (OperationWriteResult, error) {
	return store.CreateOperation(ctx, fixture.actor, CreateOperationRequest{
		SiteID: fixture.siteID, Action: ActionPurge, TargetType: TargetExactURL,
		Targets: []string{"http://" + fixture.domain + "/" + key}, NodeIDs: fixture.nodeIDs,
		IdempotencyKey: key, RequestID: key + "-request",
	})
}

func claimForNodes(
	t *testing.T,
	store *Store,
	scopeID uuid.UUID,
	worker string,
	nodeIDs []uuid.UUID,
	limit int,
	requestID string,
) []Claim {
	t.Helper()
	claims, err := store.Claim(context.Background(), ClaimRequest{
		ScopeID: scopeID, WorkerID: worker, OnlineNodeIDs: nodeIDs,
		Limit: limit, LeaseDuration: time.Minute, RequestID: requestID,
	})
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func reportRequest(claim Claim, worker string, sequence uint64, requestID string, states []ItemState) ReportRequest {
	results := make([]TargetResult, len(claim.Targets))
	for index, target := range claim.Targets {
		state := states[index]
		results[index] = TargetResult{TargetOrdinal: target.Ordinal, State: state}
		if state == ItemFailed {
			results[index].ErrorCode = "node_failure"
		}
	}
	return ReportRequest{
		ScopeID: claim.ScopeID, OperationID: claim.OperationID, NodeID: claim.NodeID,
		WorkerID: worker, LeaseID: claim.LeaseID, Attempt: claim.Attempt,
		Sequence: sequence, Results: results, RequestID: requestID,
	}
}

type testClock struct {
	mu    sync.Mutex
	value time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.value
}

func (clock *testClock) Add(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.value = clock.value.Add(duration)
}

type failingAuditor struct{}

func (failingAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("injected audit failure")
}

type failingEntitlementDenialAuditor struct {
	mu      sync.Mutex
	auditor *audit.Log
	failure error
	calls   int
}

func (checker *failingEntitlementDenialAuditor) CheckSiteChange(
	ctx context.Context,
	tx pgx.Tx,
	check entitlementguard.SiteCheck,
) error {
	checker.mu.Lock()
	checker.calls++
	call := checker.calls
	checker.mu.Unlock()
	if call > 1 {
		return checker.failure
	}
	if err := checker.auditor.Append(ctx, tx, audit.Event{
		ScopeID: check.AuditScopeID, ActorUserID: &check.ActorUserID,
		Action: "entitlement.guard.reject", ResourceType: "site",
		ResourceID: check.ResourceID.String(), RequestID: check.RequestID, Result: "denied",
		Payload: map[string]any{"operation": check.Operation, "reason": "injected_denial"},
	}); err != nil {
		return err
	}
	return entitlementguard.ErrFeatureDenied
}

func (checker *failingEntitlementDenialAuditor) callCount() int {
	checker.mu.Lock()
	defer checker.mu.Unlock()
	return checker.calls
}

type cacheControlStepUp struct{}

func (cacheControlStepUp) VerifyAndConsume(
	context.Context,
	pgx.Tx,
	rbacmanager.StepUpProof,
	rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	return rbacmanager.StepUpEvidence{
		ProofID: uuid.New(), Method: "totp", VerifiedAt: cacheTestNow,
	}, nil
}

func cacheRBACMutation(key string) rbacmanager.MutationContext {
	return rbacmanager.MutationContext{
		IdempotencyKey: key, RequestID: key + "-request", TraceID: key + "-trace",
	}
}

func expectDatabaseGuard(t *testing.T, operation func() error, message string) {
	t.Helper()
	err := operation()
	if err == nil || !strings.Contains(err.Error(), message) {
		t.Fatalf("database guard err=%v, want message containing %q", err, message)
	}
}

func mustCacheStore(t *testing.T, pool *pgxpool.Pool, clock func() time.Time) *Store {
	t.Helper()
	store, err := NewStore(pool, clock)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

// openCacheTestDatabase returns an empty schema, or with migrate a schema at
// the release head (a clone of TEST_DATABASE_TEMPLATE when it is set).
func openCacheTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if migrate {
		if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
			return pool
		}
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "cachecontrol_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^cachecontrol_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop cache control schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatalf("migrate cache control schema: %v", err)
		}
	}
	return pool
}

func assertCacheMigration(t *testing.T, pool *pgxpool.Pool, version int64, exists bool) {
	t.Helper()
	actual := cacheMigrationVersion(t, pool)
	if actual != version {
		t.Fatalf("migration version=%d, want %d", actual, version)
	}
	assertCacheTables(t, pool, exists)
}

func assertCacheTables(t *testing.T, pool *pgxpool.Pool, exists bool) {
	t.Helper()
	for _, table := range []string{
		"cache_policy_heads", "cache_policy_revisions", "cache_policy_write_requests",
		"cache_operations", "cache_operation_commands", "cache_operation_targets",
		"cache_operation_nodes", "cache_operation_node_targets", "cache_operation_node_attempts",
		"cache_operation_target_results",
	} {
		var actualExists bool
		if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&actualExists); err != nil {
			t.Fatal(err)
		}
		if actualExists != exists {
			t.Fatalf("table %s exists=%t, want %t", table, actualExists, exists)
		}
	}
}

func assertCacheMigrationBelow(t *testing.T, pool *pgxpool.Pool, ceiling int64, exists bool) {
	t.Helper()
	actual := cacheMigrationVersion(t, pool)
	if actual >= ceiling {
		t.Fatalf("migration version=%d, want below %d", actual, ceiling)
	}
	assertCacheTables(t, pool, exists)
}

func cacheMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var actual int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	return actual
}

type cacheMigration struct {
	version int64
	name    string
}

func migrateCacheThrough34(t *testing.T, pool *pgxpool.Pool) {
	migrateCacheThrough(t, pool, 34)
}

func migrateCacheThrough(t *testing.T, pool *pgxpool.Pool, ceiling int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var items []cacheMigration
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		underscore := strings.IndexByte(name, '_')
		if underscore < 1 {
			t.Fatalf("invalid migration name %q", name)
		}
		version, err := strconv.ParseInt(name[:underscore], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version <= ceiling {
			items = append(items, cacheMigration{version: version, name: name})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].version < items[j].version })
	for _, item := range items {
		var applied bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM schema_migrations WHERE version=$1
		)`, item.version).Scan(&applied); err != nil {
			t.Fatal(err)
		}
		if applied {
			continue
		}
		applyCacheMigrationFile(t, pool, item.name, item.version, true)
	}
}

func applyCacheMigrationFile(t *testing.T, pool *pgxpool.Pool, name string, version int64, up bool) {
	t.Helper()
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if up {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, version)
		}
		return err
	}); err != nil {
		t.Fatalf("apply migration file %s: %v", name, err)
	}
}
