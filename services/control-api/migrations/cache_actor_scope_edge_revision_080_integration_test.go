//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var cache080Now = time.Date(2026, 7, 29, 2, 0, 0, 0, time.UTC)

type cache080Fixture struct {
	tenantID, scopeID, actorUserID uuid.UUID
	siteID, secondSiteID, nodeID   uuid.UUID
	domain                         string
}

// migrateCache080Up applies 080 with only migrations 1..080 loaded. Going to
// the release head and rolling back would cross migration 268's one-way down
// gate (P2682).
func migrateCache080Up(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if err := migrateVersionIsolated(t.Context(), pool, "up", 80); err != nil {
		t.Fatalf("apply migrations through 080: %v", err)
	}
	var current int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != 80 {
		t.Fatalf("migration version=%d want 80", current)
	}
}

func TestCacheActorScopeEdgeRevision080PlatformFactsAndGuards(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 79)
	migrateCache080Up(t, pool)
	// Today's audit.Append writes the columns of migration 361 (unified log).
	databasetest.AddUnifiedAuditColumns(t, pool)
	fixture := seedCache080Fixture(t, pool, "platform")
	platformScopeID, platformUserID := seedCache080PlatformActor(t, pool, "primary")
	_, secondPlatformUserID := seedCache080PlatformActorInScope(t, pool, platformScopeID, "secondary")
	assertCache080NewConstraints(t, pool)

	firstRevision, firstEdge, err := insertCache080Policy(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		"shared-policy-key", "platform-policy-1", true,
	)
	if err != nil || firstRevision != 1 {
		t.Fatalf("insert platform policy revision=%d edge=%d err=%v", firstRevision, firstEdge, err)
	}
	secondRevision, secondEdge, err := insertCache080Policy(
		t.Context(), pool, fixture, platformScopeID, secondPlatformUserID,
		"shared-policy-key", "platform-policy-2", true,
	)
	if err != nil || secondRevision != 2 || secondEdge != firstEdge+1 {
		t.Fatalf("second actor policy revision/edge=%d/%d want 2/%d err=%v",
			secondRevision, secondEdge, firstEdge+1, err)
	}
	assertCache080Code(t, insertCache080UnfinishedPolicyRequest(
		t.Context(), pool, fixture.siteID, fixture.scopeID, platformScopeID,
		platformUserID, "shared-policy-key",
	), "23505")

	firstOperation, err := insertCache080QueuedOperation(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		"shared-operation-key", "platform-operation-1", true,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insertCache080QueuedOperation(
		t.Context(), pool, fixture, platformScopeID, secondPlatformUserID,
		"shared-operation-key", "platform-operation-2", true,
	); err != nil {
		t.Fatalf("same target/key for a different actor identity: %v", err)
	}
	assertCache080Code(t, insertCache080BareOperation(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		"shared-operation-key",
	), "23505")
	assertCache080Code(t, insertCache080BareOperation(
		t.Context(), pool, fixture, fixture.scopeID, platformUserID,
		"wrong-membership-operation",
	), "23503")
	assertCache080CommandActorMembership(t, pool, fixture, firstOperation, platformScopeID, platformUserID)

	beforeRejectedEdge := cache080EdgeHead(t, pool, fixture.scopeID)
	_, _, err = insertCache080Policy(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		"wrong-policy-audit", "wrong-policy-audit-request", false,
	)
	assertCache080Code(t, err, "P8002")
	if after := cache080EdgeHead(t, pool, fixture.scopeID); after != beforeRejectedEdge {
		t.Fatalf("rejected policy advanced edge head from %d to %d", beforeRejectedEdge, after)
	}
	var rejectedFacts int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM cache_policy_write_requests WHERE idempotency_key='wrong-policy-audit') +
		(SELECT count(*) FROM cache_policy_revisions WHERE request_id='wrong-policy-audit-request') +
		(SELECT count(*) FROM audit_events WHERE request_id='wrong-policy-audit-request')`).Scan(&rejectedFacts); err != nil {
		t.Fatal(err)
	}
	if rejectedFacts != 0 {
		t.Fatalf("rejected policy left %d facts", rejectedFacts)
	}
	if _, err := insertCache080QueuedOperation(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		"wrong-operation-audit", "wrong-operation-audit-request", false,
	); err == nil {
		t.Fatal("operation with mismatched actor-scope audit committed")
	} else {
		assertCache080Code(t, err, "P8004")
	}

	assertCache080Code(t, insertCache080RevisionAtEdge(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		cache080EdgeHead(t, pool, fixture.scopeID)+1,
	), "P8005")
	assertCache080Code(t, insertCache080DuplicateEdgeRevision(
		t.Context(), pool, fixture, platformScopeID, platformUserID,
		cache080EdgeHead(t, pool, fixture.scopeID),
	), "23505")
	assertCache080Code(t, func() error {
		_, err := pool.Exec(t.Context(), `UPDATE cache_operations SET actor_scope_id=$2 WHERE id=$1`,
			firstOperation, fixture.scopeID)
		return err
	}(), "P8001")
	if _, err := pool.Exec(t.Context(), `UPDATE cache_policy_revisions
		SET edge_source_revision=edge_source_revision+1 WHERE site_id=$1 AND revision=1`,
		fixture.siteID); err == nil {
		t.Fatal("immutable cache policy edge source revision accepted an update")
	}

	assertCache080Code(t, migrateVersionIsolated(t.Context(), pool, "down", 80), "P8009")
	assertPackageCommerceRBAC079Ledger(t, pool, 80)
	assertCache080Columns(t, pool, true)
	var platformFacts int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM cache_policy_revisions WHERE actor_scope_id=$1) +
		(SELECT count(*) FROM cache_operations WHERE actor_scope_id=$1)`, platformScopeID).Scan(&platformFacts); err != nil {
		t.Fatal(err)
	}
	if platformFacts < 4 {
		t.Fatalf("rejected down lost platform facts: count=%d", platformFacts)
	}
}

func seedCache080Fixture(t *testing.T, pool *pgxpool.Pool, slug string) cache080Fixture {
	t.Helper()
	fixture := cache080Fixture{
		tenantID: uuid.New(), scopeID: uuid.New(), actorUserID: uuid.New(),
		siteID: uuid.New(), secondSiteID: uuid.New(), nodeID: uuid.New(),
		domain: slug + "-0.example",
	}
	roleID := uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name,status) VALUES($1,$2,'active')`,
			[]any{fixture.tenantID, "Cache 080 " + slug}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
			[]any{fixture.scopeID, fixture.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,status)
			VALUES($1,$2,$3,'test-hash','active')`,
			[]any{fixture.actorUserID, "cache-080-" + slug + "-" + uuid.NewString(), "Cache 080 " + slug}},
		{`INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`,
			[]any{fixture.scopeID, fixture.actorUserID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role)
			VALUES($1,$2,'tenant_owner','cache 080 owner role',true)`,
			[]any{roleID, fixture.scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'sites.read'),($1,'sites.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`,
			[]any{fixture.scopeID, fixture.actorUserID, roleID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for index, siteID := range []uuid.UUID{fixture.siteID, fixture.secondSiteID} {
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
				id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
				https_enabled,enabled,status,created_by_user_id,updated_by_user_id
			) VALUES($1,$2,$3,$4,ARRAY['80'],ARRAY[]::text[],ARRAY['192.0.2.1'],
				ARRAY['192.0.2.1'],false,true,'active',$3,$3)`, siteID, fixture.scopeID,
				fixture.actorUserID, fmt.Sprintf("%s-%d.example", slug, index)); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
				return err
			}
			_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(
				site_id,position,host,port,weight,enabled
			) VALUES($1,1,'192.0.2.1',80,1,true)`, siteID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(
		id,scope_id,name,admin_state,created_by_user_id
	) VALUES($1,$2,$3,'active',$4)`, fixture.nodeID, fixture.scopeID,
		"cache-080-node-"+slug, fixture.actorUserID); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func seedCache080PlatformActor(t *testing.T, pool *pgxpool.Pool, slug string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	scopeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	return seedCache080PlatformActorInScope(t, pool, scopeID, slug)
}

func seedCache080PlatformActorInScope(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID uuid.UUID,
	slug string,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	userID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(
		id,username,display_name,password_hash,status
	) VALUES($1,$2,$3,'test-hash','active')`, userID,
		"cache-080-platform-"+slug+"-"+uuid.NewString(), "Cache 080 platform "+slug); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func cache080PolicyDocument(ttl int64) cachecontrol.PolicyDocument {
	return cachecontrol.PolicyDocument{
		Mode:      cachecontrol.PolicyOverride,
		Rules:     []cachecontrol.Rule{{Order: 1, Extensions: []string{".css"}, StatusCodes: []int{200}, TTLSeconds: ttl}},
		QueryMode: cachecontrol.QueryPreserve, VaryHeaders: []string{"Accept-Encoding"},
		DiskQuotaBytes: 64 << 20,
	}
}

func insertCache080Policy(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	actorScopeID, actorUserID uuid.UUID,
	key, requestID string,
	includeActorScope bool,
) (int64, int64, error) {
	var revision, edgeRevision int64
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE edge_configuration_scopes
			SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1
			RETURNING source_revision`, fixture.scopeID, cache080Now).Scan(&edgeRevision); err != nil {
			return err
		}
		err := tx.QueryRow(ctx, `SELECT current_revision FROM cache_policy_heads
			WHERE scope_id=$1 AND site_id=$2 FOR UPDATE`, fixture.scopeID, fixture.siteID).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			revision = 1
			if _, err := tx.Exec(ctx, `INSERT INTO cache_policy_heads(
				site_id,scope_id,tenant_id,current_revision,created_at,updated_at
			) VALUES($1,$2,$3,1,$4,$4)`, fixture.siteID, fixture.scopeID,
				fixture.tenantID, cache080Now); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			revision++
			createdAt := cache080Now.Add(time.Duration(revision-1) * time.Minute)
			if _, err := tx.Exec(ctx, `UPDATE cache_policy_heads
				SET current_revision=$3,updated_at=$4 WHERE scope_id=$1 AND site_id=$2`,
				fixture.scopeID, fixture.siteID, revision, createdAt); err != nil {
				return err
			}
		}
		digest := sha256.Sum256([]byte(requestID))
		requestFactID := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO cache_policy_write_requests(
			id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,
			request_digest,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, requestFactID, fixture.scopeID,
			actorScopeID, actorUserID, fixture.siteID, key, digest[:], cache080Now); err != nil {
			return err
		}
		createdAt := cache080Now.Add(time.Duration(revision-1) * time.Minute)
		if _, err := tx.Exec(ctx, `INSERT INTO cache_policy_revisions(
			site_id,scope_id,tenant_id,revision,mode,rules,query_mode,query_names,
			vary_headers,disk_quota_bytes,request_digest,actor_scope_id,created_by_user_id,
			request_id,created_at,edge_source_revision
		) VALUES($1,$2,$3,$4,'override',$5,'preserve',ARRAY[]::text[],ARRAY['accept-encoding'],
			$6,$7,$8,$9,$10,$11,$12)`, fixture.siteID, fixture.scopeID, fixture.tenantID,
			revision, `[ {"order":1,"extensions":[".css"],"status_codes":[200],"ttl_seconds":60} ]`,
			int64(64<<20), digest[:], actorScopeID, actorUserID, requestID, createdAt, edgeRevision); err != nil {
			return err
		}
		payload := map[string]any{"revision": revision, "mode": "override"}
		if includeActorScope {
			payload["actor_scope_id"] = actorScopeID
		}
		if err := audit.New(pool).Append(ctx, tx, audit.Event{
			ScopeID: fixture.scopeID, ActorUserID: &actorUserID,
			Action: "cache_policy.publish", ResourceType: "cache_policy",
			ResourceID: fixture.siteID.String(), RequestID: requestID,
			Result: "success", Payload: payload,
		}); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE cache_policy_write_requests
			SET response_revision=$2,completed_at=$3 WHERE id=$1`, requestFactID, revision, createdAt)
		return err
	})
	return revision, edgeRevision, err
}

func insertCache080QueuedOperation(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	actorScopeID, actorUserID uuid.UUID,
	key, requestID string,
	includeActorScope bool,
) (uuid.UUID, error) {
	operationID := uuid.New()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		digest := sha256.Sum256([]byte(requestID))
		if _, err := tx.Exec(ctx, `INSERT INTO cache_operations(
			id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
			request_id,actor_scope_id,actor_user_id,state,max_attempts,target_count,node_count,
			total_count,created_at,updated_at
		) VALUES($1,$2,$3,$4,'purge','exact_url',$5,$6,$7,$8,$9,'queued',2,1,1,1,$10,$10)`,
			operationID, fixture.scopeID, fixture.tenantID, fixture.siteID, key, digest[:],
			requestID, actorScopeID, actorUserID, cache080Now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_targets(
			operation_id,scope_id,ordinal,canonical_url,canonical_path
		) VALUES($1,$2,1,$3,'/cache.css')`, operationID, fixture.scopeID,
			"https://"+fixture.domain+"/cache.css"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_nodes(
			operation_id,scope_id,node_id,state,next_attempt_at,total_count,created_at,updated_at
		) VALUES($1,$2,$3,'queued',$4,1,$4,$4)`, operationID, fixture.scopeID,
			fixture.nodeID, cache080Now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_node_targets(
			operation_id,scope_id,node_id,target_ordinal,state
		) VALUES($1,$2,$3,1,'queued')`, operationID, fixture.scopeID, fixture.nodeID); err != nil {
			return err
		}
		payload := map[string]any{
			"action": "purge", "target_type": "exact_url", "targets": 1,
			"nodes": 1, "max_attempts": 2, "priority": "normal",
			"request_digest": fmt.Sprintf("%x", digest[:]),
		}
		if includeActorScope {
			payload["actor_scope_id"] = actorScopeID
		}
		return audit.New(pool).Append(ctx, tx, audit.Event{
			ScopeID: fixture.scopeID, ActorUserID: &actorUserID,
			Action: "cache.operation.create", ResourceType: "cache_operation",
			ResourceID: operationID.String(), RequestID: requestID,
			Result: "success", Payload: payload,
		})
	})
	return operationID, err
}

func insertCache080UnfinishedPolicyRequest(
	ctx context.Context,
	pool *pgxpool.Pool,
	siteID, targetScopeID, actorScopeID, actorUserID uuid.UUID,
	key string,
) error {
	digest := sha256.Sum256([]byte(key))
	_, err := pool.Exec(ctx, `INSERT INTO cache_policy_write_requests(
		id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), targetScopeID, actorScopeID,
		actorUserID, siteID, key, digest[:], cache080Now)
	return err
}

func insertCache080BareOperation(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	actorScopeID, actorUserID uuid.UUID,
	key string,
) error {
	digest := sha256.Sum256([]byte(key))
	_, err := pool.Exec(ctx, `INSERT INTO cache_operations(
		id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
		request_id,actor_scope_id,actor_user_id,state,max_attempts,target_count,node_count,
		total_count,created_at,updated_at
	) VALUES($1,$2,$3,$4,'purge','exact_url',$5,$6,$5,$7,$8,'queued',1,1,1,1,$9,$9)`,
		uuid.New(), fixture.scopeID, fixture.tenantID, fixture.siteID, key, digest[:],
		actorScopeID, actorUserID, cache080Now)
	return err
}

func assertCache080CommandActorMembership(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	operationID, actorScopeID, actorUserID uuid.UUID,
) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	digest := sha256.Sum256([]byte("command-membership"))
	if _, err := tx.Exec(t.Context(), `INSERT INTO cache_operation_commands(
		id,operation_id,scope_id,command,idempotency_key,request_digest,
		actor_scope_id,actor_user_id,created_at
	) VALUES($1,$2,$3,'cancel','command-membership',$4,$5,$6,$7)`, uuid.New(), operationID,
		fixture.scopeID, digest[:], actorScopeID, actorUserID, cache080Now); err != nil {
		t.Fatalf("platform command actor membership rejected: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	tx, err = pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	_, err = tx.Exec(t.Context(), `INSERT INTO cache_operation_commands(
		id,operation_id,scope_id,command,idempotency_key,request_digest,
		actor_scope_id,actor_user_id,created_at
	) VALUES($1,$2,$3,'cancel','command-wrong-membership',$4,$5,$6,$7)`, uuid.New(),
		operationID, fixture.scopeID, digest[:], fixture.scopeID, actorUserID, cache080Now)
	assertCache080Code(t, err, "23503")
}

func insertCache080RevisionAtEdge(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	actorScopeID, actorUserID uuid.UUID,
	edgeRevision int64,
) error {
	digest := sha256.Sum256([]byte("wrong-edge"))
	_, err := pool.Exec(ctx, `INSERT INTO cache_policy_revisions(
		site_id,scope_id,tenant_id,revision,mode,rules,query_mode,query_names,vary_headers,
		disk_quota_bytes,request_digest,actor_scope_id,created_by_user_id,request_id,
		created_at,edge_source_revision
	) VALUES($1,$2,$3,3,'override',$4,'preserve',ARRAY[]::text[],ARRAY['accept-encoding'],
		$5,$6,$7,$8,'wrong-edge',$9,$10)`, fixture.siteID, fixture.scopeID, fixture.tenantID,
		`[{"order":1,"extensions":[".css"],"status_codes":[200],"ttl_seconds":60}]`,
		int64(64<<20), digest[:], actorScopeID, actorUserID, cache080Now, edgeRevision)
	return err
}

func insertCache080DuplicateEdgeRevision(
	ctx context.Context,
	pool *pgxpool.Pool,
	fixture cache080Fixture,
	actorScopeID, actorUserID uuid.UUID,
	edgeRevision int64,
) error {
	digest := sha256.Sum256([]byte("duplicate-edge"))
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO cache_policy_heads(
		site_id,scope_id,tenant_id,current_revision,created_at,updated_at
	) VALUES($1,$2,$3,1,$4,$4)`, fixture.secondSiteID, fixture.scopeID,
		fixture.tenantID, cache080Now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cache_policy_revisions(
		site_id,scope_id,tenant_id,revision,mode,rules,query_mode,query_names,vary_headers,
		disk_quota_bytes,request_digest,actor_scope_id,created_by_user_id,request_id,
		created_at,edge_source_revision
	) VALUES($1,$2,$3,1,'override',$4,'preserve',ARRAY[]::text[],ARRAY['accept-encoding'],
		$5,$6,$7,$8,'duplicate-edge',$9,$10)`, fixture.secondSiteID, fixture.scopeID,
		fixture.tenantID, `[{"order":1,"extensions":[".css"],"status_codes":[200],"ttl_seconds":60}]`,
		int64(64<<20), digest[:], actorScopeID, actorUserID, cache080Now, edgeRevision)
	return err
}

func cache080EdgeHead(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var head int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision
		FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&head); err != nil {
		t.Fatal(err)
	}
	return head
}

func assertCache080Columns(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	columns := [][2]string{
		{"cache_operations", "actor_scope_id"},
		{"cache_policy_write_requests", "actor_scope_id"},
		{"cache_operation_commands", "actor_scope_id"},
		{"cache_policy_revisions", "actor_scope_id"},
		{"cache_policy_revisions", "edge_source_revision"},
	}
	for _, item := range columns {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
		)`, item[0], item[1]).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != want {
			t.Fatalf("column %s.%s exists=%t want %t", item[0], item[1], exists, want)
		}
	}
}

func assertCache080NewConstraints(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	expected := map[string]string{
		"cache_operations_actor_membership_080_fkey":            "FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id)",
		"cache_policy_write_requests_actor_membership_080_fkey": "FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id)",
		"cache_operation_commands_actor_membership_080_fkey":    "FOREIGN KEY (actor_scope_id, actor_user_id) REFERENCES memberships(scope_id, user_id)",
		"cache_policy_revisions_actor_membership_080_fkey":      "FOREIGN KEY (actor_scope_id, created_by_user_id) REFERENCES memberships(scope_id, user_id)",
		"cache_operations_idempotency_080_key":                  "UNIQUE (scope_id, actor_scope_id, actor_user_id, idempotency_key)",
		"cache_policy_write_requests_idempotency_080_key":       "UNIQUE (scope_id, actor_scope_id, actor_user_id, idempotency_key)",
		"cache_operation_commands_idempotency_080_key":          "UNIQUE (scope_id, actor_scope_id, actor_user_id, operation_id, command, idempotency_key)",
		"cache_policy_revisions_edge_source_revision_080_key":   "UNIQUE (scope_id, edge_source_revision)",
		"cache_policy_revisions_edge_source_revision_080_check": "CHECK ((edge_source_revision > 0))",
	}
	for name, want := range expected {
		var definition string
		if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
			FROM pg_constraint WHERE conname=$1 AND connamespace=current_schema()::regnamespace`,
			name).Scan(&definition); err != nil {
			t.Fatalf("constraint %s: %v", name, err)
		}
		if !strings.HasPrefix(definition, want) {
			t.Fatalf("constraint %s=%q want prefix %q", name, definition, want)
		}
	}
}

func assertCache080Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want code %s", err, want)
	}
}
