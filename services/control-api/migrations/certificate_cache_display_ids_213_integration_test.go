//go:build integration

package migrations_test

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCertificateCacheDisplayIDs213RoundTripConcurrencyAndScopeIsolation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 212)
	// Today's audit.Append writes the columns of migration 361 (unified log).
	databasetest.AddUnifiedAuditColumns(t, pool)
	now := time.Date(2026, 8, 29, 1, 0, 0, 0, time.UTC)
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	assetA1, assetA2, assetB1 := uuid.New(), uuid.New(), uuid.New()
	operationA1, operationA2, operationB1 := uuid.New(), uuid.New(), uuid.New()

	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Display A'),($2,'Display B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES
			($5,'display-213-a','Display A','unused'),($6,'display-213-b','Display B','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($4,$6);
		INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES
			($7,$3,1,$5,'display-a.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$5,$5,$11,$11),
			($8,$4,1,$6,'display-b.example.test',ARRAY['192.0.2.11:80'],ARRAY['192.0.2.11'],$6,$6,$11,$11);
		INSERT INTO site_origin_pools(site_id,updated_at) VALUES($7,$11),($8,$11);
		INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES
			($7,1,'192.0.2.10',80,1,true),($8,1,'192.0.2.11',80,1,true);
		INSERT INTO nodes(id,scope_id,display_id,name,admin_state,created_by_user_id,created_at,updated_at) VALUES
			($9,$3,1,'display node A','active',$5,$11,$11),
			($10,$4,1,'display node B','active',$6,$11,$11)`,
		pgx.QueryExecModeSimpleProtocol, tenantA, tenantB, scopeA, scopeB, userA, userB,
		siteA, siteB, nodeA, nodeB, now); err != nil {
		t.Fatalf("seed identities: %v", err)
	}

	for _, asset := range []struct {
		id, scope, user uuid.UUID
		name            string
		created         time.Time
	}{
		{assetA2, scopeA, userA, "asset A second", now.Add(2 * time.Minute)},
		{assetA1, scopeA, userA, "asset A first", now.Add(time.Minute)},
		{assetB1, scopeB, userB, "asset B first", now.Add(time.Minute)},
	} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_assets(
			tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,
			created_by_scope_id,updated_by_scope_id,created_at,updated_at)
			VALUES($1,$2,$3,'uploaded',$4,$4,$1,$1,$5,$5)`,
			asset.scope, asset.id, asset.name, asset.user, asset.created); err != nil {
			t.Fatalf("seed certificate asset: %v", err)
		}
	}
	seedCacheOperation213(t, pool, operationA2, scopeA, tenantA, userA, siteA, nodeA, 2, now.Add(4*time.Minute))
	seedCacheOperation213(t, pool, operationA1, scopeA, tenantA, userA, siteA, nodeA, 1, now.Add(3*time.Minute))
	seedCacheOperation213(t, pool, operationB1, scopeB, tenantB, userB, siteB, nodeB, 1, now.Add(3*time.Minute))

	if err := migrateVersionIsolated(t.Context(), pool, "up", 213); err != nil {
		t.Fatalf("212 -> 213: %v", err)
	}
	assertDisplayID213(t, pool, "certificate_assets", assetA1, 1)
	assertDisplayID213(t, pool, "certificate_assets", assetA2, 2)
	assertDisplayID213(t, pool, "certificate_assets", assetB1, 1)
	assertDisplayID213(t, pool, "cache_operations", operationA1, 1)
	assertDisplayID213(t, pool, "cache_operations", operationA2, 2)
	assertDisplayID213(t, pool, "cache_operations", operationB1, 1)

	const concurrent = 10
	displayIDs := make(chan int, concurrent)
	errorsCh := make(chan error, concurrent)
	var wg sync.WaitGroup
	for index := 0; index < concurrent; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			var displayID int
			err := pool.QueryRow(t.Context(), `INSERT INTO certificate_assets(
				tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,
				created_by_scope_id,updated_by_scope_id,created_at,updated_at)
				VALUES($1,$2,$3,'uploaded',$4,$4,$1,$1,$5,$5) RETURNING display_id`,
				scopeA, uuid.New(), fmt.Sprintf("concurrent asset %02d", index), userA,
				now.Add(time.Duration(index+10)*time.Minute)).Scan(&displayID)
			if err != nil {
				errorsCh <- err
				return
			}
			displayIDs <- displayID
		}(index)
	}
	wg.Wait()
	close(errorsCh)
	close(displayIDs)
	for err := range errorsCh {
		t.Fatalf("concurrent allocation: %v", err)
	}
	got := make([]int, 0, concurrent)
	for displayID := range displayIDs {
		got = append(got, displayID)
	}
	sort.Ints(got)
	for index, displayID := range got {
		if displayID != index+3 {
			t.Fatalf("concurrent certificate display IDs=%v, want 3..%d", got, concurrent+2)
		}
	}

	var isolatedAsset int
	if err := pool.QueryRow(t.Context(), `INSERT INTO certificate_assets(
		tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,
		created_by_scope_id,updated_by_scope_id,created_at,updated_at)
		VALUES($1,$2,'isolated asset','uploaded',$3,$3,$1,$1,$4,$4) RETURNING display_id`,
		scopeB, uuid.New(), userB, now.Add(time.Hour)).Scan(&isolatedAsset); err != nil || isolatedAsset != 2 {
		t.Fatalf("scope-isolated certificate display ID=(%d,%v), want 2", isolatedAsset, err)
	}

	cacheA3 := uuid.New()
	cacheB2 := uuid.New()
	seedCacheOperation213(t, pool, cacheA3, scopeA, tenantA, userA, siteA, nodeA, 3, now.Add(2*time.Hour))
	seedCacheOperation213(t, pool, cacheB2, scopeB, tenantB, userB, siteB, nodeB, 2, now.Add(2*time.Hour))
	assertDisplayID213(t, pool, "cache_operations", cacheA3, 3)
	assertDisplayID213(t, pool, "cache_operations", cacheB2, 2)

	_, err := pool.Exec(t.Context(), `INSERT INTO certificate_assets(
		tenant_scope_id,id,display_id,name,source,created_by_user_id,updated_by_user_id,
		created_by_scope_id,updated_by_scope_id,created_at,updated_at)
		VALUES($1,$2,99,'manual asset','uploaded',$3,$3,$1,$1,$4,$4)`,
		scopeA, uuid.New(), userA, now.Add(3*time.Hour))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P2131" {
		t.Fatalf("allocator ownership error=%v, want P2131", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE certificate_assets SET display_id=99,
		revision=revision+1,updated_at=updated_at+interval '1 second'
		WHERE tenant_scope_id=$1 AND id=$2`, scopeA, assetA1); !errors.As(err, &pgErr) || pgErr.Code != "P2133" {
		t.Fatalf("immutability error=%v, want P2133", err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 213); err != nil {
		t.Fatalf("213 -> 212: %v", err)
	}
	for _, table := range []string{"certificate_assets", "cache_operations"} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name='display_id')`, table).Scan(&exists); err != nil || exists {
			t.Fatalf("%s display_id after rollback=(%v,%v)", table, exists, err)
		}
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 213); err != nil {
		t.Fatalf("212 -> 213 reapply: %v", err)
	}
	assertDisplayID213(t, pool, "certificate_assets", assetA1, 1)
	assertDisplayID213(t, pool, "certificate_assets", assetA2, 2)
	assertDisplayID213(t, pool, "cache_operations", operationA1, 1)
	assertDisplayID213(t, pool, "cache_operations", operationA2, 2)
}

func seedCacheOperation213(
	t *testing.T,
	pool *pgxpool.Pool,
	operationID, scopeID, tenantID, userID, siteID, nodeID uuid.UUID,
	ordinal int,
	createdAt time.Time,
) {
	t.Helper()
	requestID := fmt.Sprintf("display-213-%s", operationID)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO cache_operations(
			id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,request_digest,
			request_id,actor_user_id,actor_scope_id,state,max_attempts,target_count,node_count,
			total_count,created_at,updated_at) VALUES($1,$2,$3,$4,'purge','whole_site',$5,$6,
			$5,$7,$2,'queued',3,1,1,1,$8,$8)`, operationID, scopeID, tenantID, siteID,
			requestID, bytes.Repeat([]byte{byte(ordinal)}, 32), userID, createdAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO cache_operation_targets(operation_id,scope_id,ordinal,canonical_url,canonical_path)
			VALUES($1,$2,1,'/','/');
			INSERT INTO cache_operation_nodes(operation_id,scope_id,node_id,state,total_count,next_attempt_at,created_at,updated_at)
			VALUES($1,$2,$3,'queued',1,$4,$4,$4);
			INSERT INTO cache_operation_node_targets(operation_id,scope_id,node_id,target_ordinal,state)
			VALUES($1,$2,$3,1,'queued')`, pgx.QueryExecModeSimpleProtocol,
			operationID, scopeID, nodeID, createdAt); err != nil {
			return err
		}
		return audit.New(pool).Append(t.Context(), tx, audit.Event{
			ScopeID: scopeID, ActorUserID: &userID, Action: "cache.operation.create",
			ResourceType: "cache_operation", ResourceID: operationID.String(), RequestID: requestID,
			Result: "success", Payload: map[string]any{
				"actor_scope_id": scopeID, "action": "purge", "target_type": "whole_site",
				"targets": 1, "nodes": 1, "max_attempts": 3,
			},
		})
	})
	if err != nil {
		t.Fatalf("seed cache operation %s: %v", operationID, err)
	}
}

func assertDisplayID213(t *testing.T, pool *pgxpool.Pool, table string, id uuid.UUID, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), fmt.Sprintf(`SELECT display_id FROM %s WHERE id=$1`, table), id).Scan(&got); err != nil || got != want {
		t.Fatalf("%s %s display_id=(%d,%v), want %d", table, id, got, err, want)
	}
}
