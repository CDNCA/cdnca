//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestSiteSyncStatusDerived503 (PJ-C02，待出包前全量跑): after 503
// sites has no sync_status column; site_sync_status_503 reads the site's
// latest automatic publication request (succeeded synced, failed failed,
// anything else pending, none synced), ignores another site's and batch
// requests; down puts the column back.
func TestSiteSyncStatusDerived503(t *testing.T) {
	const version = 503
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
	var columns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='sites' AND column_name='sync_status'`).Scan(&columns); err != nil || columns != 0 {
		t.Fatalf("sites.sync_status after 503: %d %v", columns, err)
	}
	scope, user, site, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	// FKs are triggers: replica role lets the requests stand alone.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	status := func() string {
		t.Helper()
		var got string
		if err := tx.QueryRow(ctx, `SELECT site_sync_status_503($1,$2)`, scope, site).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	revision := int64(0)
	request := func(resource *uuid.UUID, operation string, states ...string) {
		t.Helper()
		revision++
		id := uuid.New()
		if _, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_requests(
			id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,source_kind,source_resource_id,source_revision,
			operation,reason,permission_name,source_request_id,idempotency_key,correlation_id,request_digest,policy_revision,created_at)
			VALUES($1,$2,$2,$3,'tenant','site',$4,$5,$6,'resource_mutation','sites.manage','req-503',$7,$8,$9,1,
			clock_timestamp())`, id, scope, user, resource, revision, operation, "edgeauto."+id.String(), uuid.New(),
			make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		for index, state := range states {
			// 086 的 CHECK：非 pending 的 attempt>0，终态要 terminal_code，succeeded 还要 publication/rollout。
			if _, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_request_state_facts(
				request_id,sequence,state,attempt,terminal_code,publication_id,rollout_id,occurred_at)
				VALUES($1,$2,$3,CASE WHEN $3='pending' THEN 0 ELSE 1 END,
				CASE WHEN $3 IN ('succeeded','failed','superseded') THEN 'test_'||$3 END,
				CASE WHEN $3 IN ('reconciling','succeeded') THEN gen_random_uuid() END,
				CASE WHEN $3 IN ('reconciling','succeeded') THEN gen_random_uuid() END,clock_timestamp())`,
				id, index+1, state); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := status(); got != "synced" {
		t.Fatalf("no request = %s, want synced", got)
	}
	request(&site, "site.update", "pending")
	if got := status(); got != "pending" {
		t.Fatalf("pending request = %s", got)
	}
	request(&site, "site.update", "pending", "failed")
	if got := status(); got != "failed" {
		t.Fatalf("failed request = %s", got)
	}
	// Another site's and a batch request do not change this site's status.
	request(&other, "site.update", "pending", "succeeded")
	request(nil, "site.batch.enable", "pending")
	if got := status(); got != "failed" {
		t.Fatalf("other site / batch requests changed it: %s", got)
	}
	request(&site, "site.update", "pending", "succeeded")
	if got := status(); got != "synced" {
		t.Fatalf("succeeded request = %s", got)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='sites' AND column_name='sync_status'`).Scan(&columns); err != nil || columns != 1 {
		t.Fatalf("sites.sync_status after 503 down: %d %v", columns, err)
	}
}
