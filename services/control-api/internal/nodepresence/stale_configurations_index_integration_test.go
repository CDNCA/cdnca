//go:build integration

package nodepresence

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestStaleConfigurationsLookupUsesTheOversizedIndex (migration
// 648): with 100 000 unrelated audit events in the tenant scope, the
// "旧配置仍生效" lookup of a node reads audit_events_node_key_envelope_oversized_648_idx
// instead of walking the scope's events, and still finds the one node left
// out. Without the index the same query walks the scope (logged for contrast).
func TestStaleConfigurationsLookupUsesTheOversizedIndex(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is required")
	}
	ctx := context.Background()
	tenant, scope, leftOut, upToDate := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO tenants(id,display_name) VALUES($1,'Heavy')`, []any{tenant}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scope, tenant}},
			{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
				VALUES($1,$3,NULL,$4),($2,$3,NULL,$4)`, []any{leftOut, upToDate, scope, now}},
			// 100 000 unrelated events of the scope, some on the very nodes.
			{`INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,request_id,result,
				payload,previous_hash,event_hash,occurred_at)
				SELECT gen_random_uuid(),$1,n,
				       CASE WHEN n%3=0 THEN 'site.update' WHEN n%3=1 THEN 'edge_publication.publish' ELSE 'node.heartbeat_stale' END,
				       CASE WHEN n%3=2 THEN 'node' ELSE 'site' END,
				       CASE WHEN n%3=2 THEN (CASE WHEN n%2=0 THEN $2::uuid ELSE $3::uuid END)::text ELSE gen_random_uuid()::text END,
				       'req-'||n,'success','{}',CASE WHEN n=1 THEN NULL ELSE sha256(int8send(n-1)) END,
				       sha256(int8send(n)),$4::timestamptz-(100001-n)*interval '1 second'
				FROM generate_series(1,100000) n`, []any{scope, leftOut, upToDate, now}},
			{`INSERT INTO audit_events(id,scope_id,stream_position,action,resource_type,resource_id,request_id,result,
				payload,previous_hash,event_hash,occurred_at)
				VALUES(gen_random_uuid(),$1,100001,'edge_publication.key_envelope_oversized','node',$2::uuid::text,'req-left-out',
				       'denied','{"source_revision":7}',sha256(int8send(100000)),sha256(int8send(100001)),$3)`,
				[]any{scope, leftOut, now}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `ANALYZE audit_events, node_config_state, access_scopes, tenants, edge_config_publications`); err != nil {
		t.Fatal(err)
	}
	ids := []uuid.UUID{leftOut, upToDate}
	plan := func(tx pgx.Tx, analyze bool) string {
		t.Helper()
		options := "FORMAT TEXT, COSTS OFF"
		if analyze {
			options = "ANALYZE, BUFFERS, TIMING OFF, COSTS OFF"
		}
		rows, err := tx.Query(ctx, "EXPLAIN ("+options+") "+staleConfigurationsQuery, ids)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var lines []string
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, line)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return strings.Join(lines, "\n")
	}
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		indexed := plan(tx, false)
		if !strings.Contains(indexed, "audit_events_node_key_envelope_oversized_648_idx") ||
			strings.Contains(indexed, "audit_events_scope_time_idx") {
			t.Fatalf("lookup plan does not use the 648 index:\n%s", indexed)
		}
		t.Logf("with migration 648:\n%s", plan(tx, true))
		if _, err := tx.Exec(ctx, `DROP INDEX audit_events_node_key_envelope_oversized_648_idx`); err != nil {
			return err
		}
		t.Logf("without the index (contrast, rolled back):\n%s", plan(tx, true))
		return errRollbackPlan
	})
	if err != errRollbackPlan {
		t.Fatal(err)
	}

	items := []InventoryItem{{ID: leftOut}, {ID: upToDate}}
	if err := NewInventory(pool, nil, 0, nil, nil).attachStaleConfigurations(ctx, items); err != nil {
		t.Fatal(err)
	}
	if got := items[0].StaleConfigurations; len(got) != 1 || got[0].ScopeID != scope || got[0].SourceRevision != 7 ||
		got[0].TenantName != "Heavy" || got[0].Reason != StaleReasonKeyEnvelopeOversized {
		t.Fatalf("left-out node stale = %+v", got)
	}
	if got := items[1].StaleConfigurations; got != nil {
		t.Fatalf("up-to-date node stale = %+v", got)
	}
}

var errRollbackPlan = errorString("rollback the contrast plan")

type errorString string

func (e errorString) Error() string { return string(e) }
