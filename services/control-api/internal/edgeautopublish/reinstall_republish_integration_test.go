//go:build integration

package edgeautopublish_test

import (
	"context"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 重装此节点: the enrollment of the new host queues, for each scope the node
// carries, the failed-sync republication (trigger node_sync, due now) with
// its own source revision; a scope that never published is skipped.
func TestRepublishReinstalledNodeQueuesNodeSync(t *testing.T) {
	pool := openAutomaticDatabase(t)
	identity := seedAutomaticIntegrationIdentity(t, pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,4,now()) ON CONFLICT (scope_id) DO UPDATE SET source_revision=4`, identity.tenantScope); err != nil {
		t.Fatal(err)
	}
	nodeID := uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		return edgeautopublish.RepublishReinstalledNodeTx(ctx, tx, nodeID, []uuid.UUID{identity.tenantScope, uuid.New()},
			"node-reinstall/"+uuid.NewString())
	}); err != nil {
		t.Fatalf("RepublishReinstalledNodeTx() error = %v", err)
	}
	var triggers []string
	var due bool
	if err := pool.QueryRow(ctx, `SELECT triggers,due_at<=clock_timestamp() FROM edge_system_republication_heads
		WHERE scope_id=$1 AND state='pending'`, identity.tenantScope).Scan(&triggers, &due); err != nil ||
		len(triggers) != 1 || triggers[0] != "node_sync" || !due {
		t.Fatalf("republication head = %v due=%v, %v", triggers, due, err)
	}
	var revision, segments int64
	if err := pool.QueryRow(ctx, `SELECT scope.source_revision,
		(SELECT count(*) FROM edge_system_revision_segments segment
		 WHERE segment.scope_id=scope.scope_id AND segment.from_revision=4 AND segment.source='node_sync')
		FROM edge_configuration_scopes scope WHERE scope.scope_id=$1`, identity.tenantScope).Scan(&revision, &segments); err != nil ||
		revision != 5 || segments != 1 {
		t.Fatalf("scope revision = %d segments = %d, %v", revision, segments, err)
	}
}
