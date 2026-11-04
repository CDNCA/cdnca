//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestMarketSupplyL2Config629UpDown: after up a market supply group
// names an L2 configuration of another region, an ordinary group still may
// not (P5043); down restores the 504 rule and refuses while a supply group
// names one (P6292), then succeeds once it is cleared.
func TestMarketSupplyL2Config629UpDown(t *testing.T) {
	const version = 629
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	scope, user, config := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) error {
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'supply-l2-629','supply-l2','unused')`, []any{user}},
		{`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,
			created_at,updated_at) VALUES($1,$2,'supply-l2','华南','global','rr',$3,$3,now(),now())`, []any{config, scope, user}},
	} {
		if err := exec(statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	// Only the row trigger matters: written as a replica the line group needs
	// no revision rows, then the trigger runs on the l2_config_id update.
	group := func(purpose string) (uuid.UUID, error) {
		id := uuid.New()
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO node_line_groups(id,display_id,tenant_scope_id,name,region,resolved_value,ipv4_resolved_value,
				failover_mode,note,sort_order,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at,purpose)
				VALUES($1,(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),$2,$3,'',$4,$5,'primary_offline','',1,1,$6,$6,now(),now(),$7)`, id, scope, "supply-l2-"+id.String()[:8],
				"lg-"+id.String()[:12], "v4-"+id.String()[:12], user, purpose)
			return err
		})
		return id, err
	}
	// name runs the 504 row trigger on naming the configuration and rolls
	// back (the revision foreign key is deferred to commit, so no revision
	// row is needed for the trigger's answer).
	name := func(id uuid.UUID) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `UPDATE node_line_groups SET l2_config_id=$2,current_revision=current_revision+1,
			updated_at=clock_timestamp() WHERE id=$1`, id, config)
		return err
	}
	// stored writes l2_config_id as is (a replica: no trigger, no foreign key).
	stored := func(id uuid.UUID, value *uuid.UUID) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE node_line_groups SET l2_config_id=$2 WHERE id=$1`, id, value)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	supply, err := group("market_supply")
	if err != nil {
		t.Fatal(err)
	}
	general, err := group("general")
	if err != nil {
		t.Fatal(err)
	}
	if err := name(supply); !pgCode(err, "P5043") {
		t.Fatalf("supply group at 628 = %v, want P5043", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	if err := name(supply); err != nil {
		t.Fatalf("supply group names another region's configuration: %v", err)
	}
	if err := name(general); !pgCode(err, "P5043") {
		t.Fatalf("ordinary group at 629 = %v, want P5043", err)
	}
	stored(supply, &config)
	// The configuration may change region while only a supply group uses it.
	if err := exec(`UPDATE l2_topology_configs SET region='华北' WHERE id=$1`, config); err != nil {
		t.Fatalf("region change used by a supply group: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !pgCode(err, "P6292") {
		t.Fatalf("down %d with a supply group on another region = %v, want P6292", version, err)
	}
	stored(supply, nil)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if err := name(supply); !pgCode(err, "P5043") {
		t.Fatalf("supply group after down = %v, want P5043", err)
	}
}
