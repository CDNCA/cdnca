//go:build integration

package migrations_test

import (
	"errors"
	"io/fs"
	"strconv"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func tenantNodeCarriageVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*_tenant_node_carriage.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("tenant node carriage migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(strings.SplitN(matches[0], "_", 2)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// TestTenantNodeCarriageMigration checks the carriage rule on every branch and
// that the rebound tables refuse a node the row's tenant does not carry.
func TestTenantNodeCarriageMigration(t *testing.T) {
	version := tenantNodeCarriageVersion(t)
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var oldIndex, newIndex bool
	if err := pool.QueryRow(ctx, `SELECT
		to_regclass('security_policy_publication_targets_one_open_per_node_idx') IS NOT NULL,
		to_regclass('security_policy_publication_targets_open_node_tenant_287_idx') IS NOT NULL`).
		Scan(&oldIndex, &newIndex); err != nil || oldIndex || !newIndex {
		t.Fatalf("security target index old=%v new=%v err=%v", oldIndex, newIndex, err)
	}

	var cnameScope bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='cname_allocation_targets'::regclass
			AND conname='cname_allocation_targets_node_group_287_fkey')
		AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='cname_allocation_targets'::regclass
			AND conname='cname_allocation_targets_tenant_scope_id_node_group_id_fkey')`).Scan(&cnameScope); err != nil || !cnameScope {
		t.Fatalf("CNAME target node group scope = %v, %v", cnameScope, err)
	}

	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
	} else if err != nil {
		t.Fatal(err)
	}
	tenant, other, user := uuid.New(), uuid.New(), uuid.New()
	owned, claimed, grouped, packaged, backup, foreign, retired, unrelated :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	groupSite, groupPackage, groupBackup, groupForeign, groupRetired :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		exec := func(sql string, args ...any) {
			if _, execErr := tx.Exec(ctx, sql, args...); execErr != nil {
				t.Fatalf("%.80s: %v", sql, execErr)
			}
		}
		exec(`SET LOCAL session_replication_role = replica`)
		exec(`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS (SELECT 1 FROM access_scopes WHERE kind='platform')`, platform)
		for _, scope := range []uuid.UUID{tenant, other} {
			exec(`INSERT INTO tenants(id,display_name) VALUES($1,'carriage')`, scope)
			exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, scope)
		}
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'carriage','x')`, user, "carriage-"+user.String()[:8])
		display := 0
		node := func(id, scope uuid.UUID, state string) {
			display++
			exec(`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id) VALUES($1,$2,$3,$4,$5,$6)`,
				id, 90000+display, scope, "carriage-"+id.String()[:8], state, user)
		}
		node(owned, tenant, "active")
		for _, id := range []uuid.UUID{claimed, grouped, packaged, backup, foreign, unrelated} {
			node(id, platform, "active")
		}
		node(retired, platform, "retired")
		exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,updated_at) VALUES($1,$2,$3)`, claimed, tenant, now)
		group := func(id, nodeID uuid.UUID, deleted bool) {
			display++
			deletedAt := any(nil)
			if deleted {
				deletedAt = now
			}
			exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
				created_at,updated_at,display_id,resolved_value,ipv4_resolved_value,deleted_at,deleted_by_user_id)
				VALUES($1::uuid,$2,$3,2,$4::uuid,$4::uuid,$5,$5,$6,'lg-'||replace($1::uuid::text,'-',''),'lg4-'||replace($1::uuid::text,'-',''),
				$7::timestamptz,CASE WHEN $7::timestamptz IS NULL THEN NULL ELSE $4::uuid END)`,
				id, platform, "carriage-"+id.String()[:8], user, now, display, deletedAt)
			// One endpoint on the current revision, one stale endpoint on revision 1 for "unrelated".
			exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
				port,priority,weight,enabled) VALUES($1,$2,$3,$4,2,'8.8.8.8',4,80,0,1,true),($5,$6,$3,$4,1,'8.8.4.4',4,80,0,1,true)`,
				uuid.New(), nodeID, platform, id, uuid.New(), unrelated)
		}
		group(groupSite, grouped, false)
		group(groupPackage, packaged, false)
		group(groupBackup, backup, false)
		group(groupForeign, foreign, false)
		group(groupRetired, retired, false)
		subscription := uuid.New()
		exec(`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
			domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
			tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,1,jsonb_build_object('revision',1,'name','carriage','spec',jsonb_build_object('node_group_id',$4::text,'backup_node_group_id',$5::text)),
			1,1,1,0,$6::timestamptz,$6::timestamptz+interval '30 days','UTC','monthly',1,1,$7,$7,$6::timestamptz,$6::timestamptz)`,
			subscription, tenant, uuid.New(), groupPackage, groupBackup, now, user)
		site := func(scope uuid.UUID, nodeGroup *uuid.UUID, sub *uuid.UUID, deleted bool) {
			display++
			deletedAt := any(nil)
			if deleted {
				deletedAt = now
			}
			exec(`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,
				display_id,node_group_id,package_subscription_id,deleted_at,package_id,package_name)
				VALUES($1,$2,$3,$4,'{203.0.113.20}','{203.0.113.20}',$3,$3,$5,$6,$7,$8,
				CASE WHEN $7::uuid IS NULL THEN NULL ELSE $1::uuid END,CASE WHEN $7::uuid IS NULL THEN NULL ELSE 'carriage' END)`,
				uuid.New(), scope, user, "carriage-"+uuid.NewString()[:8]+".example", display, nodeGroup, sub, deletedAt)
		}
		site(tenant, &groupSite, nil, false)
		site(tenant, nil, &subscription, false)
		site(tenant, &groupRetired, nil, false)
		site(other, &groupForeign, nil, false)
		site(tenant, &groupForeign, nil, true) // deleted: carries nothing
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		node uuid.UUID
		want bool
	}{
		"owned by the tenant":               {owned, true},
		"platform node the tenant claimed":  {claimed, true},
		"site node group":                   {grouped, true},
		"package node group":                {packaged, true},
		"package backup node group":         {backup, true},
		"another tenant's node group":       {foreign, false},
		"retired node":                      {retired, false},
		"stale endpoint of a previous rev.": {unrelated, false},
	} {
		var got bool
		if err := pool.QueryRow(ctx, `SELECT tenant_carries_node_287($1,$2)`, tenant, c.node).Scan(&got); err != nil || got != c.want {
			t.Errorf("%s: carries=%v err=%v, want %v", name, got, err, c.want)
		}
	}
	insert := func(node uuid.UUID) error {
		_, err := pool.Exec(ctx, `INSERT INTO l4_node_drain_counters(configuration_scope_id,node_id,revision,updated_at)
			VALUES($1,$2,1,now())`, tenant, node)
		return err
	}
	if err := insert(grouped); err != nil {
		t.Fatalf("carried platform node refused: %v", err)
	}
	var pgErr *pgconn.PgError
	if err := insert(foreign); !errors.As(err, &pgErr) || pgErr.Code != "23503" || pgErr.ConstraintName != "tenant_node_carriage_287" {
		t.Fatalf("uncarried node accepted: %v", err)
	}
}
