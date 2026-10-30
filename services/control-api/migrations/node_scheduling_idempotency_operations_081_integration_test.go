//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var nodeScheduling081Now = time.Date(2026, 7, 29, 4, 0, 0, 0, time.UTC)

func TestNodeSchedulingIdempotencyOperations081AllowsOperationDomains(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 81)
	scopeID, actorUserID, groupID := seedNodeScheduling081Group(t, pool)

	operations := []string{
		"node_scheduling.group.put",
		"node_scheduling.group.create",
		"node_scheduling.group.update",
		"node_scheduling.group.rollback",
		"node_scheduling.target_snapshot.create",
	}
	for _, operation := range operations {
		insertNodeScheduling081Receipt(t, pool, scopeID, actorUserID, groupID, operation)
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO node_scheduling_write_requests(
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		target_group_id,created_at
	) VALUES($1,$2,$3,'node_scheduling.invalid','invalid',$4,$5,$6)`,
		uuid.New(), scopeID, actorUserID, make([]byte, 32), groupID, nodeScheduling081Now)
	assertPackageCommerceRBAC079Code(t, err, "23514")
	_, err = pool.Exec(t.Context(), `UPDATE node_scheduling_write_requests
		SET operation='node_scheduling.group.put'
		WHERE tenant_scope_id=$1 AND actor_user_id=$2
		  AND operation='node_scheduling.group.create'`, scopeID, actorUserID)
	assertPackageCommerceRBAC079Code(t, err, "P0001")

	assertPackageCommerceRBAC079Code(t, database.Migrate(t.Context(), pool, "down"), "P8101")
	assertNodeScheduling081Head(t, pool, 81)
	assertNodeScheduling081Constraint(t, pool, operations)
	assertPackageCommerceRBAC079Ledger(t, pool, 81)
}

func TestNodeSchedulingIdempotencyOperations081LegacyRoundTrip(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 80)
	scopeID, actorUserID, groupID := seedNodeScheduling081Group(t, pool)
	insertNodeScheduling081Receipt(t, pool, scopeID, actorUserID, groupID, "node_scheduling.group.put")
	legacy := []string{"node_scheduling.group.put"}
	operations := append(append([]string(nil), legacy...),
		"node_scheduling.group.create",
		"node_scheduling.group.update",
		"node_scheduling.group.rollback",
		"node_scheduling.target_snapshot.create",
	)
	assertNodeScheduling081Constraint(t, pool, legacy)

	migrateNodeScheduling081(t, pool, "up")
	assertNodeScheduling081Head(t, pool, 81)
	assertNodeScheduling081Constraint(t, pool, operations)
	assertNodeScheduling081Receipt(t, pool, scopeID, actorUserID, groupID, "node_scheduling.group.put")
	assertPackageCommerceRBAC079Ledger(t, pool, 81)

	migrateNodeScheduling081(t, pool, "down")
	assertNodeScheduling081Head(t, pool, 80)
	assertNodeScheduling081Constraint(t, pool, legacy)
	assertNodeScheduling081Receipt(t, pool, scopeID, actorUserID, groupID, "node_scheduling.group.put")
	assertPackageCommerceRBAC079Ledger(t, pool, 80)

	migrateNodeScheduling081(t, pool, "up")
	assertNodeScheduling081Head(t, pool, 81)
	assertNodeScheduling081Constraint(t, pool, operations)
	assertNodeScheduling081Receipt(t, pool, scopeID, actorUserID, groupID, "node_scheduling.group.put")
	assertPackageCommerceRBAC079Ledger(t, pool, 81)
}

//go:linkname migrateNodeScheduling081FS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateNodeScheduling081FS(context.Context, *pgxpool.Pool, string, fs.FS) error

func migrateNodeScheduling081(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	files := make(fstest.MapFS, 81*2)
	for version := int64(1); version <= 81; version++ {
		migration, err := loadPackageCommerceRBAC079Migration(version)
		if err != nil {
			t.Fatal(err)
		}
		files[migration.identifier+".up.sql"] = &fstest.MapFile{Data: migration.upScript}
		files[migration.identifier+".down.sql"] = &fstest.MapFile{Data: migration.downScript}
	}
	if err := migrateNodeScheduling081FS(t.Context(), pool, direction, files); err != nil {
		t.Fatalf("migrate 081 %s: %v", direction, err)
	}
}

func assertNodeScheduling081Receipt(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, actorUserID, groupID uuid.UUID,
	operation string,
) {
	t.Helper()
	digest := sha256.Sum256([]byte(operation))
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_scheduling_write_requests
		WHERE tenant_scope_id=$1 AND actor_user_id=$2 AND target_group_id=$3
		  AND operation=$4 AND request_digest=$5`,
		scopeID, actorUserID, groupID, operation, digest[:]).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("preserved %s receipt count=%d want=1", operation, count)
	}
}

func insertNodeScheduling081Receipt(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, actorUserID, groupID uuid.UUID,
	operation string,
) {
	t.Helper()
	digest := sha256.Sum256([]byte(operation))
	key := strings.NewReplacer("node_scheduling.", "", ".", "-").Replace(operation)
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_scheduling_write_requests(
		id,tenant_scope_id,actor_user_id,operation,idempotency_key,request_digest,
		target_group_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), scopeID, actorUserID,
		operation, key, digest[:], groupID, nodeScheduling081Now); err != nil {
		t.Fatalf("insert %s receipt: %v", operation, err)
	}
}

func assertNodeScheduling081Head(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var head int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatal(err)
	}
	if head != want {
		t.Fatalf("migration head=%d want=%d", head, want)
	}
}

func assertNodeScheduling081Constraint(t *testing.T, pool *pgxpool.Pool, operations []string) {
	t.Helper()
	var definition string
	if err := pool.QueryRow(t.Context(), `SELECT pg_get_constraintdef(oid)
		FROM pg_constraint WHERE conrelid='node_scheduling_write_requests'::regclass
		  AND conname='node_scheduling_write_requests_operation_check'`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	for _, operation := range operations {
		if !strings.Contains(definition, "'"+operation+"'") {
			t.Fatalf("operation constraint %q omits %q", definition, operation)
		}
	}
	all := []string{
		"node_scheduling.group.put",
		"node_scheduling.group.create",
		"node_scheduling.group.update",
		"node_scheduling.group.rollback",
		"node_scheduling.target_snapshot.create",
	}
	for _, operation := range all {
		if !containsNodeScheduling081Operation(operations, operation) && strings.Contains(definition, "'"+operation+"'") {
			t.Fatalf("operation constraint %q unexpectedly contains %q", definition, operation)
		}
	}
}

func containsNodeScheduling081Operation(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func seedNodeScheduling081Group(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, actorUserID, groupID, endpointID :=
		uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name,status) VALUES($1,'Node 081','active')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,status)
			VALUES($1,$2,'Node 081','test-hash','active')`, []any{actorUserID, "node-081-" + uuid.NewString()}},
		{`INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, []any{scopeID, actorUserID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_groups(
			id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at
		) VALUES($1,$2,'Node 081 group',1,$3,$3,$4,$4)`, groupID, scopeID, actorUserID, nodeScheduling081Now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_group_revisions(
			line_group_id,tenant_scope_id,revision,name,probe_interval_ms,probe_timeout_ms,
			failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,
			endpoint_count,configuration_digest,created_by_user_id,created_at
		) VALUES($1,$2,1,'Node 081 group',10000,3000,3,3,0,0,1,$3,$4,$5)`,
			groupID, scopeID, make([]byte, 32), actorUserID, nodeScheduling081Now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoints(
			id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,
			region,carrier,priority,weight,enabled
		) VALUES($1,$2,$3,1,'192.0.2.81',4,443,'','',0,100,true)`, endpointID, scopeID, groupID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO node_line_endpoint_health(
			tenant_scope_id,line_group_id,config_revision,endpoint_id,status,
			consecutive_successes,consecutive_failures,last_sequence,last_changed_at,
			row_revision,created_at,updated_at
		) VALUES($1,$2,1,$3,'unknown',0,0,0,$4,1,$4,$4)`, scopeID, groupID, endpointID, nodeScheduling081Now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_line_group_revisions SET sealed_at=$4
			WHERE tenant_scope_id=$1 AND line_group_id=$2 AND revision=$3`, scopeID, groupID, int64(1), nodeScheduling081Now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return scopeID, actorUserID, groupID
}
