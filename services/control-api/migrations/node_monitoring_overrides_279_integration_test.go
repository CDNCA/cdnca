//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNodeMonitoringOverridesMigration279(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 278)
	ctx := t.Context()
	scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'override-owner','Override owner','test-only')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'n1','active',$3,1)`, []any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 279); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", 279); err != nil {
		t.Fatalf("rollback without overrides: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 279); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	now := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	insert := `INSERT INTO node_monitoring_overrides(node_id,scope_id,monitor_enabled,protocol,probe_timeout_ms,monitor_port,
		revision,updated_by_user_id,created_at,updated_at) VALUES($1,$2,true,$3,$4,$5,$6,$7,$8,$8)`
	var pgError *pgconn.PgError
	for _, invalid := range []struct {
		protocol string
		timeout  int
		port     int
		revision int
		code     string
	}{
		{"udp", 1000, 80, 1, "23514"}, {"tcp", 99, 80, 1, "23514"}, {"tcp", 60001, 80, 1, "23514"},
		{"tcp", 1000, 0, 1, "23514"}, {"tcp", 1000, 65536, 1, "23514"}, {"tcp", 1000, 80, 2, "P2792"},
	} {
		_, err := pool.Exec(ctx, insert, nodeID, scopeID, invalid.protocol, invalid.timeout, invalid.port, invalid.revision, userID, now)
		if !errors.As(err, &pgError) || pgError.Code != invalid.code {
			t.Fatalf("invalid override %+v accepted or wrong error: %v", invalid, err)
		}
	}
	if _, err := pool.Exec(ctx, insert, nodeID, scopeID, "http", 5000, 8080, 1, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_monitoring_overrides SET revision=3,updated_at=$2 WHERE node_id=$1`, nodeID, now); !errors.As(err, &pgError) || pgError.Code != "P2792" {
		t.Fatalf("revision skip accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_monitoring_overrides SET revision=2,protocol=NULL,updated_at=$2 WHERE node_id=$1`, nodeID, now.Add(time.Second)); err != nil {
		t.Fatalf("revision advance: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_monitoring_overrides`); !errors.As(err, &pgError) || pgError.Code != "P2791" {
		t.Fatalf("override delete accepted: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO node_write_requests(id,actor_user_id,actor_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,'node.monitoring_override','k1',$4,$5)`, uuid.New(), userID, scopeID, make([]byte, 32), now); err != nil {
		t.Fatalf("monitoring override write request: %v", err)
	}
	err := migrateVersionIsolated(ctx, pool, "down", 279)
	if !errors.As(err, &pgError) || pgError.Code != "P2793" {
		t.Fatalf("override rollback must fail with P2793: %v", err)
	}
	var head int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 279 {
		t.Fatalf("rollback failure changed head: %d %v", head, err)
	}
}
