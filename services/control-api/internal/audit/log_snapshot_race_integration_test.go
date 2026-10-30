package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fix-cnamewait (73, 10-26): a Serializable transaction took its snapshot
// before another append to the same scope committed; after the stream lock
// it still read the old head and the insert hit
// audit_events_scope_id_stream_position_key (23505), which callers treat as a
// permanent conflict (the CNAME intent waited for its 16-minute lease). The
// stale head is a serialization failure: report 40001 so the caller retries
// the whole transaction, and the chain stays gap-free.
func TestAppendUnderStaleSnapshotIsSerializationFailure(t *testing.T) {
	pool := isolatedAuditPool(t)
	ctx := context.Background()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, "INSERT INTO tenants(id,display_name) VALUES($1,'Audit Race')", tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)", scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	log := New(pool)
	event := func(name string) Event {
		return Event{ScopeID: scopeID, Action: "audit.snapshot_race", ResourceType: "role",
			ResourceID: uuid.NewString(), RequestID: "audit-race-" + name, Result: "success", Payload: map[string]any{"n": name}}
	}
	appendCommitted := func(name string) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return log.Append(ctx, tx, event(name)) }); err != nil {
			t.Fatalf("append %s: %v", name, err)
		}
	}
	appendCommitted("first")

	stale, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatal(err)
	}
	defer stale.Rollback(context.Background())
	if _, err := stale.Exec(ctx, "SELECT 1 FROM access_scopes WHERE id=$1", scopeID); err != nil { // takes the snapshot
		t.Fatal(err)
	}
	appendCommitted("concurrent")
	err = log.Append(ctx, stale, event("stale"))
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "40001" {
		t.Fatalf("append under stale snapshot = %v, want SQLSTATE 40001 (serialization failure)", err)
	}
	_ = stale.Rollback(ctx)

	// The caller's whole-transaction retry appends at the next position.
	if err := pgx.BeginTxFunc(ctx, pool, pgx.TxOptions{IsoLevel: pgx.Serializable}, func(tx pgx.Tx) error {
		return log.Append(ctx, tx, event("retry"))
	}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	var count, last int64
	if err := pool.QueryRow(ctx, `SELECT count(*),max(stream_position) FROM audit_events WHERE scope_id=$1`, scopeID).
		Scan(&count, &last); err != nil || count != 3 || last != 3 {
		t.Fatalf("chain count=%d last=%d err=%v, want 3 gap-free", count, last, err)
	}
	if err := log.VerifyScope(ctx, scopeID); err != nil {
		t.Fatalf("verify chain: %v", err)
	}
}
