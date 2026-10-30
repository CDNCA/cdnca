//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4TLSPassthroughMigration checks that 293 keeps existing streams plain
// and exclusive, validates SNI lists the way edgeconfig does, and refuses to
// roll back once passthrough history exists.
func TestL4TLSPassthroughMigration(t *testing.T) {
	const version = 293
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "passthrough-293", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19493, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}

	var passthrough bool
	var names []string
	if err := pool.QueryRow(ctx, `SELECT f.tls_passthrough, l.server_names FROM l4_forwards f
		JOIN l4_forward_listeners l ON l.id=f.id WHERE f.id=$1`, legacy).Scan(&passthrough, &names); err != nil ||
		passthrough || len(names) != 0 {
		t.Fatalf("existing stream after 293: passthrough=%t names=%v err=%v", passthrough, names, err)
	}
	// Plain sockets stay unique per (protocol, port).
	other := uuid.New()
	var pgErr *pgconn.PgError
	if _, err := pool.Exec(ctx, `INSERT INTO l4_forwards(
		id,scope_id,package_subscription_id,owner_user_id,name,protocol,listen_address,listen_port,
		upstream_address,upstream_port,connect_timeout_ms,response_timeout_ms,max_connections_per_client,
		proxy_protocol_v1,enabled,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,'Second plain','tcp','*',19493,'192.0.2.10',9000,3000,30000,100,false,true,$4,$4,$5,$5)`,
		other, scope, subscription, user, now); !errors.As(err, &pgErr) || pgErr.Code != "23505" ||
		pgErr.ConstraintName != "l4_forwards_protocol_port_active_293_idx" {
		t.Fatalf("duplicate plain socket err=%v", err)
	}
	// Passthrough needs a v2 (site-bound) TCP stream.
	if _, err := pool.Exec(ctx, `UPDATE l4_forwards SET tls_passthrough=true, server_names='{a.example.com}' WHERE id=$1`,
		legacy); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_tls_passthrough_293" {
		t.Fatalf("v1 passthrough err=%v", err)
	}

	for names, want := range map[string]bool{
		`{a.example.com}`:                    true,
		`{*.example.com,a.example.com}`:      true,
		`{a.example.com,*.example.com}`:      false, // not in byte order
		`{}`:                                 false,
		`{A.example.com}`:                    false,
		`{*.com}`:                            false,
		`{a.*.example.com}`:                  false,
		`{a*.example.com}`:                   false,
		`{localhost}`:                        false,
		`{a.example.com.}`:                   false,
		`{a.example.com,a.example.com}`:      false,
		`{-a.example.com}`:                   false,
		`{xn--bcher-kva.example,b.example}`:  false,
		`{b.example,xn--bcher-kva.example}`:  true,
		`{a.example.com,b.example.com,NULL}`: false,
	} {
		var got *bool
		if err := pool.QueryRow(ctx, `SELECT valid_l4_server_names_293($1::text[])`, names).Scan(&got); err != nil {
			t.Fatalf("%s: %v", names, err)
		}
		if (got != nil && *got) != want {
			t.Errorf("valid_l4_server_names_293(%s)=%v want %t", names, got, want)
		}
	}

	// Passthrough history blocks the rollback.
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "passthrough-293-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"tls_passthrough":true}'
		WHERE idempotency_key='passthrough-293-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2933" {
		t.Fatalf("down with passthrough history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"tls_passthrough":false}'
		WHERE idempotency_key='passthrough-293-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with only plain responses: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
