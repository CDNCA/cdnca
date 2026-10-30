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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestL4ForwardDisplayIDs214RoundTripConcurrencyAndScopeIsolation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 213)
	now := time.Date(2026, 8, 29, 2, 0, 0, 0, time.UTC)
	scopeA, userA, subscriptionA := seedL4DisplayIdentity214(t, pool, "a", now)
	scopeB, userB, subscriptionB := seedL4DisplayIdentity214(t, pool, "b", now)
	forwardA1 := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	forwardA2 := uuid.MustParse("11111111-1111-4111-8111-111111111112")
	forwardB1 := uuid.MustParse("22222222-2222-4222-8222-222222222221")

	seedL4Forward214(t, pool, forwardA2, scopeA, subscriptionA, userA, "A second", 32102, now.Add(2*time.Minute))
	seedL4Forward214(t, pool, forwardA1, scopeA, subscriptionA, userA, "A first", 32101, now.Add(time.Minute))
	seedL4Forward214(t, pool, forwardB1, scopeB, subscriptionB, userB, "B first", 32201, now.Add(time.Minute))
	seedL4WriteReceipt214(t, pool, forwardA1, scopeA, userA, "stream.create", "create-a1", now)
	seedL4WriteReceipt214(t, pool, forwardA2, scopeA, userA, "stream.update", "update-a2", now)

	var sourceRevisionA, sourceRevisionB int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeA).Scan(&sourceRevisionA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeB).Scan(&sourceRevisionB); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 214); err != nil {
		t.Fatalf("213 -> 214: %v", err)
	}
	assertL4DisplayID214(t, pool, forwardA1, 1)
	assertL4DisplayID214(t, pool, forwardA2, 2)
	assertL4DisplayID214(t, pool, forwardB1, 1)
	assertL4ReceiptDisplayID214(t, pool, "create-a1", "1")
	assertL4ReceiptDisplayID214(t, pool, "update-a2", "2")
	assertL4SourceRevision214(t, pool, scopeA, sourceRevisionA)
	assertL4SourceRevision214(t, pool, scopeB, sourceRevisionB)

	const concurrent = 10
	displayIDs := make(chan int64, concurrent)
	errorsCh := make(chan error, concurrent)
	var wait sync.WaitGroup
	for index := 0; index < concurrent; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			var displayID int64
			err := pool.QueryRow(t.Context(), l4Insert214(true), uuid.New(), scopeA, subscriptionA, userA,
				fmt.Sprintf("A concurrent %02d", index), 32300+index, now.Add(time.Duration(index+10)*time.Minute)).Scan(&displayID)
			if err != nil {
				errorsCh <- err
				return
			}
			displayIDs <- displayID
		}(index)
	}
	wait.Wait()
	close(errorsCh)
	close(displayIDs)
	for err := range errorsCh {
		t.Fatalf("concurrent allocation: %v", err)
	}
	got := make([]int, 0, concurrent)
	for displayID := range displayIDs {
		got = append(got, int(displayID))
	}
	sort.Ints(got)
	for index, displayID := range got {
		if displayID != index+3 {
			t.Fatalf("concurrent L4 display IDs=%v, want 3..%d", got, concurrent+2)
		}
	}

	var isolated int64
	if err := pool.QueryRow(t.Context(), l4Insert214(true), uuid.New(), scopeB, subscriptionB, userB,
		"B isolated", 32401, now.Add(time.Hour)).Scan(&isolated); err != nil || isolated != 2 {
		t.Fatalf("scope-isolated L4 display ID=(%d,%v), want 2", isolated, err)
	}

	_, err := pool.Exec(t.Context(), `INSERT INTO l4_forwards(
		id,display_id,scope_id,package_subscription_id,owner_user_id,name,protocol,listen_address,
		listen_port,upstream_address,upstream_port,connect_timeout_ms,response_timeout_ms,
		max_connections_per_client,proxy_protocol_v1,enabled,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,99,$2,$3,$4,'manual','tcp','*',32501,'192.0.2.99',9000,
		3000,30000,100,false,true,$4,$4,$5,$5)`, uuid.New(), scopeA, subscriptionA, userA, now.Add(2*time.Hour))
	assertL4DisplayPostgresCode214(t, err, "P2141")
	_, err = pool.Exec(t.Context(), `UPDATE l4_forwards SET display_id=99 WHERE id=$1`, forwardA1)
	assertL4DisplayPostgresCode214(t, err, "P2142")

	if err := migrateVersionIsolated(t.Context(), pool, "down", 214); err != nil {
		t.Fatalf("214 -> 213: %v", err)
	}
	assertL4DisplaySchema214(t, pool, false)
	assertL4ReceiptDisplayID214(t, pool, "create-a1", "")
	assertL4ReceiptDisplayID214(t, pool, "update-a2", "")
	if err := migrateVersionIsolated(t.Context(), pool, "up", 214); err != nil {
		t.Fatalf("213 -> 214 reapply: %v", err)
	}
	assertL4DisplayID214(t, pool, forwardA1, 1)
	assertL4DisplayID214(t, pool, forwardA2, 2)
	assertL4DisplayID214(t, pool, forwardB1, 1)
	assertL4ReceiptDisplayID214(t, pool, "create-a1", "1")
	assertL4ReceiptDisplayID214(t, pool, "update-a2", "2")
}

func seedL4DisplayIdentity214(
	t *testing.T,
	pool *pgxpool.Pool,
	suffix string,
	now time.Time,
) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID, subscriptionID, productID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	displayName := "L4 display " + suffix
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{tenantID, displayName}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'unused')`,
			[]any{userID, "l4-display-214-" + suffix, displayName}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed L4 identity %s: %v", suffix, err)
		}
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='replica'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscriptions(
		id,tenant_scope_id,product_id,product_revision,product_snapshot,
		site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,
		custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,revision,
		created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3::uuid,1,jsonb_build_object('id',$3::uuid::text,'revision',1,'name','L4 display','spec','{}'::jsonb),
		10,10,10,-1,$4,$5,'UTC','monthly',0,1,1,'active',1,$6,$6,$4,$4)`,
		subscriptionID, scopeID, productID, now.Add(-time.Hour), now.Add(24*time.Hour), userID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role='origin'`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID, subscriptionID
}

func seedL4Forward214(
	t *testing.T,
	pool *pgxpool.Pool,
	id, scopeID, subscriptionID, userID uuid.UUID,
	name string,
	port int,
	createdAt time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), l4Insert214(false), id, scopeID, subscriptionID, userID, name, port, createdAt); err != nil {
		t.Fatalf("seed L4 forward %s: %v", id, err)
	}
}

func l4Insert214(returnDisplayID bool) string {
	query := `INSERT INTO l4_forwards(
		id,scope_id,package_subscription_id,owner_user_id,name,protocol,listen_address,listen_port,
		upstream_address,upstream_port,connect_timeout_ms,response_timeout_ms,max_connections_per_client,
		proxy_protocol_v1,enabled,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'tcp','*',$6,'192.0.2.10',9000,3000,30000,100,false,true,$4,$4,$7,$7)`
	if returnDisplayID {
		query += ` RETURNING display_id`
	}
	return query
}

func seedL4WriteReceipt214(
	t *testing.T,
	pool *pgxpool.Pool,
	forwardID, scopeID, userID uuid.UUID,
	operation, key string,
	createdAt time.Time,
) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO l4_write_requests(
		id,actor_user_id,target_scope_id,operation,idempotency_key,request_digest,resource_id,
		response_status,response_body,created_at,completed_at)
		VALUES($1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::bytea,$7::uuid,200,
			jsonb_build_object('id',$7::uuid::text,'name',$5::text),$8::timestamptz,$8::timestamptz)`,
		uuid.New(), userID, scopeID, operation, key, bytes.Repeat([]byte{byte(len(key))}, 32), forwardID, createdAt); err != nil {
		t.Fatalf("seed L4 write receipt %s: %v", key, err)
	}
}

func assertL4DisplayID214(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT display_id FROM l4_forwards WHERE id=$1`, id).Scan(&got); err != nil || got != want {
		t.Fatalf("L4 forward %s display_id=(%d,%v), want %d", id, got, err, want)
	}
}

func assertL4ReceiptDisplayID214(t *testing.T, pool *pgxpool.Pool, key, want string) {
	t.Helper()
	var got *string
	if err := pool.QueryRow(t.Context(), `SELECT response_body->>'display_id' FROM l4_write_requests
		WHERE idempotency_key=$1`, key).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if want == "" && got != nil {
		t.Fatalf("L4 receipt %s display_id=%q, want absent", key, *got)
	}
	if want != "" && (got == nil || *got != want) {
		t.Fatalf("L4 receipt %s display_id=%v, want %q", key, got, want)
	}
}

func assertL4SourceRevision214(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, scopeID).Scan(&got); err != nil || got != want {
		t.Fatalf("L4 source revision=(%d,%v), want %d", got, err, want)
	}
}

func assertL4DisplaySchema214(t *testing.T, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var column, sequence bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='l4_forwards' AND column_name='display_id'),
		to_regclass(current_schema() || '.l4_forward_display_id_sequences') IS NOT NULL`).Scan(&column, &sequence); err != nil {
		t.Fatal(err)
	}
	if column != want || sequence != want {
		t.Fatalf("L4 display schema column/sequence=%v/%v, want %v", column, sequence, want)
	}
}

func assertL4DisplayPostgresCode214(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("postgres error=%v, want %s", err, want)
	}
}
