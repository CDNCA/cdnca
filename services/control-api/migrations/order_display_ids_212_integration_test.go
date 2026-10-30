//go:build integration

package migrations_test

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestOrderDisplayIDs212RoundTripConcurrencyAndScopeIsolation(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 211)
	now := time.Date(2026, 8, 28, 2, 0, 0, 0, time.UTC)
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	manualA, manualB := uuid.New(), uuid.New()
	packageA, packageB := uuid.New(), uuid.New()
	rechargeA, rechargeB := uuid.New(), uuid.New()

	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name) VALUES($1,'Order display A'),($2,'Order display B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES
			($5,'order-display-a','Order display A','unused'),($6,'order-display-b','Order display B','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($4,$6)`,
		pgx.QueryExecModeSimpleProtocol, tenantA, tenantB, scopeA, scopeB, userA, userB); err != nil {
		t.Fatalf("seed identities: %v", err)
	}
	for _, seed := range []struct {
		scope, tenant, user, manual, packageID, recharge uuid.UUID
		created                                          time.Time
	}{
		{scopeA, tenantA, userA, manualA, packageA, rechargeA, now},
		{scopeB, tenantB, userB, manualB, packageB, rechargeB, now.Add(time.Minute)},
	} {
		if _, err := pool.Exec(t.Context(), `
			INSERT INTO account_order_records(
				id,tenant_scope_id,tenant_id,user_id,order_type,note,original_amount_minor,
				paid_amount_minor,payment_method,merchant_order_number,transaction_number,status,
				paid_at,revision,created_by_user_id,updated_by_user_id,created_at,recorded_at,updated_at)
			VALUES($1,$2,$3,$4,'purchase','',100,0,'','','','unpaid',NULL,1,$4,$4,$5,$5,$5);
			INSERT INTO package_orders(
				id,tenant_scope_id,user_id,operation,product_kind,product_id,product_revision,
				package_period,product_snapshot,entitlement_snapshot,pricing_snapshot,currency,
				original_amount_minor,discount_amount_minor,payable_amount_minor,settlement_direction,
				funding_source,effective_mode,effective_at,request_id,trace_id,created_by_scope_id,
				created_by_user_id,created_at)
			VALUES($6,$2,$4,'purchase','package_subscription',$7,1,'month','{}','{}','{}','CNY',
				100,0,100,'debit','balance','immediate',$5,$8,$8,$2,$4,$5);
			INSERT INTO recharge_orders_v1(
				id,tenant_scope_id,tenant_id,user_id,channel,amount_minor,currency,state,revision,created_at,updated_at)
			VALUES($9,$2,$3,$4,'alipay',100,'CNY','pending',1,$5,$5)`,
			pgx.QueryExecModeSimpleProtocol, seed.manual, seed.scope, seed.tenant, seed.user, seed.created, seed.packageID,
			uuid.New(), "order-display-"+seed.packageID.String(), seed.recharge); err != nil {
			t.Fatalf("seed order facts: %v", err)
		}
	}

	if err := migrateVersionIsolated(t.Context(), pool, "up", 212); err != nil {
		t.Fatalf("211 -> 212: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 212)
	for _, row := range []struct {
		table string
		id    uuid.UUID
	}{
		{"account_order_records", manualA}, {"account_order_records", manualB},
		{"package_orders", packageA}, {"package_orders", packageB},
		{"recharge_orders_v1", rechargeA}, {"recharge_orders_v1", rechargeB},
	} {
		var displayID int64
		if err := pool.QueryRow(t.Context(), fmt.Sprintf(`SELECT display_id FROM %s WHERE id=$1`, row.table), row.id).Scan(&displayID); err != nil || displayID != 1 {
			t.Fatalf("%s %s display_id=(%d,%v), want 1", row.table, row.id, displayID, err)
		}
	}

	const concurrent = 12
	displayIDs := make(chan int, concurrent)
	errorsCh := make(chan error, concurrent)
	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			var displayID int
			err := pool.QueryRow(t.Context(), `INSERT INTO account_order_records(
				id,tenant_scope_id,tenant_id,user_id,order_type,note,original_amount_minor,
				paid_amount_minor,payment_method,merchant_order_number,transaction_number,status,
				paid_at,revision,created_by_user_id,updated_by_user_id,created_at,recorded_at,updated_at)
				VALUES($1,$2,$3,$4,'purchase','',100,0,'','','','unpaid',NULL,1,$4,$4,$5,$5,$5)
				RETURNING display_id`, uuid.New(), scopeA, tenantA, userA, now.Add(time.Duration(index+2)*time.Minute)).Scan(&displayID)
			if err != nil {
				errorsCh <- err
				return
			}
			displayIDs <- displayID
		}(i)
	}
	wg.Wait()
	close(errorsCh)
	close(displayIDs)
	for err := range errorsCh {
		t.Fatalf("concurrent allocation: %v", err)
	}
	got := make([]int, 0, concurrent)
	for displayID := range displayIDs {
		got = append(got, displayID)
	}
	sort.Ints(got)
	for index, displayID := range got {
		if displayID != index+2 {
			t.Fatalf("concurrent display IDs=%v, want 2..%d", got, concurrent+1)
		}
	}

	var isolated int
	if err := pool.QueryRow(t.Context(), `INSERT INTO account_order_records(
		id,tenant_scope_id,tenant_id,user_id,order_type,note,original_amount_minor,
		paid_amount_minor,payment_method,merchant_order_number,transaction_number,status,
		paid_at,revision,created_by_user_id,updated_by_user_id,created_at,recorded_at,updated_at)
		VALUES($1,$2,$3,$4,'purchase','',100,0,'','','','unpaid',NULL,1,$4,$4,$5,$5,$5)
		RETURNING display_id`, uuid.New(), scopeB, tenantB, userB, now.Add(time.Hour)).Scan(&isolated); err != nil || isolated != 2 {
		t.Fatalf("scope-isolated display ID=(%d,%v), want 2", isolated, err)
	}

	_, err := pool.Exec(t.Context(), `INSERT INTO account_order_records(
		id,display_id,tenant_scope_id,tenant_id,user_id,order_type,note,original_amount_minor,
		paid_amount_minor,payment_method,merchant_order_number,transaction_number,status,
		paid_at,revision,created_by_user_id,updated_by_user_id,created_at,recorded_at,updated_at)
		VALUES($1,99,$2,$3,$4,'purchase','',100,0,'','','','unpaid',NULL,1,$4,$4,$5,$5,$5)`,
		uuid.New(), scopeA, tenantA, userA, now.Add(2*time.Hour))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P2121" {
		t.Fatalf("allocator ownership error=%v, want P2121", err)
	}

	down, err := controlmigrations.FS.ReadFile("212_order_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	fenced, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fenced.Exec(t.Context(), `INSERT INTO schema_migrations(
		version,migration_id,checksum_sha256,down_checksum_sha256,integrity_state,metadata_recorded_at,applied_at)
		VALUES(213,'unexpected_head',repeat('a',64),repeat('b',64),'verified',now(),now())`); err != nil {
		t.Fatal(err)
	}
	_, err = fenced.Exec(t.Context(), string(down))
	if !errors.As(err, &pgErr) || pgErr.Code != "P2120" {
		t.Fatalf("rollback fence error=%v, want P2120", err)
	}
	if err := fenced.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := migrateVersionIsolated(t.Context(), pool, "down", 212); err != nil {
		t.Fatalf("212 -> 211: %v", err)
	}
	assertPackageCommerceRBAC079Ledger(t, pool, 211)
	for _, table := range []string{"account_order_records", "package_orders", "recharge_orders_v1"} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name='display_id')`, table).Scan(&exists); err != nil || exists {
			t.Fatalf("%s display_id after rollback=(%v,%v)", table, exists, err)
		}
	}
}
