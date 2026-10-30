//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDNSReconcile076MigrationFilesEmbedded(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("076_dns_reconcile_facts.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlmigrations.FS.ReadFile("076_dns_reconcile_facts.down.sql"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"dns_reconcile_tasks",
		"dns_reconcile_operations",
		"dns_reconcile_provider_reports",
		"dns_reconcile_propagation_attempts",
		"dns_reconcile_commit_facts",
		"dns_reconcile_cancel_facts",
	} {
		if !strings.Contains(string(up), "CREATE TABLE "+table) {
			t.Errorf("076 up does not create %s", table)
		}
	}
}

func TestDNSReconcile076MigrationRoundTrip(t *testing.T) {
	pool, cleanup := newDNSReconcile076Pool(t)
	defer cleanup()

	if err := applyDNSReconcile076Down(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	assertDNSReconcile076State(t, pool, 75, false)
	if err := applyDNSReconcile076Up(t.Context(), pool, 76); err != nil {
		t.Fatal(err)
	}
	assertDNSReconcile076State(t, pool, 76, true)
}

func TestDNSReconcile076DownRejectsFactsAndFactsAreAppendOnly(t *testing.T) {
	pool, cleanup := newDNSReconcile076Pool(t)
	defer cleanup()
	fixture := seedDNSReconcile076Base(t, pool, "guard")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return insertDNSReconcile076Facts(t.Context(), tx, fixture)
	}); err != nil {
		t.Fatal(err)
	}
	assertDNSReconcile076PGCode(t, applyDNSReconcile076Down(t.Context(), pool), "55000")
	assertDNSReconcile076State(t, pool, 76, true)
	assertDNSReconcile076PGCode(t, func() error {
		_, err := pool.Exec(t.Context(), `UPDATE dns_reconcile_tasks
			SET required_consecutive=4 WHERE tenant_id=$1 AND job_id=$2`, fixture.tenantID, fixture.jobID)
		return err
	}(), "P0001")
}

func TestDNSReconcile076DownSerializesUncommittedWriter(t *testing.T) {
	pool, cleanup := newDNSReconcile076Pool(t)
	defer cleanup()
	fixture := seedDNSReconcile076Base(t, pool, "down-race")
	writer, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(context.WithoutCancel(t.Context()))
	if err := insertDNSReconcile076Facts(t.Context(), writer, fixture); err != nil {
		t.Fatal(err)
	}
	var writerPID int
	if err := writer.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&writerPID); err != nil {
		t.Fatal(err)
	}

	downPool := newDNSReconcile076MigrationPool(t, pool, "dns_reconcile_076_down_waiter")
	defer downPool.Close()
	downContext, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	downConn, err := downPool.Acquire(downContext)
	if err != nil {
		t.Fatal(err)
	}
	var downPID int
	if err := downConn.QueryRow(downContext, `SELECT pg_backend_pid()`).Scan(&downPID); err != nil {
		downConn.Release()
		t.Fatal(err)
	}
	downResult := make(chan error, 1)
	go func() {
		err := applyDNSReconcile076DownConnection(downContext, downConn)
		downConn.Release()
		downResult <- err
	}()
	waitDNSReconcile076Blocked(t, pool, writerPID, downPID)
	if err := writer.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-downResult:
		assertDNSReconcile076PGCode(t, err, "55000")
	case <-downContext.Done():
		t.Fatalf("wait for 076 down: %v", downContext.Err())
	}
	assertDNSReconcile076State(t, pool, 76, true)
}

type dnsReconcile076Fixture struct {
	tenantID, scopeID, siteID, zoneID, jobID uuid.UUID
	createdAt                                time.Time
	jobKey                                   string
	jobDigest                                []byte
}

func seedDNSReconcile076Base(t *testing.T, pool *pgxpool.Pool, suffix string) dnsReconcile076Fixture {
	t.Helper()
	fixture := dnsReconcile076Fixture{
		tenantID: uuid.New(), scopeID: uuid.New(), siteID: uuid.New(), zoneID: uuid.New(),
		jobID: uuid.New(), createdAt: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		jobKey: "dnsr-" + strings.Repeat("a", 64), jobDigest: bytesOf076(1),
	}
	userID := uuid.New()
	username := "dns076" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET CONSTRAINTS ALL DEFERRED`); err != nil {
			return err
		}
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{fixture.tenantID, "DNS 076 " + suffix}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'hash')`, []any{userID, username, "DNS 076 " + suffix}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, userID}},
			{`INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			 VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3)`, []any{fixture.siteID, fixture.scopeID, userID, suffix + ".example.test"}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{fixture.siteID}},
			{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, []any{fixture.siteID}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertDNSReconcile076Facts(ctx context.Context, tx pgx.Tx, fixture dnsReconcile076Fixture) error {
	if _, err := tx.Exec(ctx, `INSERT INTO background_jobs(
		id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,trace_id,
		state,attempt,max_attempts,claimable_at,total_count,created_at,updated_at
	) VALUES($1,$2,'dns_reconcile','dns_reconcile/site',$3,$4,
		'request-076','','queued',0,20,$5,1,$5,$5)`,
		fixture.jobID, fixture.tenantID, fixture.jobKey, fixture.jobDigest, fixture.createdAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO background_job_items(
		tenant_id,job_id,ordinal,item_id,state
	) VALUES($1,$2,1,'reconcile','pending')`, fixture.tenantID, fixture.jobID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO dns_reconcile_tasks(
		tenant_id,tenant_scope_id,job_id,site_id,zone_id,idempotency_key,job_idempotency_key,
		payload_digest,job_request_digest,canonical_request,plan_digest,deterministic_plan,
		initial_provider_revision,required_consecutive,created_at
	) VALUES($1,$2,$3,$4,$5,'raw-key',$6,$7,$8,'{}'::jsonb,$9,'{}'::jsonb,7,3,$10)`,
		fixture.tenantID, fixture.scopeID, fixture.jobID, fixture.siteID, fixture.zoneID,
		fixture.jobKey, bytesOf076(2), fixture.jobDigest, bytesOf076(3), fixture.createdAt)
	return err
}

func bytesOf076(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), sha256.Size))
}

func newDNSReconcile076MigrationPool(t *testing.T, pool *pgxpool.Pool, applicationName string) *pgxpool.Pool {
	t.Helper()
	config := pool.Config()
	config.MaxConns = 1
	config.MinConns = 0
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	config.ConnConfig.RuntimeParams["lock_timeout"] = "10s"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "12s"
	result, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func applyDNSReconcile076DownConnection(ctx context.Context, database interface {
	Begin(context.Context) (pgx.Tx, error)
}) error {
	script, err := controlmigrations.FS.ReadFile("076_dns_reconcile_facts.down.sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, database, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=76`)
		if err == nil && command.RowsAffected() != 1 {
			return fmt.Errorf("delete 076 ledger rows = %d, want 1", command.RowsAffected())
		}
		return err
	})
}

func waitDNSReconcile076Blocked(t *testing.T, pool *pgxpool.Pool, writerPID, downPID int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $1::integer = ANY(pg_catalog.pg_blocking_pids($2::integer))`,
			writerPID, downPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for 076 down backend %d to block on writer backend %d", downPID, writerPID)
		case <-ticker.C:
		}
	}
}

func assertDNSReconcile076PGCode(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, want)
	}
}

func newDNSReconcile076Pool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	pool, cleanup := new069Pool(t)
	migrate069(t, pool, "up")
	for version := int64(70); version <= 76; version++ {
		if err := applyDNSReconcile076Up(t.Context(), pool, version); err != nil {
			cleanup()
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
	assertDNSReconcile076State(t, pool, 76, true)
	return pool, cleanup
}

func applyDNSReconcile076Up(ctx context.Context, pool *pgxpool.Pool, version int64) error {
	upMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
	if err != nil || len(upMatches) != 1 {
		return fmt.Errorf("resolve migration %03d up: matches=%v err=%w", version, upMatches, err)
	}
	downMatches, err := fs.Glob(controlmigrations.FS, fmt.Sprintf("%03d_*.down.sql", version))
	if err != nil || len(downMatches) != 1 {
		return fmt.Errorf("resolve migration %03d down: matches=%v err=%w", version, downMatches, err)
	}
	up, err := fs.ReadFile(controlmigrations.FS, upMatches[0])
	if err != nil {
		return err
	}
	down, err := fs.ReadFile(controlmigrations.FS, downMatches[0])
	if err != nil {
		return err
	}
	identifier := strings.TrimSuffix(upMatches[0], ".up.sql")
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(up)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(
			version,migration_id,checksum_sha256,down_checksum_sha256,
			integrity_state,metadata_recorded_at
		) VALUES($1,$2,$3,$4,'verified',now())`, version, identifier,
			fmt.Sprintf("%x", sha256.Sum256(up)), fmt.Sprintf("%x", sha256.Sum256(down)))
		return err
	})
}

func applyDNSReconcile076Down(ctx context.Context, pool *pgxpool.Pool) error {
	script, err := controlmigrations.FS.ReadFile("076_dns_reconcile_facts.down.sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=76`)
		if err == nil && command.RowsAffected() != 1 {
			return fmt.Errorf("delete 076 ledger rows = %d, want 1", command.RowsAffected())
		}
		return err
	})
}

func assertDNSReconcile076State(t *testing.T, pool *pgxpool.Pool, wantVersion int64, wantTables bool) {
	t.Helper()
	var version int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != wantVersion {
		t.Fatalf("migration version=%d, want %d", version, wantVersion)
	}
	for _, table := range []string{
		"dns_reconcile_tasks", "dns_reconcile_operations", "dns_reconcile_provider_reports",
		"dns_reconcile_propagation_attempts", "dns_reconcile_task_events", "dns_reconcile_commit_facts",
		"dns_reconcile_cancel_facts",
	} {
		var exists bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists != wantTables {
			t.Fatalf("table %s exists=%t, want %t", table, exists, wantTables)
		}
	}
}
