//go:build integration

package corefactguard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const coreFactTrigger = "zz_core_fact_truncate_guard_045"

func TestCoreFactTruncateGuards(t *testing.T) {
	pool := openTestDatabase(t)
	ctx := t.Context()

	applyMigrationsThrough(t, pool, 45)
	assertMigrationVersion(t, pool, 45)
	assertGuardCoverage(t, pool, true)

	if err := applyMigration045(ctx, pool, "down"); err != nil {
		t.Fatalf("empty migration 045 down: %v", err)
	}
	assertMigrationVersion(t, pool, 44)
	assertGuardCoverage(t, pool, false)
	if err := applyMigration045(ctx, pool, "up"); err != nil {
		t.Fatalf("migration 045 up after down: %v", err)
	}
	assertMigrationVersion(t, pool, 45)
	assertGuardCoverage(t, pool, true)

	seedCoreFacts(t, pool)
	wantState := readFactState(t, pool)

	for _, test := range []struct {
		name string
		sql  string
	}{
		{name: "update", sql: `UPDATE billing_transactions SET reason='tampered'`},
		{name: "delete", sql: `DELETE FROM billing_transactions`},
		{name: "truncate", sql: `TRUNCATE billing_postings`},
		{name: "truncate cascade", sql: `TRUNCATE billing_accounts CASCADE`},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireP0001(t, execSQL(pool, test.sql))
			if got := readFactState(t, pool); got != wantState {
				t.Fatalf("state changed after rejected %s:\n got: %+v\nwant: %+v", test.name, got, wantState)
			}
		})
	}

	err := applyMigration045(ctx, pool, "down")
	postgresError := requireP0001(t, err)
	if !strings.Contains(postgresError.Message, "protected table audit_events contains facts") {
		t.Fatalf("down error = %q", postgresError.Message)
	}
	if got := readFactState(t, pool); got != wantState {
		t.Fatalf("state changed after rejected down:\n got: %+v\nwant: %+v", got, wantState)
	}
	assertGuardCoverage(t, pool, true)
}

func applyMigrationsThrough(t *testing.T, pool *pgxpool.Pool, target int) {
	t.Helper()
	ctx := t.Context()
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= target; version++ {
		matches, err := fs.Glob(migrations.FS, fmt.Sprintf("%03d_*.up.sql", version))
		if err != nil || len(matches) != 1 {
			t.Fatalf("migration %03d up match count = %d, error = %v", version, len(matches), err)
		}
		script, err := fs.ReadFile(migrations.FS, matches[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(script)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, version)
			return err
		}); err != nil {
			t.Fatalf("apply migration %03d: %v", version, err)
		}
	}
}

func applyMigration045(ctx context.Context, pool *pgxpool.Pool, direction string) error {
	script, err := fs.ReadFile(migrations.FS, "045_core_fact_truncate_guards."+direction+".sql")
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			return err
		}
		if direction == "up" {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES(45)`)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=45`)
		}
		return err
	})
}

func openTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "core_fact_guard_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^core_fact_guard_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop core fact guard schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func seedCoreFacts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := t.Context()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	platformScopeID := uuid.MustParse("45000000-0000-0000-0000-000000000001")
	tenantScopeID := uuid.MustParse("45000000-0000-0000-0000-000000000003")
	userID := uuid.MustParse("45000000-0000-0000-0000-000000000004")
	clearingAccountID := uuid.MustParse("45000000-0000-0000-0000-000000000005")
	transactionID := uuid.MustParse("45000000-0000-0000-0000-000000000006")

	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []string{
			`INSERT INTO tenants(id,display_name) VALUES('45000000-0000-0000-0000-000000000002','Guard tenant')`,
			`INSERT INTO access_scopes(id,kind) VALUES('45000000-0000-0000-0000-000000000001','platform')`,
			`INSERT INTO access_scopes(id,kind,tenant_id) VALUES('45000000-0000-0000-0000-000000000003','tenant','45000000-0000-0000-0000-000000000002')`,
			`INSERT INTO users(id,username,display_name,password_hash) VALUES('45000000-0000-0000-0000-000000000004','guard-user','Guard user','not-used')`,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO audit_events(
			id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
			request_id,result,payload,event_hash,occurred_at
		) VALUES($1,$2,1,$3,'test.core_fact_guard','migration','045','guard-request',
			'success','{}',decode(repeat('01',32),'hex'),$4)`, uuid.New(), platformScopeID, userID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO billing_accounts(
			id,scope_id,kind,balance_minor,revision,created_at,updated_at
		) VALUES
			($1,$1,'tenant_liability',100,2,$4,$4),
			($2,$3,'platform_clearing',-100,2,$4,$4)`, tenantScopeID, clearingAccountID, platformScopeID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO billing_transactions(
			id,target_scope_id,operation,direction,amount_minor,reason,created_by_user_id,created_at
		) VALUES($1,$2,'manual_adjustment','credit',100,'guard seed',$3,$4)`, transactionID, tenantScopeID, userID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO billing_postings(
			id,transaction_id,account_id,side,amount_minor,balance_after_minor,created_at
		) VALUES
			($1,$2,$3,'credit',100,100,$6),
			($4,$2,$5,'debit',100,-100,$6)`, uuid.New(), transactionID, tenantScopeID, uuid.New(), clearingAccountID, now); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type factState struct {
	migrationLedger  string
	auditCount       int
	transactionCount int
	postingCount     int
	reason           string
	tenantBalance    int64
	clearingBalance  int64
}

func readFactState(t *testing.T, pool *pgxpool.Pool) factState {
	t.Helper()
	var state factState
	err := pool.QueryRow(t.Context(), `SELECT
		(SELECT string_agg(version::text,',' ORDER BY version) FROM schema_migrations),
		(SELECT count(*) FROM audit_events),
		(SELECT count(*) FROM billing_transactions),
		(SELECT count(*) FROM billing_postings),
		(SELECT reason FROM billing_transactions LIMIT 1),
		(SELECT balance_minor FROM billing_accounts WHERE kind='tenant_liability'),
		(SELECT balance_minor FROM billing_accounts WHERE kind='platform_clearing')
	`).Scan(&state.migrationLedger, &state.auditCount, &state.transactionCount,
		&state.postingCount, &state.reason, &state.tenantBalance, &state.clearingBalance)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func execSQL(pool *pgxpool.Pool, statement string) error {
	_, err := pool.Exec(context.Background(), statement)
	return err
}

func requireP0001(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "P0001" {
		t.Fatalf("error = %v, want PostgreSQL P0001", err)
	}
	return postgresError
}

func assertMigrationVersion(t *testing.T, pool *pgxpool.Pool, want int64) {
	t.Helper()
	var got int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("migration version = %d, want %d", got, want)
	}
}

func assertGuardCoverage(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	wantTables := protectedTables()
	slices.Sort(wantTables)
	rows, err := pool.Query(t.Context(), `SELECT relation.relname
		FROM pg_trigger trigger
		JOIN pg_class relation ON relation.oid=trigger.tgrelid
		JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
		JOIN pg_proc function ON function.oid=trigger.tgfoid
		WHERE namespace.nspname=current_schema() AND trigger.tgname=$1
		  AND NOT trigger.tgisinternal AND trigger.tgenabled='A'
		  AND trigger.tgtype=34 AND function.proname='prevent_core_fact_truncate_045'
		ORDER BY relation.relname`, coreFactTrigger)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var gotTables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		gotTables = append(gotTables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if expected && !slices.Equal(gotTables, wantTables) {
		t.Fatalf("guarded tables = %v, want %v", gotTables, wantTables)
	}
	if !expected && len(gotTables) != 0 {
		t.Fatalf("guarded tables after down = %v", gotTables)
	}
	var functionExists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
		SELECT 1 FROM pg_proc function
		JOIN pg_namespace namespace ON namespace.oid=function.pronamespace
		WHERE namespace.nspname=current_schema() AND function.proname='prevent_core_fact_truncate_045'
	)`).Scan(&functionExists); err != nil {
		t.Fatal(err)
	}
	if functionExists != expected {
		t.Fatalf("guard function exists = %t, want %t", functionExists, expected)
	}
}

func protectedTables() []string {
	return []string{
		"audit_events", "billing_transactions", "billing_postings", "artifact_signing_keys",
		"config_versions", "configuration_artifacts", "rollouts", "node_deployments",
		"node_deployment_artifacts", "edge_command_outbox", "deployment_status_events",
		"artifact_fetch_requests", "node_config_reconciliations", "edge_config_publications",
		"traffic_package_product_snapshots", "traffic_package_buckets", "traffic_package_events",
		"traffic_package_ledger_entries", "node_ca_key_epochs", "node_ca_key_epoch_revocations",
		"node_certificates", "node_certificate_renewal_requests", "node_certificate_revocations",
		"node_certificate_events", "identity_verification_materials",
		"identity_verification_state_events", "identity_verification_submissions",
		"identity_verification_review_assignments", "identity_verification_reviews",
		"identity_verified_persons", "identity_verified_organizations", "admin_impersonation_grants",
		"admin_impersonation_sessions", "admin_impersonation_revocations", "certificate_asset_versions",
		"certificate_asset_private_key_envelope_facts",
		"certificate_asset_activation_facts", "certificate_asset_revocation_facts",
		"certificate_site_binding_facts", "account_recovery_challenges", "mfa_credentials",
		"mfa_credential_events", "mfa_recovery_codes", "mfa_recovery_code_consumptions",
		"mfa_step_up_proofs", "mfa_step_up_uses", "custom_role_revisions",
		"custom_role_deactivations", "custom_role_grants", "custom_role_grant_revocations",
		"custom_rbac_write_requests", "announcement_versions", "announcement_audience_users",
		"announcement_audience_groups", "announcement_recipient_snapshots", "announcement_inbox_events",
		"promotion_policies", "promotion_policy_versions", "promotion_policy_product_targets",
		"promotion_policy_tenant_targets", "promotion_quotes", "promotion_quote_policies",
		"promotion_reservations", "promotion_reservation_events", "promotion_renewal_price_snapshots",
		"promotion_renewal_bindings", "promotion_adjustment_decisions",
	}
}
