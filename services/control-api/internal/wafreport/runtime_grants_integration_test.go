package wafreport

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestWAFReportRuntimeGrantsMigration(t *testing.T) {
	migrator, app := wafReportGrantsTestPools(t)
	now := time.Now().UTC().Truncate(time.Second)
	store := NewStore(app, func() time.Time { return now })
	id := uuid.New()
	policies := []json.RawMessage{json.RawMessage(`{"id":"rule-1"}`)}
	digest := sha256.Sum256(policies[0])
	_, _, err := store.Prepare(t.Context(), id, policies, digest)
	assertWAFReportPGCode(t, err, "42501")
	t.Log("migration 256 / real app role: Prepare denied with 42501")
	assertWAFReportPrivileges(t, migrator, false)

	if err := wafReportMigrate(t, migrator, "up"); err != nil {
		t.Fatal(err)
	}
	assertWAFReportPrivileges(t, migrator, true)
	first, send, err := store.Prepare(t.Context(), id, policies, digest)
	if err != nil || !send || first.Sequence != 1 || first.RequestID == "" {
		t.Fatalf("Prepare after 257: snapshot=%+v send=%t err=%v", first, send, err)
	}
	retry, send, err := store.Prepare(t.Context(), id, policies, digest)
	if err != nil || !send || retry.Sequence != first.Sequence || retry.RequestID != first.RequestID {
		t.Fatalf("unsent replay changed identity: snapshot=%+v send=%t err=%v", retry, send, err)
	}
	for range 2 {
		if err := store.MarkSent(t.Context(), first); err != nil {
			t.Fatal(err)
		}
	}
	retry, send, err = store.Prepare(t.Context(), id, policies, digest)
	if err != nil || send || !retry.Sent || retry.RequestID != first.RequestID {
		t.Fatalf("sent replay: snapshot=%+v send=%t err=%v", retry, send, err)
	}
	policies = []json.RawMessage{json.RawMessage(`{"id":"rule-2"}`)}
	digest = sha256.Sum256(policies[0])
	second, send, err := store.Prepare(t.Context(), id, policies, digest)
	if err != nil || !send || second.Sequence != 2 || second.RequestID == first.RequestID {
		t.Fatalf("changed snapshot: snapshot=%+v send=%t err=%v", second, send, err)
	}
	if err := store.MarkSent(t.Context(), first); err != nil {
		t.Fatal(err)
	}
	retry, send, err = store.Prepare(t.Context(), id, policies, digest)
	if err != nil || !send || retry.RequestID != second.RequestID {
		t.Fatalf("stale acknowledgement changed current snapshot: snapshot=%+v send=%t err=%v", retry, send, err)
	}
	if err := store.MarkSent(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	before := wafReportRowJSON(t, migrator, id)
	if err := wafReportMigrate(t, migrator, "down"); err != nil {
		t.Fatal(err)
	}
	assertWAFReportPrivileges(t, migrator, false)
	_, _, err = store.Prepare(t.Context(), id, policies, digest)
	assertWAFReportPGCode(t, err, "42501")
	assertWAFReportPGCode(t, store.MarkSent(t.Context(), second), "42501")
	if after := wafReportRowJSON(t, migrator, id); after != before {
		t.Fatalf("rollback changed report row: before=%s after=%s", before, after)
	}
	if err := wafReportMigrate(t, migrator, "up"); err != nil {
		t.Fatal(err)
	}
	retry, send, err = store.Prepare(t.Context(), id, policies, digest)
	if err != nil || send || !retry.Sent || retry.Sequence != 2 || retry.RequestID != second.RequestID {
		t.Fatalf("re-up did not restore persisted replay: snapshot=%+v send=%t err=%v", retry, send, err)
	}
	assertWAFReportPrivileges(t, migrator, true)
	t.Log("257 up/down/up: minimum privileges, Prepare/MarkSent replay and persisted row passed")
}

func TestWAFReportRuntimeGrantsPreserveExistingACL(t *testing.T) {
	migrator, _ := wafReportGrantsTestPools(t)
	id := uuid.New()
	if _, err := migrator.Exec(t.Context(), `INSERT INTO waf_custom_rule_report_state(installation_id,sequence,request_id,observed_at,policies,policies_digest,updated_at)
		VALUES($1,1,'existing',now(),'[]',decode(repeat('a',64),'hex'),now())`, id); err != nil {
		t.Fatal(err)
	}
	rowBefore := wafReportRowJSON(t, migrator, id)
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE"} {
		for _, grantOption := range []bool{false, true} {
			if !t.Run(fmt.Sprintf("existing_%s_grant_option_%t", privilege, grantOption), func(t *testing.T) {
				grant := "GRANT " + privilege + " ON waf_custom_rule_report_state TO cdnca_control_app"
				if grantOption {
					grant += " WITH GRANT OPTION"
				}
				if _, err := migrator.Exec(t.Context(), grant); err != nil {
					t.Fatal(err)
				}
				aclBefore := wafReportACL(t, migrator)
				assertWAFReportPGCode(t, wafReportMigrate(t, migrator, "up"), "P2571")
				if aclAfter := wafReportACL(t, migrator); aclAfter != aclBefore {
					t.Fatalf("rejected migration changed ACL: before=%s after=%s", aclBefore, aclAfter)
				}
				if after := wafReportRowJSON(t, migrator, id); after != rowBefore {
					t.Fatal("rejected migration changed existing report")
				}
				var head int
				if err := migrator.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 256 {
					t.Fatalf("rejected migration changed ledger: head=%d err=%v", head, err)
				}
				if _, err := migrator.Exec(t.Context(), "REVOKE "+privilege+" ON waf_custom_rule_report_state FROM cdnca_control_app RESTRICT"); err != nil {
					t.Fatal(err)
				}
			}) {
				return
			}
		}
	}
	if _, err := migrator.Exec(t.Context(), `GRANT REFERENCES ON waf_custom_rule_report_state TO cdnca_control_app;
		GRANT SELECT ON waf_custom_rule_report_state TO cdnca_plugin_webhook_runtime WITH GRANT OPTION`); err != nil {
		t.Fatal(err)
	}
	aclBefore := wafReportACL(t, migrator)
	if err := wafReportMigrate(t, migrator, "up"); err != nil {
		t.Fatal(err)
	}
	var appReferences, otherSelectGrant bool
	if err := migrator.QueryRow(t.Context(), `SELECT has_table_privilege('cdnca_control_app','waf_custom_rule_report_state','REFERENCES'),
		has_table_privilege('cdnca_plugin_webhook_runtime','waf_custom_rule_report_state','SELECT WITH GRANT OPTION')`).Scan(&appReferences, &otherSelectGrant); err != nil || !appReferences || !otherSelectGrant {
		t.Fatalf("unrelated grants changed: app REFERENCES=%t other SELECT grant=%t err=%v", appReferences, otherSelectGrant, err)
	}
	if err := wafReportMigrate(t, migrator, "down"); err != nil {
		t.Fatal(err)
	}
	if aclAfter := wafReportACL(t, migrator); aclAfter != aclBefore {
		t.Fatalf("rollback changed existing ACL: before=%s after=%s", aclBefore, aclAfter)
	}
	if after := wafReportRowJSON(t, migrator, id); after != rowBefore {
		t.Fatal("ACL migration changed report row")
	}
}

// wafReportMigrate runs the migrator over 1..257 only (257 is the migration
// under test; later heads must not be applied or rolled back here).
func wafReportMigrate(t *testing.T, pool *pgxpool.Pool, direction string) error {
	t.Helper()
	return databasetest.MigrateThrough(t.Context(), pool, direction, wafReportGrantsMigration)
}

const wafReportGrantsMigration = 257

func assertWAFReportPGCode(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("PostgreSQL error=%v, want SQLSTATE %s", err, code)
	}
}

func wafReportRowJSON(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var value string
	if err := pool.QueryRow(t.Context(), `SELECT row_to_json(report)::text FROM waf_custom_rule_report_state report WHERE installation_id=$1`, id).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func wafReportACL(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var value string
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(jsonb_build_array(grantor,grantee,privilege_type,is_grantable)
		ORDER BY grantor,grantee,privilege_type,is_grantable),'[]'::jsonb)::text
		FROM pg_class relation CROSS JOIN LATERAL aclexplode(COALESCE(relation.relacl,acldefault('r',relation.relowner))) acl
		WHERE relation.oid='waf_custom_rule_report_state'::regclass`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertWAFReportPrivileges(t *testing.T, pool *pgxpool.Pool, granted bool) {
	t.Helper()
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
		var allowed, grantOption bool
		if err := pool.QueryRow(t.Context(), `SELECT has_table_privilege('cdnca_control_app','waf_custom_rule_report_state',$1),
			has_table_privilege('cdnca_control_app','waf_custom_rule_report_state',$1||' WITH GRANT OPTION')`, privilege).Scan(&allowed, &grantOption); err != nil {
			t.Fatal(err)
		}
		want := granted && (privilege == "SELECT" || privilege == "INSERT" || privilege == "UPDATE")
		if allowed != want || grantOption {
			t.Errorf("%s allowed=%t grant_option=%t, want %t/false", privilege, allowed, grantOption, want)
		}
	}
	var publicCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_class relation CROSS JOIN LATERAL aclexplode(relation.relacl) acl
		WHERE relation.oid='waf_custom_rule_report_state'::regclass AND acl.grantee=0`).Scan(&publicCount); err != nil || publicCount != 0 {
		t.Fatalf("PUBLIC grants=%d err=%v", publicCount, err)
	}
}

func wafReportGrantsTestPools(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is required for real runtime-role migration tests")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "waf_report_grants_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier+" AUTHORIZATION cdnca_control_migrator"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop task schema: %v", err)
		}
	})
	openAs := func(role string) *pgxpool.Pool {
		config, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		config.ConnConfig.RuntimeParams["search_path"] = schema
		config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
			_, err := connection.Exec(ctx, "SET ROLE "+pgx.Identifier{role}.Sanitize())
			return err
		}
		pool, err := pgxpool.NewWithConfig(t.Context(), config)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		var actual string
		var elevated bool
		if err := pool.QueryRow(t.Context(), `SELECT current_user,rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&actual, &elevated); err != nil || actual != role || elevated {
			t.Fatalf("role=%s elevated=%t err=%v", actual, elevated, err)
		}
		return pool
	}
	migrator := openAs("cdnca_control_migrator")
	// The tests exercise 257's own up/down, so the chain stops at 257: 256 is
	// the baseline and "up"/"down" below run through wafReportMigrate.
	if err := databasetest.MigrateThrough(t.Context(), migrator, "up", 256); err != nil {
		t.Fatal(err)
	}
	var count, head int
	if err := migrator.QueryRow(t.Context(), `SELECT count(*),max(version) FROM schema_migrations WHERE integrity_state='verified'`).Scan(&count, &head); err != nil || count != 256 || head != 256 {
		t.Fatalf("full verified baseline=%d/%d err=%v", count, head, err)
	}
	var owner string
	if err := migrator.QueryRow(t.Context(), `SELECT relowner::regrole::text FROM pg_class WHERE oid='waf_custom_rule_report_state'::regclass`).Scan(&owner); err != nil || owner != "cdnca_control_migrator" {
		t.Fatalf("target owner=%s err=%v", owner, err)
	}
	return migrator, openAs("cdnca_control_app")
}
