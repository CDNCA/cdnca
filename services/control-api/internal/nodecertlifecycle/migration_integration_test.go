//go:build integration

package nodecertlifecycle

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNodeCertificateLifecycleMigrationPreservesLegacyFacts(t *testing.T) {
	pool := openLifecycleTestDatabase(t, false)
	ctx := context.Background()
	migrateLifecycleDependencies(t, pool, 35)
	if version := migrationVersion(t, pool); version != 35 {
		t.Fatalf("migration version = %d, want 35", version)
	}
	seedLegacyNodeCertificateFacts(t, pool)

	applyLifecycleMigration(t, pool, "up")
	assertLegacyLifecycleState(t, pool)
	assertNoNodeCertificateSecretColumns(t, pool)
	assertLifecycleTruncateGuards(t, pool, true)
	assertLifecycleHistoryCannotBeTruncated(t, pool)

	applyLifecycleMigration(t, pool, "down")
	assertLifecycleColumns(t, pool, false)
	assertLegacyFactsPreserved(t, pool)
	assertLifecycleTruncateGuards(t, pool, false)

	applyLifecycleMigration(t, pool, "up")
	assertLegacyLifecycleState(t, pool)
	assertNoNodeCertificateSecretColumns(t, pool)
	assertLifecycleTruncateGuards(t, pool, true)
	assertLifecycleHistoryCannotBeTruncated(t, pool)

	var version int64
	if err := pool.QueryRow(ctx, `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 35 {
		t.Fatalf("direct 036 script roundtrip changed migration ledger version to %d, want 35", version)
	}
}

func TestNodeCertificateLifecycleMigrationDownBlocksLateWriter(t *testing.T) {
	fixture := newLifecycleFixture036(t)
	script, err := fs.ReadFile(controlmigrations.FS, "036_node_certificate_lifecycle.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	marker := strings.Index(string(script), "DO $$")
	if marker < 1 {
		t.Fatal("migration 036 down lock/check boundary is missing")
	}
	down, err := fixture.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = down.Rollback(context.Background()) })
	if _, err := down.Exec(context.Background(), string(script[:marker])); err != nil {
		t.Fatal(err)
	}

	ca, _ := testCertificateAuthority(t, fixture.clock.Now())
	caPEM := certificatePEM(ca)
	_, caDigest, publicKeyDigest, err := validateCACertificate(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	epochID := uuid.New()
	requestID := uuid.New()
	requestDigest := sha256.Sum256([]byte("late-writer-ca-epoch"))
	writerResult := make(chan error, 1)
	go func() {
		_, err := fixture.pool.Exec(context.Background(), `INSERT INTO node_ca_key_epochs(
			id,installation_id,epoch,key_id,ca_certificate_pem,ca_certificate_sha256,public_key_sha256,
			not_before,not_after,status,request_id,request_digest,created_by_scope_id,created_by_user_id,created_at)
			VALUES($1,$2,1,'late-writer-ca',$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12)`,
			epochID, fixture.installationID, caPEM, caDigest[:], publicKeyDigest[:], ca.NotBefore, ca.NotAfter,
			requestID, requestDigest[:], fixture.actor.ScopeID, fixture.actor.UserID, fixture.clock.Now())
		writerResult <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-writerResult:
			t.Fatalf("late lifecycle writer returned before migration down released its lock: %v", err)
		default:
		}
		var waiting bool
		if err := fixture.pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM pg_locks
			WHERE relation='node_ca_key_epochs'::regclass
			  AND mode='RowExclusiveLock' AND NOT granted
		)`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late lifecycle writer did not wait for migration down")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := down.Exec(context.Background(), string(script[marker:])); err != nil {
		t.Fatal(err)
	}
	if err := down.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-writerResult; err == nil {
		t.Fatal("late lifecycle writer succeeded after migration down")
	}
	if version := migrationVersion(t, fixture.pool); version != 36 {
		t.Fatalf("direct 036 down script changed migration ledger version to %d, want 36", version)
	}
	var epochTableExists bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT to_regclass(current_schema() || '.node_ca_key_epochs') IS NOT NULL`).Scan(&epochTableExists); err != nil {
		t.Fatal(err)
	}
	if epochTableExists {
		t.Fatal("node_ca_key_epochs still exists after migration down")
	}
}

// lifecycleMigrationHead is 036_node_certificate_lifecycle, the migration under test.
const lifecycleMigrationHead = 36

func openLifecycleTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "node_cert_lifecycle_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_cert_lifecycle_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("refusing unexpected schema %q", schema)
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
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop lifecycle migration schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		// 268 的 down 是刻意的单向闸门，不能从发布头回滚到 036；夹具只装载 1..036。
		if err := databasetest.MigrateThrough(context.Background(), pool, "up", lifecycleMigrationHead); err != nil {
			t.Fatal(err)
		}
		if version := migrationVersion(t, pool); version != 36 {
			t.Fatalf("lifecycle fixture migration version = %d, want 36", version)
		}
	}
	return pool
}

func migrateLifecycleDependencies(t *testing.T, pool *pgxpool.Pool, maximumVersion int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `CREATE TABLE schema_migrations (
		version bigint PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		t.Fatal(err)
	}
	entries, err := fs.ReadDir(controlmigrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	for version := int64(1); version <= maximumVersion; version++ {
		prefix := fmt.Sprintf("%03d_", version)
		var name string
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !strings.HasSuffix(entry.Name(), ".up.sql") {
				continue
			}
			if name != "" {
				t.Fatalf("multiple up migrations for version %d: %s and %s", version, name, entry.Name())
			}
			name = entry.Name()
		}
		if name == "" {
			t.Fatalf("missing up migration for lifecycle dependency version %d", version)
		}
		script, err := fs.ReadFile(controlmigrations.FS, name)
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
			t.Fatalf("apply lifecycle dependency migration %d (%s): %v", version, name, err)
		}
	}
}

func seedLegacyNodeCertificateFacts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC)
	scopeID := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	userID := uuid.MustParse("10000000-0000-0000-0000-000000000002")
	nodeID := uuid.MustParse("10000000-0000-0000-0000-000000000003")
	tokenID := uuid.MustParse("10000000-0000-0000-0000-000000000004")
	authorizationID := uuid.MustParse("10000000-0000-0000-0000-000000000005")
	certificateID := uuid.MustParse("10000000-0000-0000-0000-000000000006")
	renewalID := uuid.MustParse("10000000-0000-0000-0000-000000000007")
	revocationID := uuid.MustParse("10000000-0000-0000-0000-000000000008")

	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		statements := []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'legacy-node-operator','Legacy Node Operator','test-hash')`, []any{userID}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, userID}},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at)
			  VALUES($1,$2,'legacy-node','active',$3,$4,$4)`, []any{nodeID, scopeID, userID, now}},
			{`INSERT INTO node_enrollment_tokens(
				id,node_id,purpose,token_hash,created_by_user_id,created_at,expires_at
			  ) VALUES($1,$2,'initial_enrollment',$3,$4,$5,$6)`, []any{
				tokenID, nodeID, lifecycleDigest(1), userID, now.Add(-2 * time.Hour), now.Add(2 * time.Hour),
			}},
			{`INSERT INTO node_enrollment_authorizations(
				id,token_id,node_id,purpose,request_id,request_digest,authorized_at
			  ) VALUES($1,$2,$3,'initial_enrollment','legacy-enrollment-request',$4,$5)`, []any{
				authorizationID, tokenID, nodeID, lifecycleDigest(2), now.Add(-time.Hour),
			}},
			{`INSERT INTO node_identity_authorizations(
				id,token_id,node_id,purpose,request_id,request_digest,token_hash,csr_der,csr_sha256,
				machine_fingerprint_sha256,protocol_min_major,protocol_min_minor,protocol_max_major,
				protocol_max_minor,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
				capabilities_sha256,gateway_workload_identity,gateway_instance_id,artifact_key_id,
				artifact_public_key,status,authorized_at,expires_at
			  ) VALUES($1,$2,$3,'initial_enrollment',$4,$5,$6,$7,$8,$9,1,0,1,0,1,0,$10,$11,
				'spiffe://cdn-platform/gateway/legacy','gateway-legacy','x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
				$12,'authorized',$13,$14)`, []any{
				authorizationID, tokenID, nodeID, uuid.MustParse("10000000-0000-0000-0000-000000000009"),
				lifecycleDigest(3), lifecycleDigest(4), []byte("legacy-csr"), lifecycleDigest(5), lifecycleDigest(6),
				[]byte(`{"version":1}`), lifecycleDigest(7), lifecycleDigest(8), now.Add(-time.Hour), now.Add(time.Hour),
			}},
			{`INSERT INTO node_certificates(
				id,node_id,issuance_kind,enrollment_authorization_id,serial_number,csr_sha256,
				certificate_public_key_sha256,uri_san,not_before,not_after,renewal_at,
				leaf_certificate_pem,issuing_chain_pem,leaf_certificate_sha256,status,issued_at
			  ) VALUES($1,$2,'initial',$3,'abcdef',$4,$5,$6,$7,$8,$9,$10,ARRAY[$11::bytea],$12,'active',$13)`, []any{
				certificateID, nodeID, authorizationID, lifecycleDigest(5), lifecycleDigest(9),
				"spiffe://cdn-platform/node/" + nodeID.String(), now.Add(-24 * time.Hour), now.Add(24 * time.Hour),
				now.Add(12 * time.Hour), []byte("legacy-leaf-pem"), []byte("legacy-ca-pem"), lifecycleDigest(10), now.Add(-24 * time.Hour),
			}},
			{`INSERT INTO node_certificate_renewal_requests(
				request_id,request_digest,node_id,current_certificate_id,current_serial_number,csr_der,
				csr_sha256,gateway_workload_identity,gateway_instance_id,status,created_at,expires_at
			  ) VALUES($1,$2,$3,$4,'abcdef',$5,$6,'spiffe://cdn-platform/gateway/legacy',
				'gateway-legacy','pending',$7,$8)`, []any{
				renewalID, lifecycleDigest(11), nodeID, certificateID, []byte("legacy-renewal-csr"), lifecycleDigest(12), now, now.Add(time.Hour),
			}},
			{`INSERT INTO node_certificate_revocations(
				request_id,request_digest,certificate_id,node_id,reason,revoked_at,authorization_revision
			  ) VALUES($1,$2,$3,$4,'legacy recorded revocation',$5,2)`, []any{
				revocationID, lifecycleDigest(13), certificateID, nodeID, now.Add(30 * time.Minute),
			}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func applyLifecycleMigration(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	name := "036_node_certificate_lifecycle." + direction + ".sql"
	script, err := fs.ReadFile(controlmigrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(context.Background(), pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), string(script))
		return err
	})
	if err != nil {
		t.Fatalf("apply migration 036 %s: %v", direction, err)
	}
}

func assertLegacyLifecycleState(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	assertLegacyFactsPreserved(t, pool)
	ctx := context.Background()
	var certificateStatus, renewalStatus, revocationStatus string
	var certificateOwner, certificateInstallation, certificateEpoch, certificateDER any
	var renewalOwner, renewalInstallation, renewalEpoch, renewalDER any
	var revocationOwner, revocationInstallation, revocationEpoch, revocationDER, revocationEffectiveAt any
	if err := pool.QueryRow(ctx, `SELECT rotation_status,owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256
		FROM node_certificates WHERE serial_number='abcdef'`).Scan(
		&certificateStatus, &certificateOwner, &certificateInstallation, &certificateEpoch, &certificateDER,
	); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT pop_status,owner_scope_id,installation_id,ca_epoch_id,current_leaf_der_sha256
		FROM node_certificate_renewal_requests`).Scan(
		&renewalStatus, &renewalOwner, &renewalInstallation, &renewalEpoch, &renewalDER,
	); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT binding_status,owner_scope_id,installation_id,ca_epoch_id,leaf_der_sha256,effective_at
		FROM node_certificate_revocations`).Scan(
		&revocationStatus, &revocationOwner, &revocationInstallation, &revocationEpoch, &revocationDER, &revocationEffectiveAt,
	); err != nil {
		t.Fatal(err)
	}
	if certificateStatus != "legacy_unbound" || renewalStatus != "legacy_unbound" || revocationStatus != "legacy_unbound" {
		t.Fatalf("legacy states = certificate %q, renewal %q, revocation %q", certificateStatus, renewalStatus, revocationStatus)
	}
	if certificateOwner != nil || certificateInstallation != nil || certificateEpoch != nil || certificateDER != nil {
		t.Fatalf("migration guessed certificate binding: owner=%v installation=%v epoch=%v der=%v",
			certificateOwner, certificateInstallation, certificateEpoch, certificateDER)
	}
	if renewalOwner != nil || renewalInstallation != nil || renewalEpoch != nil || renewalDER != nil {
		t.Fatalf("migration guessed renewal binding: owner=%v installation=%v epoch=%v der=%v",
			renewalOwner, renewalInstallation, renewalEpoch, renewalDER)
	}
	if revocationOwner != nil || revocationInstallation != nil || revocationEpoch != nil ||
		revocationDER != nil || revocationEffectiveAt != nil {
		t.Fatalf("migration guessed revocation binding: owner=%v installation=%v epoch=%v der=%v effective_at=%v",
			revocationOwner, revocationInstallation, revocationEpoch, revocationDER, revocationEffectiveAt)
	}
}

func assertLegacyFactsPreserved(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for table, want := range map[string]int{
		"node_certificates": 1, "node_certificate_renewal_requests": 1, "node_certificate_revocations": 1,
	} {
		var got int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s row count = %d, want %d", table, got, want)
		}
	}
	var serial, uriSAN, renewalSerial, revocationReason string
	if err := pool.QueryRow(ctx, `SELECT serial_number,uri_san FROM node_certificates`).Scan(&serial, &uriSAN); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT current_serial_number FROM node_certificate_renewal_requests`).Scan(&renewalSerial); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT reason FROM node_certificate_revocations`).Scan(&revocationReason); err != nil {
		t.Fatal(err)
	}
	if serial != "abcdef" || renewalSerial != serial ||
		uriSAN != "spiffe://cdn-platform/node/10000000-0000-0000-0000-000000000003" ||
		revocationReason != "legacy recorded revocation" {
		t.Fatalf("legacy facts changed: serial=%q renewal=%q uri=%q reason=%q", serial, renewalSerial, uriSAN, revocationReason)
	}
}

func assertLifecycleColumns(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	for table, column := range map[string]string{
		"node_certificates":                 "rotation_status",
		"node_certificate_renewal_requests": "pop_status",
		"node_certificate_revocations":      "binding_status",
	} {
		var actual bool
		if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
		)`, table, column).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("%s.%s exists = %t, want %t", table, column, actual, expected)
		}
	}
}

func assertNoNodeCertificateSecretColumns(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var columns []string
	rows, err := pool.Query(context.Background(), `SELECT table_name || '.' || column_name
		FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND table_name IN ('node_ca_key_epochs','node_ca_key_epoch_revocations','node_certificates',
		                     'node_certificate_renewal_requests','node_certificate_revocations')
		  AND (column_name LIKE '%private%' OR column_name LIKE '%secret%' OR column_name LIKE '%credential%')
		ORDER BY table_name,column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(columns) != 0 {
		t.Fatalf("node certificate lifecycle schema contains forbidden secret-bearing columns: %v", columns)
	}
}

func assertLifecycleHistoryCannotBeTruncated(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, target := range lifecycleHistoryGuards() {
		t.Run(target.table, func(t *testing.T) {
			tx, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			for _, other := range lifecycleHistoryGuards() {
				if other.table == target.table {
					continue
				}
				statement := "ALTER TABLE " + pgx.Identifier{other.table}.Sanitize() +
					" DISABLE TRIGGER " + pgx.Identifier{other.trigger}.Sanitize()
				if _, err := tx.Exec(context.Background(), statement); err != nil {
					t.Fatal(err)
				}
			}
			_, err = tx.Exec(context.Background(), "TRUNCATE "+pgx.Identifier{target.table}.Sanitize()+" CASCADE")
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "P0001" ||
				postgresError.Message != "node certificate lifecycle history cannot be truncated" {
				t.Errorf("TRUNCATE %s error = %v, want its lifecycle history trigger rejection", target.table, err)
			}
		})
	}
	assertLegacyFactsPreserved(t, pool)
}

func assertLifecycleTruncateGuards(t *testing.T, pool *pgxpool.Pool, expected bool) {
	t.Helper()
	for _, guard := range lifecycleHistoryGuards() {
		var actual bool
		if err := pool.QueryRow(context.Background(), `SELECT EXISTS(
			SELECT 1 FROM pg_trigger trigger
			JOIN pg_class relation ON relation.oid=trigger.tgrelid
			JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
			JOIN pg_proc function ON function.oid=trigger.tgfoid
			JOIN pg_namespace function_namespace ON function_namespace.oid=function.pronamespace
			WHERE namespace.nspname=current_schema() AND relation.relname=$1 AND trigger.tgname=$2
			  AND NOT trigger.tgisinternal AND (trigger.tgtype & 32) = 32 AND (trigger.tgtype & 2) = 2
			  AND (trigger.tgtype & 1) = 0 AND trigger.tgenabled <> 'D'
			  AND function_namespace.nspname=current_schema()
			  AND function.proname='prevent_node_certificate_lifecycle_truncate'
		)`, guard.table, guard.trigger).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Errorf("truncate guard %s on %s exists = %t, want %t", guard.trigger, guard.table, actual, expected)
		}
	}
}

type lifecycleHistoryGuard struct {
	table   string
	trigger string
}

func lifecycleHistoryGuards() []lifecycleHistoryGuard {
	return []lifecycleHistoryGuard{
		{table: "node_ca_key_epochs", trigger: "node_ca_key_epochs_truncate_protected"},
		{table: "node_ca_key_epoch_revocations", trigger: "node_ca_key_epoch_revocations_truncate_protected"},
		{table: "node_certificates", trigger: "node_certificates_truncate_protected"},
		{table: "node_certificate_renewal_requests", trigger: "node_certificate_renewals_truncate_protected"},
		{table: "node_certificate_revocations", trigger: "node_certificate_revocations_truncate_protected"},
		{table: "node_certificate_events", trigger: "node_certificate_events_truncate_protected"},
	}
}

func migrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func lifecycleDigest(value byte) []byte {
	return []byte(strings.Repeat(string([]byte{value}), 32))
}
