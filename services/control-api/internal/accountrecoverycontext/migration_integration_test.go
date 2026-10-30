package accountrecoverycontext

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const contextMigrationVersion = int64(61)

type contextIdentity struct {
	tenantID uuid.UUID
	scopeID  uuid.UUID
	userID   uuid.UUID
}

func TestAccountRecoveryContextPostgreSQL17(t *testing.T) {
	pool := contextIntegrationPool(t, contextMigrationVersion)
	assertPostgreSQL17(t, pool)
	first := seedContextIdentity(t, pool, "first")
	second := seedContextIdentity(t, pool, "second")
	sharedUserID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,'shared-recovery-user','Shared recovery user','test-hash')`, sharedUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id)
		VALUES($1,$3),($2,$3)`, first.scopeID, second.scopeID, sharedUserID); err != nil {
		t.Fatal(err)
	}
	writeHostBinding(t, pool, "first.recovery.example", first, "first-create")
	writeHostBinding(t, pool, "second.recovery.example", second, "second-create")

	resolver, err := NewResolver(pool, Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host     string
		tenantID uuid.UUID
		scopeID  uuid.UUID
	}{
		{host: "first.recovery.example", tenantID: first.tenantID, scopeID: first.scopeID},
		{host: "second.recovery.example", tenantID: second.tenantID, scopeID: second.scopeID},
	} {
		request := contextRequest(test.host)
		request.Header.Set("X-Tenant", second.tenantID.String())
		request.Header.Set("X-Scope", second.scopeID.String())
		request.Header.Set("Cookie", "tenant="+second.tenantID.String())
		request.Header.Set("Authorization", "Bearer "+second.tenantID.String())
		request.Body = io.NopCloser(strings.NewReader(`{"username":"shared-recovery-user"}`))
		trusted, err := resolver.Resolve(request)
		if err != nil || trusted.TenantID != test.tenantID || trusted.ScopeID != test.scopeID {
			t.Fatalf("resolve %s = %+v, %v", test.host, trusted, err)
		}
		var matchedUserID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT account.id
			FROM users account
			JOIN memberships membership ON membership.user_id=account.id
			WHERE account.username='shared-recovery-user' AND membership.scope_id=$1`,
			trusted.ScopeID).Scan(&matchedUserID); err != nil || matchedUserID != sharedUserID {
			t.Fatalf("host %s selected wrong shared username membership: %s, %v",
				test.host, matchedUserID, err)
		}
	}

	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, first.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(contextRequest("first.recovery.example")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inactive tenant error=%v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='active' WHERE id=$1`, first.tenantID); err != nil {
		t.Fatal(err)
	}
	reviseHostBinding(t, pool, "first.recovery.example", first, 2, "inactive", "first-retire")
	if _, err := resolver.Resolve(contextRequest("first.recovery.example")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inactive binding error=%v", err)
	}
}

func TestAccountRecoveryPublicHostFactsAreProtected(t *testing.T) {
	pool := contextIntegrationPool(t, contextMigrationVersion)
	identity := seedContextIdentity(t, pool, "facts")

	invalidHosts := []string{
		"UPPER.example", "trailing.example.", "port.example:443", "*.example", "192.0.2.1",
		"localhost", "a.local", "a.internal", "control\n.example", "b\u00fccher.example",
		strings.Repeat("a", 64) + ".example",
	}
	for index, hostname := range invalidHosts {
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			return insertHostRevision(t.Context(), tx, hostname, identity, 1, "active", "invalid-"+strconv.Itoa(index))
		})
		if err == nil {
			t.Fatalf("invalid hostname %q was accepted", hostname)
		}
	}

	writeHostBinding(t, pool, "facts.recovery.example", identity, "facts-create")
	var actorUserID, actorScopeID uuid.UUID
	var requestID, traceID string
	if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,actor_scope_id,request_id,trace_id
		FROM account_recovery_public_host_revisions
		WHERE hostname='facts.recovery.example' AND revision=1`).Scan(
		&actorUserID, &actorScopeID, &requestID, &traceID,
	); err != nil || actorUserID != identity.userID || actorScopeID != identity.scopeID ||
		requestID != "facts-create" || traceID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("revision audit actor=%s/%s request/trace=%q/%q err=%v",
			actorUserID, actorScopeID, requestID, traceID, err)
	}

	platformScopeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	invalidScopeIdentity := identity
	invalidScopeIdentity.scopeID = platformScopeID
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return insertHostRevision(t.Context(), tx, "platform.recovery.example", invalidScopeIdentity,
			1, "active", "platform-target")
	}); err == nil {
		t.Fatal("platform scope was accepted as an account recovery tenant target")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE account_recovery_public_hosts
		SET tenant_id=$2 WHERE hostname=$1`, "facts.recovery.example", uuid.New()); err == nil {
		t.Fatal("unaudited projection update succeeded")
	}
	if _, err := pool.Exec(t.Context(), `UPDATE account_recovery_public_host_revisions
		SET request_id='tampered' WHERE hostname=$1`, "facts.recovery.example"); err == nil {
		t.Fatal("append-only revision update succeeded")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM account_recovery_public_host_revisions
		WHERE hostname=$1`, "facts.recovery.example"); err == nil {
		t.Fatal("append-only revision delete succeeded")
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM account_recovery_public_hosts
		WHERE hostname=$1`, "facts.recovery.example"); err == nil {
		t.Fatal("projection delete succeeded")
	}

	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION account_recovery_context_test_audit_failure()
		RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$;
		CREATE TRIGGER account_recovery_context_test_audit_failure
		BEFORE INSERT ON account_recovery_public_host_revisions
		FOR EACH ROW EXECUTE FUNCTION account_recovery_context_test_audit_failure()`); err != nil {
		t.Fatal(err)
	}
	failed := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if err := insertHostRevision(t.Context(), tx, "rollback.recovery.example", identity, 1, "active", "rollback"); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO account_recovery_public_hosts(
			hostname,tenant_id,tenant_scope_id,state,current_revision,created_at,updated_at
		) VALUES($1,$2,$3,'active',1,now(),now())`,
			"rollback.recovery.example", identity.tenantID, identity.scopeID)
		return err
	})
	if failed == nil {
		t.Fatal("injected audit failure did not abort binding transaction")
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER account_recovery_context_test_audit_failure
		ON account_recovery_public_host_revisions;
		DROP FUNCTION account_recovery_context_test_audit_failure()`); err != nil {
		t.Fatal(err)
	}
	var revisions, projections int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM account_recovery_public_host_revisions WHERE hostname='rollback.recovery.example'),
		(SELECT count(*) FROM account_recovery_public_hosts WHERE hostname='rollback.recovery.example')`).Scan(
		&revisions, &projections,
	); err != nil || revisions != 0 || projections != 0 {
		t.Fatalf("audit rollback revisions/projections=%d/%d err=%v", revisions, projections, err)
	}

	downScript := contextMigrationScript(t, "061_account_recovery_public_hosts.down.sql")
	if _, err := pool.Exec(t.Context(), downScript); err == nil {
		t.Fatal("061 down succeeded with binding/revision facts")
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM account_recovery_public_hosts`).Scan(&projections); err != nil || projections != 1 {
		t.Fatalf("protected down changed facts count=%d err=%v", projections, err)
	}
}

func TestAccountRecoveryPublicHostConcurrentBindingHasOneWinner(t *testing.T) {
	pool := contextIntegrationPool(t, contextMigrationVersion)
	first := seedContextIdentity(t, pool, "race-first")
	second := seedContextIdentity(t, pool, "race-second")
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, identity := range []contextIdentity{first, second} {
		go func(index int, identity contextIdentity) {
			<-start
			results <- writeHostBindingError(t.Context(), pool, "race.recovery.example", identity,
				"race-"+strconv.Itoa(index))
		}(index, identity)
	}
	close(start)
	var successes, failures int
	for index := 0; index < 2; index++ {
		if err := <-results; err == nil {
			successes++
		} else {
			failures++
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("concurrent successes/failures=%d/%d", successes, failures)
	}
	var projections, revisions int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM account_recovery_public_hosts WHERE hostname='race.recovery.example'),
		(SELECT count(*) FROM account_recovery_public_host_revisions WHERE hostname='race.recovery.example')`).Scan(
		&projections, &revisions,
	); err != nil || projections != 1 || revisions != 1 {
		t.Fatalf("race projections/revisions=%d/%d err=%v", projections, revisions, err)
	}
}

func TestAccountRecoveryPublicHostMigrationEmptyDownUp(t *testing.T) {
	pool := contextIntegrationPool(t, 60)
	upScript := contextMigrationScript(t, "061_account_recovery_public_hosts.up.sql")
	downScript := contextMigrationScript(t, "061_account_recovery_public_hosts.down.sql")
	if !strings.Contains(downScript, "ACCESS EXCLUSIVE") {
		t.Fatal("061 down does not take ACCESS EXCLUSIVE locks")
	}
	if _, err := pool.Exec(t.Context(), upScript); err != nil {
		t.Fatalf("first 061 up: %v", err)
	}
	if _, err := pool.Exec(t.Context(), downScript); err != nil {
		t.Fatalf("empty 061 down: %v", err)
	}
	var relation *string
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('account_recovery_public_hosts')::text`).Scan(&relation); err != nil || relation != nil {
		t.Fatalf("projection remains after empty down: %v, %v", relation, err)
	}
	if _, err := pool.Exec(t.Context(), upScript); err != nil {
		t.Fatalf("second 061 up: %v", err)
	}
}

func writeHostBinding(t *testing.T, pool *pgxpool.Pool, hostname string, identity contextIdentity, requestID string) {
	t.Helper()
	if err := writeHostBindingError(t.Context(), pool, hostname, identity, requestID); err != nil {
		t.Fatal(err)
	}
}

func writeHostBindingError(
	ctx context.Context,
	pool *pgxpool.Pool,
	hostname string,
	identity contextIdentity,
	requestID string,
) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if err := insertHostRevision(ctx, tx, hostname, identity, 1, "active", requestID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO account_recovery_public_hosts(
			hostname,tenant_id,tenant_scope_id,state,current_revision,created_at,updated_at
		) VALUES($1,$2,$3,'active',1,now(),now())`, hostname, identity.tenantID, identity.scopeID)
		return err
	})
}

func reviseHostBinding(
	t *testing.T,
	pool *pgxpool.Pool,
	hostname string,
	identity contextIdentity,
	revision int64,
	state string,
	requestID string,
) {
	t.Helper()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if err := insertHostRevision(t.Context(), tx, hostname, identity, revision, state, requestID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE account_recovery_public_hosts
			SET tenant_id=$2,tenant_scope_id=$3,state=$4,current_revision=$5,updated_at=now()
			WHERE hostname=$1`, hostname, identity.tenantID, identity.scopeID, state, revision)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func insertHostRevision(
	ctx context.Context,
	tx pgx.Tx,
	hostname string,
	identity contextIdentity,
	revision int64,
	state string,
	requestID string,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO account_recovery_public_host_revisions(
		hostname,revision,tenant_id,tenant_scope_id,state,actor_user_id,actor_scope_id,
		request_id,trace_id,recorded_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'0123456789abcdef0123456789abcdef',now())`,
		hostname, revision, identity.tenantID, identity.scopeID, state,
		identity.userID, identity.scopeID, requestID)
	return err
}

func seedContextIdentity(t *testing.T, pool *pgxpool.Pool, suffix string) contextIdentity {
	t.Helper()
	identity := contextIdentity{tenantID: uuid.New(), scopeID: uuid.New(), userID: uuid.New()}
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, []any{identity.tenantID, "Context " + suffix}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{identity.scopeID, identity.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,'test-hash')`,
			[]any{identity.userID, "context-" + suffix, "Context " + suffix}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{identity.scopeID, identity.userID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return identity
}

func contextRequest(hostname string) *http.Request {
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://placeholder.invalid/v1/account-recovery/requests", nil)
	request.Host = hostname
	request.RemoteAddr = "198.51.100.20:44000"
	return request
}

type contextMigration struct {
	version int64
	name    string
}

func contextIntegrationPool(t *testing.T, through int64) *pgxpool.Pool {
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
	schema := "account_recovery_context_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^account_recovery_context_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupContext, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop account recovery context schema: %v", err)
		}
		admin.Close()
	})
	applyContextMigrations(t, pool, through)
	return pool
}

func applyContextMigrations(t *testing.T, pool *pgxpool.Pool, through int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	items := make([]contextMigration, 0, through)
	for _, entry := range entries {
		name := entry.Name()
		separator := strings.IndexByte(name, '_')
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") || separator < 1 {
			continue
		}
		version, err := strconv.ParseInt(name[:separator], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if version <= through {
			items = append(items, contextMigration{version: version, name: name})
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	if int64(len(items)) != through {
		t.Fatalf("migration count through %03d=%d, want %d", through, len(items), through)
	}
	for index, item := range items {
		if item.version != int64(index+1) {
			t.Fatalf("migration sequence index=%d version=%03d", index+1, item.version)
		}
		script := contextMigrationScript(t, item.name)
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := tx.Exec(t.Context(), script)
			return err
		}); err != nil {
			t.Fatalf("apply migration %s: %v", item.name, err)
		}
	}
}

func contextMigrationScript(t *testing.T, name string) string {
	t.Helper()
	script, err := fs.ReadFile(migrations.FS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(script)
}

func assertPostgreSQL17(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var version string
	if err := pool.QueryRow(t.Context(), `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "17.") {
		t.Fatalf("PostgreSQL version=%q, want 17.x", version)
	}
}
