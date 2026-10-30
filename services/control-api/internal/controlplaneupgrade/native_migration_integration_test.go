//go:build integration && !windows

package controlplaneupgrade

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestNativeMigrationRealPostgresBackupMigrateRestore drives the production
// nativePGTools and the real `control-api migrate` against a temporary,
// installer-shaped database: the control role owns the database and public,
// the three NOLOGIN runtime roles exist, and the ledger sits three versions
// below the embedded head. It applies those three migrations from a backup,
// restores the backup, and proves the schema, ledger and data are back.
func TestNativeMigrationRealPostgresBackupMigrateRestore(t *testing.T) {
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	tools := nativePGTools{directory: os.Getenv("CDNCA_TEST_PG_TOOLS_DIR")}
	if tools.directory == "" {
		tools.directory = "/usr/bin"
	}
	if _, err := os.Stat(tools.tool("pg_dump")); err != nil {
		t.Skipf("pg_dump not found in %s", tools.directory)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	work := t.TempDir()
	binary := filepath.Join(work, "control-api")
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/control-api")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build control-api: %v %s", err, output)
	}

	suffix := fmt.Sprintf("%d_%d", os.Getpid(), time.Now().UnixNano()%1_000_000)
	role, database, password := "native_mig_"+suffix, "native_mig_"+suffix, "pw-"+suffix+"/@x"
	superuser, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer superuser.Close(context.WithoutCancel(ctx))
	sqlExec := func(conn *pgx.Conn, sql string) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	for _, runtime := range []string{"cdnca_control_app", "cdnca_plugin_webhook_runtime", "cdnca_control_runtime"} {
		sqlExec(superuser, fmt.Sprintf(`DO $$ BEGIN CREATE ROLE %s NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
			EXCEPTION WHEN duplicate_object THEN NULL; END $$`, runtime))
	}
	sqlExec(superuser, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", role, password))
	sqlExec(superuser, fmt.Sprintf("CREATE DATABASE %s OWNER %s", database, role))
	t.Cleanup(func() {
		cleanup := context.Background()
		_, _ = superuser.Exec(cleanup, fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", database))
		_, _ = superuser.Exec(cleanup, fmt.Sprintf("DROP ROLE IF EXISTS %s", role))
	})
	adminURL, err := url.Parse(admin)
	if err != nil {
		t.Fatal(err)
	}
	ownerAdmin := *adminURL
	ownerAdmin.Path = "/" + database
	installer, err := pgx.Connect(ctx, ownerAdmin.String())
	if err != nil {
		t.Fatal(err)
	}
	sqlExec(installer, fmt.Sprintf("ALTER SCHEMA public OWNER TO %s; REVOKE ALL ON SCHEMA public FROM PUBLIC", role))
	installer.Close(ctx)

	controlURL := *adminURL
	controlURL.User, controlURL.Path = url.UserPassword(role, password), "/"+database
	dsn := controlURL.String()
	migrate := func(direction string) {
		t.Helper()
		command := exec.CommandContext(ctx, binary, "migrate", direction)
		command.Env = []string{"PATH=/usr/bin:/bin", "DATABASE_URL=" + dsn}
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("migrate %s: %v %s", direction, err, output)
		}
	}
	migrate("up")
	headOutput, err := tools.Query(ctx, dsn, "SELECT max(version) FROM schema_migrations")
	if err != nil {
		t.Fatal(err)
	}
	var head int
	fmt.Sscan(headOutput, &head)
	for range 3 {
		migrate("down")
	}
	base := head - 3
	var applied []string
	for version := base + 1; version <= head; version++ {
		matches, _ := filepath.Glob(filepath.Join("..", "..", "migrations", fmt.Sprintf("%03d_*.up.sql", version)))
		if len(matches) != 1 {
			t.Fatalf("migration %d: %v", version, matches)
		}
		applied = append(applied, strings.TrimSuffix(filepath.Base(matches[0]), ".up.sql"))
	}
	if _, err := tools.Query(ctx, dsn, "CREATE TABLE native_probe(value text); INSERT INTO native_probe VALUES ('before')"); err != nil {
		t.Fatal(err)
	}
	normalize := regexp.MustCompile(`[()\s]+`)
	schema := func() string {
		t.Helper()
		parsed, _ := parseNativeDSN(dsn)
		command := exec.CommandContext(ctx, tools.tool("pg_dump"), "-w", "--schema-only")
		command.Env = tools.environment(parsed)
		output, err := command.Output()
		if err != nil {
			t.Fatalf("schema dump: %v", err)
		}
		var lines []string
		for _, line := range strings.Split(string(output), "\n") {
			if !strings.HasPrefix(line, `\restrict`) && !strings.HasPrefix(line, `\unrestrict`) {
				lines = append(lines, normalize.ReplaceAllString(line, " "))
			}
		}
		return strings.Join(lines, "\n")
	}
	data := func() string {
		t.Helper()
		output, err := tools.Query(ctx, dsn, `SELECT (SELECT string_agg(value, ',' ORDER BY value) FROM native_probe) || '|' ||
			(SELECT md5(string_agg(version || migration_id || checksum_sha256, ',' ORDER BY version)) FROM schema_migrations)`)
		if err != nil {
			t.Fatal(err)
		}
		return output
	}
	beforeSchema, beforeData := schema(), data()

	executor := &nativeExecutor{owner: uint32(os.Getuid()), commands: nativeUnitCommands("ActiveState=inactive\nMainPID=0\n"),
		config:   NativeStandaloneConfig{ControlUnit: "cdnca-control-api.service", StepTimeout: 5 * time.Minute, DatabaseTimeout: 15 * time.Minute},
		database: tools, controlDSN: func(context.Context) (string, error) { return dsn, nil }, freeSpace: nativeFreeSpace,
		backupDir: filepath.Join(work, nativeBackupDirectory)}
	plan := Plan{ID: "00000000-0000-4000-8000-0000000000aa"}
	record := &MigrationRecord{Applied: applied}
	for index, check := range []func() error{
		func() error { return tools.Compatible(ctx, dsn) },
		func() error { return executor.expectOwnership(ctx, dsn) },
		func() error { return executor.expectLedger(ctx, dsn, base) },
		executor.ensureBackupDirectory,
		func() error { return executor.checkBackupSpace(ctx, dsn) },
	} {
		if err := check(); err != nil {
			t.Fatalf("preflight check %d: %v", index, err)
		}
	}
	if err := executor.BackupDatabase(ctx, plan, record); err != nil {
		t.Fatal(err)
	}
	t.Logf("backup %s: %d bytes in %dms", record.BackupPath, record.BackupBytes, record.BackupMillis)
	started := time.Now()
	if err := tools.Migrate(ctx, dsn, binary); err != nil {
		t.Fatal(err)
	}
	if err := executor.expectLedger(ctx, dsn, head); err != nil {
		t.Fatal(err)
	}
	t.Logf("migrate up %v in %s", applied, time.Since(started))
	if _, err := tools.Query(ctx, dsn, "INSERT INTO native_probe VALUES ('written-by-candidate')"); err != nil {
		t.Fatal(err)
	}
	if schema() == beforeSchema {
		t.Fatal("migrations did not change the schema")
	}
	assertRestored := func(label string) {
		t.Helper()
		if err := executor.RestoreDatabase(ctx, plan, record); err != nil {
			t.Fatalf("%s restore: %v", label, err)
		}
		t.Logf("%s restore in %dms", label, record.RestoreMillis)
		if after := schema(); after != beforeSchema {
			left, right := strings.Split(beforeSchema, "\n"), strings.Split(after, "\n")
			for index := 0; index < len(left) && index < len(right); index++ {
				if left[index] != right[index] {
					t.Fatalf("%s schema differs at line %d:\n%s\n%s", label, index, left[index], right[index])
				}
			}
			t.Fatalf("%s schema length differs: %d != %d", label, len(left), len(right))
		}
		if got := data(); got != beforeData {
			t.Fatalf("%s data = %q, want %q", label, got, beforeData)
		}
	}
	assertRestored("after migration")
	// A crash between the wipe and the replay is recovered by restoring again.
	parsed, _ := parseNativeDSN(dsn)
	if _, err := tools.run(ctx, tools.environment(parsed), parsed.password, []byte(nativeWipeSQL), tools.tool("psql"),
		"-X", "-w", "-q", "-v", "ON_ERROR_STOP=1", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := executor.expectLedger(ctx, dsn, base); err == nil {
		t.Fatal("wipe left the ledger in place")
	}
	assertRestored("after interrupted restore")
	// The restored database is an ordinary, migratable control database.
	if err := tools.Migrate(ctx, dsn, binary); err != nil {
		t.Fatal(err)
	}
	if err := executor.expectLedger(ctx, dsn, head); err != nil {
		t.Fatal(err)
	}
}
