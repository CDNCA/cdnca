package nativebackup

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestPostgresComponentRestoresOntoNewerMajor captures on an older major
// (OLD_TEST_DATABASE_URL + OLD_PG_TOOLS_DIR, e.g. PostgreSQL 16) and restores
// onto a newer one (TEST_DATABASE_URL + PG_TOOLS_DIR, e.g. 17): the restore
// preflight accepts the newer target and the logical dump loads.
// The reverse direction is refused by the preflight.
func TestPostgresComponentRestoresOntoNewerMajor(t *testing.T) {
	oldRaw, oldTools := os.Getenv("OLD_TEST_DATABASE_URL"), os.Getenv("OLD_PG_TOOLS_DIR")
	newRaw, newTools := os.Getenv("TEST_DATABASE_URL"), os.Getenv("PG_TOOLS_DIR")
	if oldRaw == "" || oldTools == "" || newRaw == "" || newTools == "" {
		t.Skip("OLD_TEST_DATABASE_URL, OLD_PG_TOOLS_DIR, TEST_DATABASE_URL and PG_TOOLS_DIR are required")
	}
	hostFor := func(raw, tools string) (*Host, func(database, statement string) string) {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		env := []string{"PGHOST=" + parsed.Hostname(), "PGPORT=" + parsed.Port(), "PGUSER=" + parsed.User.Username()}
		target := DatabaseTarget{Name: "g10u", Owner: "g10u", ToolsDir: tools, RolePrefix: "g10u", Env: env}
		sql := func(database, statement string) string {
			t.Helper()
			command := exec.Command(target.tool("psql"), "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "--dbname", database, "--command", statement)
			command.Env = append(os.Environ(), env...)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: %v %s", statement, err, output)
			}
			return strings.TrimSpace(string(output))
		}
		return &Host{Exec: OSExecutor{}, Database: target, Scratch: t.TempDir()}, sql
	}
	source, sourceSQL := hostFor(oldRaw, oldTools)
	target, targetSQL := hostFor(newRaw, newTools)
	for _, sql := range []func(string, string) string{sourceSQL, targetSQL} {
		sql := sql
		clean := func() {
			sql("postgres", "DROP DATABASE IF EXISTS g10u WITH (FORCE)")
			sql("postgres", "DROP ROLE IF EXISTS g10u_app")
			sql("postgres", "DROP ROLE IF EXISTS g10u")
		}
		clean()
		t.Cleanup(clean)
	}
	sourceSQL("postgres", "CREATE ROLE g10u LOGIN PASSWORD 'not-a-real-secret-5678'")
	sourceSQL("postgres", "CREATE ROLE g10u_app NOLOGIN NOINHERIT")
	sourceSQL("postgres", "GRANT g10u_app TO g10u")
	sourceSQL("postgres", "CREATE DATABASE g10u OWNER g10u TEMPLATE template0")
	sourceSQL("g10u", "ALTER SCHEMA public OWNER TO g10u; SET ROLE g10u;"+
		"CREATE TABLE schema_migrations (version bigint PRIMARY KEY);"+
		"INSERT INTO schema_migrations SELECT generate_series(1, 600);"+
		"CREATE TABLE sites (id serial PRIMARY KEY, name text NOT NULL);"+
		"INSERT INTO sites (name) SELECT 'site-' || g FROM generate_series(1, 300) g;"+
		"GRANT SELECT ON sites TO g10u_app;")
	component := postgresComponent{}
	var archive bytes.Buffer
	detail, err := component.Capture(context.Background(), source, &archive)
	if err != nil {
		t.Fatal(err)
	}
	record := ComponentRecord{Name: ComponentPostgreSQL, Detail: detail}
	targetVersion := targetSQL("postgres", "SHOW server_version_num")
	if targetVersion[:2] <= detail["server_version_num"][:2] {
		t.Skipf("target %s is not a newer major than the source %s", targetVersion, detail["server_version_num"])
	}
	if err := component.Preflight(context.Background(), target, record, Manifest{}); err != nil {
		t.Fatalf("a newer target was refused: %v", err)
	}
	if err := component.Restore(context.Background(), target, record, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got := targetSQL("g10u", "SELECT (SELECT count(*) FROM sites)||'|'||(SELECT max(version) FROM schema_migrations)"); got != "300|600" {
		t.Fatalf("restored %s", got)
	}
	if got := targetSQL("g10u", "SELECT has_table_privilege('g10u_app', 'sites', 'SELECT')"); got != "t" {
		t.Fatalf("grant %s", got)
	}
	// Downgrade: the newer server's capture onto the older one is refused.
	newer := ComponentRecord{Name: ComponentPostgreSQL, Detail: map[string]string{"server_version_num": targetVersion}}
	sourceSQL("postgres", "DROP DATABASE IF EXISTS g10u WITH (FORCE)")
	sourceSQL("postgres", "DROP ROLE IF EXISTS g10u_app")
	sourceSQL("postgres", "DROP ROLE IF EXISTS g10u")
	if err := component.Preflight(context.Background(), source, newer, Manifest{}); err == nil ||
		!strings.Contains(err.Error(), "restore_postgresql_version_mismatch") {
		t.Fatalf("a downgrade was not refused: %v", err)
	}
}
