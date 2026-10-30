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

// TestPostgresComponentRoundTrip dumps a database and its roles with the real
// PostgreSQL 17 client programs, drops everything, restores it and compares.
// Needs TEST_DATABASE_URL pointing at a throwaway cluster whose user is a
// superuser and PG_TOOLS_DIR.
func TestPostgresComponentRoundTrip(t *testing.T) {
	raw := os.Getenv("TEST_DATABASE_URL")
	tools := os.Getenv("PG_TOOLS_DIR")
	if raw == "" || tools == "" {
		t.Skip("TEST_DATABASE_URL and PG_TOOLS_DIR are required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	env := []string{"PGHOST=" + parsed.Hostname(), "PGPORT=" + parsed.Port(), "PGUSER=" + parsed.User.Username()}
	target := DatabaseTarget{Name: "g10x", Owner: "g10x", ToolsDir: tools, RolePrefix: "g10x", Env: env}
	host := &Host{Exec: OSExecutor{}, Database: target, Scratch: t.TempDir()}
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
	cleanup := func() {
		sql("postgres", "DROP DATABASE IF EXISTS g10x WITH (FORCE)")
		sql("postgres", "DROP ROLE IF EXISTS g10x_app")
		sql("postgres", "DROP ROLE IF EXISTS g10x")
	}
	cleanup()
	t.Cleanup(cleanup)
	sql("postgres", "CREATE ROLE g10x LOGIN PASSWORD 'not-a-real-secret-1234'")
	sql("postgres", "CREATE ROLE g10x_app NOLOGIN NOINHERIT")
	sql("postgres", "GRANT g10x_app TO g10x")
	sql("postgres", "CREATE DATABASE g10x OWNER g10x TEMPLATE template0")
	sql("g10x", "ALTER SCHEMA public OWNER TO g10x; SET ROLE g10x;"+
		"CREATE TABLE schema_migrations (version bigint PRIMARY KEY);"+
		"INSERT INTO schema_migrations SELECT generate_series(1, 299);"+
		"CREATE TABLE sites (id serial PRIMARY KEY, name text NOT NULL);"+
		"INSERT INTO sites (name) SELECT 'site-' || g FROM generate_series(1, 500) g;"+
		"GRANT SELECT ON sites TO g10x_app;"+
		"CREATE FUNCTION site_count() RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path = public AS 'SELECT count(*) FROM sites';")
	passwordBefore := sql("postgres", "SELECT rolpassword FROM pg_authid WHERE rolname = 'g10x'")

	component := postgresComponent{}
	var archive bytes.Buffer
	detail, err := component.Capture(context.Background(), host, &archive)
	if err != nil {
		t.Fatal(err)
	}
	if detail["schema_version"] != "299" || detail["roles"] != "g10x,g10x_app" || !strings.HasPrefix(detail["server_version_num"], "17") {
		t.Fatalf("detail = %v", detail)
	}
	record := ComponentRecord{Name: ComponentPostgreSQL, Detail: detail}
	if err := component.Preflight(context.Background(), host, record, Manifest{}); err == nil {
		t.Fatal("preflight must refuse a target that already has the database")
	}
	cleanup()
	if err := component.Preflight(context.Background(), host, record, Manifest{}); err != nil {
		t.Fatal(err)
	}
	if err := component.Restore(context.Background(), host, record, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got := sql("g10x", "SELECT count(*), max(name) FROM sites"); got != "500|site-99" {
		t.Fatalf("rows = %s", got)
	}
	if got := sql("g10x", "SELECT site_count()"); got != "500" {
		t.Fatalf("function = %s", got)
	}
	if got := sql("postgres", "SELECT rolpassword FROM pg_authid WHERE rolname = 'g10x'"); got != passwordBefore {
		t.Fatal("the login role must keep its password verifier")
	}
	if got := sql("g10x", "SELECT has_table_privilege('g10x_app', 'sites', 'SELECT'), pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'g10x'"); got != "t|g10x" {
		t.Fatalf("grants/owner = %s", got)
	}
	if got := sql("postgres", "SELECT pg_has_role('g10x', 'g10x_app', 'MEMBER')"); got != "t" {
		t.Fatalf("membership = %s", got)
	}
	if err := component.Compensate(context.Background(), host, record); err != nil {
		t.Fatal(err)
	}
	if got := sql("postgres", "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'g10x%'"); got != "0" {
		t.Fatalf("compensate must remove the roles: %s", got)
	}
}

func TestFilterRolesKeepsOnlyInstallationRoles(t *testing.T) {
	dump := strings.Join([]string{
		"CREATE ROLE cdnca;",
		"ALTER ROLE cdnca WITH NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB LOGIN NOREPLICATION NOBYPASSRLS PASSWORD 'SCRAM-SHA-256$x';",
		"CREATE ROLE postgres;",
		"ALTER ROLE postgres WITH SUPERUSER;",
		"CREATE ROLE cdnca_control_app;",
		"GRANT cdnca_control_app TO cdnca WITH INHERIT TRUE GRANTED BY postgres;",
		"GRANT pg_read_all_data TO cdnca GRANTED BY postgres;",
	}, "\n")
	got, err := filterRoles(dump, []string{"cdnca", "cdnca_control_app"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "postgres") || strings.Contains(got, "pg_read_all_data") {
		t.Fatalf("foreign roles leaked: %s", got)
	}
	for _, want := range []string{"CREATE ROLE cdnca;", "CREATE ROLE cdnca_control_app;", "GRANT cdnca_control_app TO cdnca WITH INHERIT TRUE;"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %s", want, got)
		}
	}
}
