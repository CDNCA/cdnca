//go:build !windows

package controlplaneupgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// nativeDatabase is the PostgreSQL boundary of a native migration. Every
// call receives the control service's own DATABASE_URL; the password only
// travels in child-process environments, never in argv or receipts.
type nativeDatabase interface {
	Query(ctx context.Context, dsn, sql string) (string, error)
	Compatible(ctx context.Context, dsn string) error
	Dump(ctx context.Context, dsn, filename string) error
	Verify(ctx context.Context, filename string) error
	Restore(ctx context.Context, dsn, filename string) error
	Migrate(ctx context.Context, dsn, binary string) error
	// EnsureRoles creates, as the local PostgreSQL superuser, the NOLOGIN
	// roles a release needs but the control login cannot create (FX01:
	// cdnca_retention_cleanup), and grants them to the control login.
	EnsureRoles(ctx context.Context, dsn string) error
}

type nativeDSN struct {
	host, port, user, password, database, sslmode string
}

var (
	nativeDatabaseName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$-]{0,62}$`)
	nativeSSLModes     = map[string]bool{"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true}
)

// parseNativeDSN accepts the URL form install-control writes. Unknown query
// parameters fail closed instead of silently changing libpq behaviour.
func parseNativeDSN(raw string) (nativeDSN, error) {
	invalid := errors.New("control database URL is not a supported postgres URL")
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.Opaque != "" || parsed.Fragment != "" {
		return nativeDSN{}, invalid
	}
	password, _ := parsed.User.Password()
	dsn := nativeDSN{host: parsed.Hostname(), port: parsed.Port(), user: parsed.User.Username(), password: password,
		database: strings.TrimPrefix(parsed.Path, "/")}
	for key, values := range parsed.Query() {
		if len(values) != 1 {
			return nativeDSN{}, invalid
		}
		switch key {
		case "sslmode":
			dsn.sslmode = values[0]
		case "host":
			dsn.host = values[0]
		default:
			return nativeDSN{}, invalid
		}
	}
	if dsn.port == "" {
		dsn.port = "5432"
	}
	if port, err := strconv.Atoi(dsn.port); err != nil || port < 1 || port > 65535 || dsn.host == "" ||
		strings.ContainsAny(dsn.host, ",\x00") || !nativeDatabaseName.MatchString(dsn.database) ||
		!nativeDatabaseName.MatchString(dsn.user) || strings.ContainsRune(dsn.password, 0) ||
		(dsn.sslmode != "" && !nativeSSLModes[dsn.sslmode]) {
		return nativeDSN{}, invalid
	}
	return dsn, nil
}

type nativePGTools struct {
	directory string
}

func (tools nativePGTools) environment(dsn nativeDSN) []string {
	environment := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "PGCONNECT_TIMEOUT=10",
		"PGAPPNAME=cdnca-control-upgrade", "PGHOST=" + dsn.host, "PGPORT=" + dsn.port, "PGUSER=" + dsn.user,
		"PGDATABASE=" + dsn.database, "PGOPTIONS=-c client_min_messages=warning"}
	if dsn.password != "" {
		environment = append(environment, "PGPASSWORD="+dsn.password)
	}
	if dsn.sslmode != "" {
		environment = append(environment, "PGSSLMODE="+dsn.sslmode)
	}
	return environment
}

func (tools nativePGTools) run(ctx context.Context, environment []string, secret string, stdin []byte, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = environment
	command.WaitDelay = 10 * time.Second
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	stdout, stderr := &nativeTail{limit: 64 << 10}, &nativeTail{limit: 4 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "***")
		}
		return "", fmt.Errorf("%s failed: %w: %s", filepath.Base(name), err, message)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func (tools nativePGTools) tool(name string) string { return filepath.Join(tools.directory, name) }

func (tools nativePGTools) Query(ctx context.Context, raw, sql string) (string, error) {
	dsn, err := parseNativeDSN(raw)
	if err != nil {
		return "", err
	}
	return tools.run(ctx, tools.environment(dsn), dsn.password, nil, tools.tool("psql"), "-X", "-w", "-q", "-A", "-t",
		"-v", "ON_ERROR_STOP=1", "-c", sql)
}

// Compatible requires pg_dump, pg_restore and psql of at least the server's
// major version; an older pg_dump refuses to dump a newer server mid-upgrade.
func (tools nativePGTools) Compatible(ctx context.Context, raw string) error {
	output, err := tools.Query(ctx, raw, "SHOW server_version_num")
	server, convErr := strconv.Atoi(output)
	if err != nil || convErr != nil || server < 100000 {
		return errors.Join(errors.New("read PostgreSQL server version"), err)
	}
	for _, name := range []string{"pg_dump", "pg_restore", "psql"} {
		version, err := tools.run(ctx, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, "", nil, tools.tool(name), "--version")
		_, number, found := strings.Cut(version, "(PostgreSQL) ")
		major, convErr := strconv.Atoi(strings.SplitN(number, ".", 2)[0])
		if err != nil || !found || convErr != nil || major < server/10000 {
			return fmt.Errorf("%s is missing or older than PostgreSQL %d", name, server/10000)
		}
	}
	return nil
}

func (tools nativePGTools) Dump(ctx context.Context, raw, filename string) error {
	dsn, err := parseNativeDSN(raw)
	if err != nil {
		return err
	}
	_, err = tools.run(ctx, tools.environment(dsn), dsn.password, nil, tools.tool("pg_dump"), "-w", "--format=custom", "--file="+filename)
	return err
}

// Verify reads the whole archive (every data block, not only the TOC), so a
// truncated or corrupt dump is rejected before anything is migrated.
func (tools nativePGTools) Verify(ctx context.Context, filename string) error {
	_, err := tools.run(ctx, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}, "", nil, tools.tool("pg_restore"),
		"--file=/dev/null", filename)
	return err
}

// Restore returns the database to exactly the dump: it removes every object
// in schemas owned by the connecting role (the caller verified ownership),
// then replays the archive. Both halves are idempotent, so a crash at any
// point is recovered by running Restore again.
func (tools nativePGTools) Restore(ctx context.Context, raw, filename string) error {
	dsn, err := parseNativeDSN(raw)
	if err != nil {
		return err
	}
	environment := tools.environment(dsn)
	if _, err := tools.run(ctx, environment, dsn.password, []byte(nativeWipeSQL), tools.tool("psql"), "-X", "-w", "-q",
		"-v", "ON_ERROR_STOP=1", "-f", "-"); err != nil {
		return err
	}
	_, err = tools.run(ctx, environment, dsn.password, nil, tools.tool("pg_restore"), "-w", "--exit-on-error",
		"--dbname="+dsn.database, filename)
	return err
}

func (tools nativePGTools) Migrate(ctx context.Context, raw, binary string) error {
	dsn, err := parseNativeDSN(raw)
	if err != nil {
		return err
	}
	_, err = tools.run(ctx, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DATABASE_URL=" + raw},
		dsn.password, nil, binary, "migrate", "up")
	return err
}

var nativeRoleLogin = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// nativeEnsureRolesSQL is idempotent: it creates cdnca_retention_cleanup when
// missing and grants it (the role is NOINHERIT; the login uses SET LOCAL ROLE).
func nativeEnsureRolesSQL(login string) (string, error) {
	if !nativeRoleLogin.MatchString(login) {
		return "", errors.New("control database login is not a plain role name")
	}
	return fmt.Sprintf(`DO $ensure$
BEGIN
    IF to_regrole('cdnca_retention_cleanup') IS NULL THEN
        CREATE ROLE cdnca_retention_cleanup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
    END IF;
    IF NOT pg_has_role('%[1]s', 'cdnca_retention_cleanup', 'MEMBER') THEN
        GRANT cdnca_retention_cleanup TO "%[1]s";
    END IF;
END;
$ensure$;`, login), nil
}

// EnsureRoles runs the role script through the local superuser (peer
// authentication over the socket, as scripts/install-control.sh does); the
// control DSN only names the login to grant. A non-local database is left to
// its operator.
func (tools nativePGTools) EnsureRoles(ctx context.Context, raw string) error {
	dsn, err := parseNativeDSN(raw)
	if err != nil {
		return err
	}
	if dsn.host != "127.0.0.1" && dsn.host != "localhost" && dsn.host != "::1" && !strings.HasPrefix(dsn.host, "/") {
		return errors.New("control database is not local; create cdnca_retention_cleanup as its superuser")
	}
	sql, err := nativeEnsureRolesSQL(dsn.user)
	if err != nil {
		return err
	}
	runuser, err := exec.LookPath("runuser")
	if err != nil {
		return errors.New("runuser is required to create PostgreSQL roles")
	}
	_, err = tools.run(ctx, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "PGCONNECT_TIMEOUT=10"}, "",
		[]byte(sql), runuser, "-u", "postgres", "--", tools.tool("psql"), "-X", "-w", "-q", "-v", "ON_ERROR_STOP=1",
		"--dbname", "postgres", "-f", "-")
	return err
}

// nativeWipeSQL drops relations in bounded batches (each batch commits, so
// PostgreSQL's shared lock table is never exhausted), then the remaining
// functions, types and sequences with their owned schemas, and recreates the
// default public schema that pg_dump never emits a CREATE for.
const nativeWipeSQL = `SET client_min_messages = warning;
SELECT format('DROP %s IF EXISTS %s CASCADE', kind, string_agg(name, ', '))
FROM (
  SELECT CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'f' THEN 'FOREIGN TABLE' ELSE 'TABLE' END AS kind,
    format('%I.%I', n.nspname, c.relname) AS name,
    (row_number() OVER (PARTITION BY c.relkind IN ('r', 'p') ORDER BY c.oid) - 1) / 64 AS batch,
    c.relkind IN ('r', 'p') AS tabular
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND NOT c.relispartition
    AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
) relations
GROUP BY tabular, kind, batch
ORDER BY tabular, kind, batch
\gexec
SELECT format('DROP SCHEMA %I CASCADE', nspname) FROM pg_namespace
WHERE nspowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
  AND nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema'
ORDER BY nspname
\gexec
CREATE SCHEMA IF NOT EXISTS public;
COMMENT ON SCHEMA public IS 'standard public schema';
`

// nativeOwnershipSQL counts user objects the connecting role does not own;
// Restore can only reproduce a database it fully owns.
const nativeOwnershipSQL = `SELECT
 (SELECT count(*) FROM pg_namespace WHERE nspname NOT LIKE 'pg\_%' AND nspname <> 'information_schema' AND nspowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user))
 + (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND c.relowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user))
 + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND p.proowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user))
 + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema' AND t.typowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user))
 + (SELECT count(*) FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace WHERE n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema')`

type nativeTail struct {
	limit int
	data  []byte
}

func (tail *nativeTail) Write(value []byte) (int, error) {
	tail.data = append(tail.data, value...)
	if len(tail.data) > tail.limit {
		tail.data = append([]byte(nil), tail.data[len(tail.data)-tail.limit:]...)
	}
	return len(value), nil
}

func (tail *nativeTail) String() string { return string(tail.data) }
