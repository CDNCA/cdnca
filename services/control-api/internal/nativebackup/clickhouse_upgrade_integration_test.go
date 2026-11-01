package nativebackup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dockerClickHouse runs the component's clickhouse-client calls inside a
// ClickHouse container (the host has no client); other commands fail.
type dockerClickHouse struct {
	t         *testing.T
	container string
}

func (executor dockerClickHouse) Run(ctx context.Context, command Command) error {
	if command.Path != "/usr/bin/clickhouse-client" {
		executor.t.Fatalf("unexpected command %s", command.Path)
	}
	process := exec.CommandContext(ctx, "docker", append([]string{"exec", executor.container, "clickhouse-client"}, command.Args...)...)
	process.Stdout = command.Stdout
	var stderr bytes.Buffer
	process.Stderr = &stderr
	if err := process.Run(); err != nil {
		return &CommandError{Program: "clickhouse-client", Detail: stderr.String()}
	}
	return nil
}

// sameOwners keeps the files as extracted: the backups directory is a bind
// mount both containers read.
type sameOwners struct{}

func (sameOwners) Lookup(string, string, int, int) (int, int, error) { return os.Getuid(), os.Getgid(), nil }
func (sameOwners) Chown(string, int, int) error                       { return nil }

// TestClickHouseComponentRestoresOntoNewerServer captures with an older
// ClickHouse (OLD_CLICKHOUSE_CONTAINER, e.g. 24.8) and restores onto a newer
// one (NEW_CLICKHOUSE_CONTAINER, e.g. 25.3) with the real BACKUP/RESTORE:
// the preflight accepts the newer target, tables, a materialized view and a
// SQL-managed user with its grant come back. Both containers
// mount CLICKHOUSE_BACKUPS_ROOT/var/lib/clickhouse/backups at
// /var/lib/clickhouse/backups. The reverse direction is refused.
func TestClickHouseComponentRestoresOntoNewerServer(t *testing.T) {
	oldContainer, newContainer, root := os.Getenv("OLD_CLICKHOUSE_CONTAINER"), os.Getenv("NEW_CLICKHOUSE_CONTAINER"), os.Getenv("CLICKHOUSE_BACKUPS_ROOT")
	if oldContainer == "" || newContainer == "" || root == "" {
		t.Skip("OLD_CLICKHOUSE_CONTAINER, NEW_CLICKHOUSE_CONTAINER and CLICKHOUSE_BACKUPS_ROOT are required")
	}
	ctx := context.Background()
	hostFor := func(container string) (*Host, func(string) string) {
		host := &Host{Layout: Layout{Root: root}, Exec: dockerClickHouse{t: t, container: container}, Systemd: newFakeSystemd(t),
			Owners: sameOwners{}, Scratch: filepath.Join(t.TempDir(), "run.1")}
		query := func(sql string) string {
			t.Helper()
			output, err := clickhouseComponent{}.query(ctx, host, sql)
			if err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
			return output
		}
		return host, query
	}
	source, sourceSQL := hostFor(oldContainer)
	target, targetSQL := hostFor(newContainer)
	for _, sql := range []func(string) string{sourceSQL, targetSQL} {
		sql("DROP DATABASE IF EXISTS cdnca_analytics SYNC")
		sql("DROP USER IF EXISTS cdnca_analytics_reader")
	}
	sourceSQL("CREATE DATABASE cdnca_analytics")
	sourceSQL("CREATE TABLE cdnca_analytics.requests (at DateTime, site UInt32, bytes UInt64) ENGINE = MergeTree ORDER BY (site, at)")
	sourceSQL("CREATE MATERIALIZED VIEW cdnca_analytics.bytes_by_site ENGINE = SummingMergeTree ORDER BY site AS " +
		"SELECT site, sum(bytes) AS bytes FROM cdnca_analytics.requests GROUP BY site")
	sourceSQL("INSERT INTO cdnca_analytics.requests SELECT toDateTime('2026-10-01 00:00:00') + number, number % 50, number FROM numbers(100000)")
	sourceSQL("CREATE USER cdnca_analytics_reader IDENTIFIED WITH sha256_password BY 'not-a-real-secret-ch' DEFAULT DATABASE cdnca_analytics")
	sourceSQL("GRANT SELECT ON cdnca_analytics.* TO cdnca_analytics_reader")
	sourceVersion, targetVersion := sourceSQL("SELECT version()"), targetSQL("SELECT version()")
	if order, ok := compareDottedVersions(targetVersion, sourceVersion); !ok || order <= 0 {
		t.Skipf("target %s is not newer than the source %s", targetVersion, sourceVersion)
	}

	component := clickhouseComponent{}
	var archive bytes.Buffer
	detail, err := component.Capture(ctx, source, &archive)
	if err != nil {
		t.Fatal(err)
	}
	if detail["present"] != "1" || detail["server_version"] != sourceVersion || detail["users"] != "cdnca_analytics_reader" {
		t.Fatalf("detail = %v", detail)
	}
	record := ComponentRecord{Name: ComponentClickHouse, Detail: detail}
	if err := component.Preflight(ctx, target, record, Manifest{}); err != nil {
		t.Fatalf("a newer target was refused: %v", err)
	}
	if err := component.Restore(ctx, target, record, bytes.NewReader(archive.Bytes())); err != nil {
		t.Fatal(err)
	}
	if got := targetSQL("SELECT count(), sum(bytes) FROM cdnca_analytics.requests"); got != "100000\t4999950000" {
		t.Fatalf("restored requests %q", got)
	}
	if got := targetSQL("SELECT count(), sum(bytes) FROM cdnca_analytics.bytes_by_site"); !strings.HasSuffix(got, "\t4999950000") {
		t.Fatalf("restored materialized view %q", got)
	}
	// The view keeps working on the newer server.
	targetSQL("INSERT INTO cdnca_analytics.requests VALUES (now(), 7, 1000)")
	if got := targetSQL("SELECT sum(bytes) FROM cdnca_analytics.bytes_by_site"); got != "4999951000" {
		t.Fatalf("materialized view after insert %q", got)
	}
	if got := targetSQL("SELECT storage FROM system.users WHERE name = 'cdnca_analytics_reader'"); got != "local_directory" {
		t.Fatalf("restored user storage %q", got)
	}
	if got := targetSQL("SELECT count() FROM system.grants WHERE user_name = 'cdnca_analytics_reader' AND access_type = 'SELECT' AND database = 'cdnca_analytics'"); got != "1" {
		t.Fatalf("restored grant %q", got)
	}
	reader := exec.Command("docker", "exec", newContainer, "clickhouse-client", "--user", "cdnca_analytics_reader",
		"--password", "not-a-real-secret-ch", "--query", "SELECT count() FROM cdnca_analytics.requests")
	if output, err := reader.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "100001" {
		t.Fatalf("restored user cannot read: %v %s", err, output)
	}
	if entries, _ := os.ReadDir(Layout{Root: root}.Path(clickhouseBackupsDir)); len(entries) != 0 {
		t.Fatalf("backup files left behind: %v", entries)
	}

	// Downgrade: the newer server's capture onto the older one is refused.
	sourceSQL("DROP DATABASE IF EXISTS cdnca_analytics SYNC")
	sourceSQL("DROP USER IF EXISTS cdnca_analytics_reader")
	newer := ComponentRecord{Name: ComponentClickHouse, Detail: map[string]string{"present": "1", "server_version": targetVersion}}
	if err := component.Preflight(ctx, source, newer, Manifest{}); err == nil || !strings.Contains(err.Error(), "restore_clickhouse_version_mismatch") {
		t.Fatalf("a downgrade was not refused: %v", err)
	}
}
