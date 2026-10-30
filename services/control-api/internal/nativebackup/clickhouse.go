package nativebackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// clickhouseComponent uses ClickHouse's native BACKUP/RESTORE, which keeps
// parts, materialized views (with their DEFINER) and the SQL-managed users and
// grants consistent. The package default `backups.allowed_path` is
// "backups", i.e. /var/lib/clickhouse/backups, so no server configuration
// change is needed. Credentials come from the private admin client file
// written by configure-clickhouse.py, never from argv.
type clickhouseComponent struct{}

const (
	clickhouseDatabase   = "cdnca_analytics"
	clickhouseAdminFile  = AnalyticsConfig + "/admin.xml"
	clickhouseBackupsDir = ClickHouseData + "/backups"
)

var clickhouseUserPattern = regexp.MustCompile(`^cdnca_analytics_[a-z0-9_]{1,32}$`)

func (clickhouseComponent) Name() ComponentName { return ComponentClickHouse }

func (clickhouseComponent) query(ctx context.Context, host *Host, sql string) (string, error) {
	arguments := []string{"--host", "127.0.0.1", "--log_queries=0", "--max_execution_time=3600", "--query", sql}
	// A BaoTa host may run ClickHouse on a moved native port (host port profile).
	if ports, err := ReadHostPorts(host.Layout); err != nil {
		return "", err
	} else if ports.ClickHouseTCP != DefaultHostPorts().ClickHouseTCP {
		arguments = append([]string{"--port", strconv.Itoa(ports.ClickHouseTCP)}, arguments...)
	}
	if _, err := os.Lstat(host.Layout.Path(clickhouseAdminFile)); err == nil {
		arguments = append([]string{"--config-file", host.Layout.Path(clickhouseAdminFile)}, arguments...)
	}
	return run(ctx, host.Exec, Command{Path: "/usr/bin/clickhouse-client", Args: arguments})
}

// waitReady retries until the server answers (after a restart or reload).
func (component clickhouseComponent) waitReady(ctx context.Context, host *Host) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 60; attempt++ {
		version, err := component.query(ctx, host, "SELECT version()")
		if err == nil {
			return version, nil
		}
		lastErr = err
		if !sleepContext(ctx, time.Second) {
			break
		}
	}
	return "", fmt.Errorf("restore_clickhouse_unavailable: %w", lastErr)
}

func (component clickhouseComponent) users(ctx context.Context, host *Host) ([]string, error) {
	output, err := component.query(ctx, host, "SELECT name FROM system.users WHERE storage = 'local_directory' AND name LIKE 'cdnca\\_analytics\\_%' ORDER BY name")
	if err != nil {
		return nil, err
	}
	var users []string
	for _, line := range strings.Split(output, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if !clickhouseUserPattern.MatchString(line) {
			return nil, errors.New("unexpected ClickHouse user name")
		}
		users = append(users, line)
	}
	return users, nil
}

func (component clickhouseComponent) Capture(ctx context.Context, host *Host, output io.Writer) (map[string]string, error) {
	version, err := component.query(ctx, host, "SELECT version()")
	if err != nil {
		return nil, err
	}
	exists, err := component.query(ctx, host, "EXISTS DATABASE "+clickhouseDatabase)
	if err != nil {
		return nil, err
	}
	detail := map[string]string{"server_version": version, "database": clickhouseDatabase, "present": exists}
	if exists != "1" {
		// Analytics was never installed on this host: record an empty archive.
		return detail, writeTarFiles(output, nil, nil)
	}
	users, err := component.users(ctx, host)
	if err != nil {
		return nil, err
	}
	detail["users"] = strings.Join(users, ",")
	name := "cdnca-" + strings.ReplaceAll(filepath.Base(host.Scratch), ".", "-")
	if _, err := component.query(ctx, host, "BACKUP DATABASE "+clickhouseDatabase+
		", TABLE system.users, TABLE system.roles TO File('"+name+"') SETTINGS id = '"+name+"'"); err != nil {
		return nil, err
	}
	directory := host.Layout.Path(filepath.Join(clickhouseBackupsDir, name))
	defer os.RemoveAll(directory)
	stats, err := ArchiveTree(Layout{Root: host.Layout.Path(clickhouseBackupsDir)}, []treePath{{Path: "/" + name, Required: true}}, output)
	if err != nil {
		return nil, err
	}
	detail["backup_name"] = name
	detail["files"] = fmt.Sprint(stats.Files)
	return detail, nil
}

func (component clickhouseComponent) Preflight(ctx context.Context, host *Host, record ComponentRecord, _ Manifest) error {
	if record.Detail["present"] != "1" {
		return nil
	}
	version, err := component.query(ctx, host, "SELECT version()")
	if err != nil {
		return fmt.Errorf("restore_clickhouse_unavailable: %w", err)
	}
	if version != record.Detail["server_version"] {
		return fmt.Errorf("restore_clickhouse_version_mismatch:%s!=%s", version, record.Detail["server_version"])
	}
	exists, err := component.query(ctx, host, "EXISTS DATABASE "+clickhouseDatabase)
	if err != nil {
		return err
	}
	users, err := component.users(ctx, host)
	if err != nil {
		return err
	}
	if exists != "0" || len(users) != 0 {
		return errors.New("restore_target_not_empty:clickhouse")
	}
	return nil
}

func (component clickhouseComponent) Restore(ctx context.Context, host *Host, record ComponentRecord, input io.Reader) error {
	if record.Detail["present"] != "1" {
		_, err := io.Copy(io.Discard, input)
		return err
	}
	// The configuration step restored the private default-user drop-in;
	// restart so the server and the admin client file agree.
	if err := host.Systemd.Stop(ctx, "clickhouse-server.service"); err != nil {
		return err
	}
	if err := host.Systemd.Start(ctx, "clickhouse-server.service"); err != nil {
		return err
	}
	if _, err := component.waitReady(ctx, host); err != nil {
		return err
	}
	name := record.Detail["backup_name"]
	if !regexp.MustCompile(`^cdnca-[A-Za-z0-9-]{1,96}$`).MatchString(name) {
		return ErrArtifactCorrupt
	}
	backups := host.Layout.Path(clickhouseBackupsDir)
	if err := os.MkdirAll(backups, 0o750); err != nil {
		return err
	}
	uid, gid, err := host.Owners.Lookup("clickhouse", "clickhouse", -1, -1)
	if err != nil {
		return err
	}
	if err := host.Owners.Chown(backups, uid, gid); err != nil {
		return err
	}
	defer os.RemoveAll(filepath.Join(backups, name))
	if _, err := ExtractTree(Layout{Root: backups}, []treePath{{Path: "/" + name}}, host.Owners, input); err != nil {
		return err
	}
	_, err = component.query(ctx, host, "RESTORE DATABASE "+clickhouseDatabase+
		", TABLE system.users, TABLE system.roles FROM File('"+name+"')")
	return err
}

func (component clickhouseComponent) Compensate(ctx context.Context, host *Host, record ComponentRecord) error {
	if record.Detail["present"] != "1" {
		return nil
	}
	var joined error
	if _, err := component.query(ctx, host, "DROP DATABASE IF EXISTS "+clickhouseDatabase+" SYNC"); err != nil {
		joined = err
	}
	for _, user := range strings.Split(record.Detail["users"], ",") {
		if clickhouseUserPattern.MatchString(user) {
			if _, err := component.query(ctx, host, "DROP USER IF EXISTS "+user); err != nil {
				joined = errors.Join(joined, err)
			}
		}
	}
	return joined
}

func sleepContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
