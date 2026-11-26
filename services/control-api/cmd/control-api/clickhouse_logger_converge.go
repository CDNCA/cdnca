package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nativebackup"
)

// The ClickHouse vendor config.xml logs at trace with 10 x 1000M files; a 20G system disk filled up
// and the broken log channel then sent every message to syslog. Fresh installs write a bounded logger into the
// managed cdnca-loopback.xml (scripts/native-runtime/configure-clickhouse.py LOOPBACK_DEFAULT, the same bytes as
// install-ubuntu-dependencies.sh). Upgrades never rewrite /etc, so the backup agent (root, unsandboxed, started by
// every upgrade and hot release and by its timer) brings a host still on the earlier managed form to those bytes
// and restarts a running clickhouse-server once. Any other content is left alone.
const (
	clickHouseLoopbackPath      = "/etc/clickhouse-server/config.d/cdnca-loopback.xml"
	clickHouseLoopbackListeners = "<clickhouse>\n    <listen_host replace=\"replace\">127.0.0.1</listen_host>\n    <interserver_listen_host replace=\"replace\">127.0.0.1</interserver_listen_host>\n"
	clickHouseLoggerBlock       = "    <logger>\n        <level>information</level>\n        <size>100M</size>\n        <count>5</count>\n    </logger>\n"
	// clickHouseLoggerFailed stops further attempts after a restart with the new file failed (the earlier file was
	// put back); remove it to try again.
	clickHouseLoggerFailed = nativebackup.AgentRoot + "/clickhouse-logger.failed"
)

// The moved ports a BaoTa host profile appends (configure-clickhouse.py _LOOPBACK_TAGS) and the closing tag.
var clickHouseLoopbackTail = regexp.MustCompile(`^(?:    <(?:http_port|tcp_port|mysql_port|postgresql_port|interserver_http_port)>[1-9][0-9]{3,4}</(?:http_port|tcp_port|mysql_port|postgresql_port|interserver_http_port)>\n)*</clickhouse>\n$`)

// boundedClickHouseLoopback returns the bounded content for a file in the earlier managed form, nil otherwise.
func boundedClickHouseLoopback(have []byte) []byte {
	rest, ok := bytes.CutPrefix(have, []byte(clickHouseLoopbackListeners))
	if !ok || !clickHouseLoopbackTail.Match(rest) {
		return nil
	}
	return append([]byte(clickHouseLoopbackListeners+clickHouseLoggerBlock), rest...)
}

type clickHouseLoggerConverge struct {
	path, failed string
	lock         func() (func(), error)
	restart      func(context.Context) error
}

func convergeClickHouseLogger(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	converge := clickHouseLoggerConverge{path: clickHouseLoopbackPath, failed: clickHouseLoggerFailed,
		lock: func() (func(), error) { return nativebackup.LockRelease(nativebackup.Layout{}) },
		restart: func(ctx context.Context) error {
			// try-restart: a stopped server (migration hold) picks the file up when it is started again.
			return exec.CommandContext(ctx, "/usr/bin/systemctl", "try-restart", "clickhouse-server.service").Run()
		}}
	if changed, err := converge.run(ctx); err != nil {
		slog.Error("ClickHouse logger converge failed", "path", clickHouseLoopbackPath, "error", err)
	} else if changed {
		slog.Info("ClickHouse logger bounded and clickhouse-server restarted", "path", clickHouseLoopbackPath)
	}
}

func (c clickHouseLoggerConverge) run(ctx context.Context) (bool, error) {
	if _, err := os.Lstat(c.failed); err == nil {
		return false, nil
	}
	have, _, err := readClickHouseLoopback(c.path)
	if errors.Is(err, fs.ErrNotExist) || (err == nil && boundedClickHouseLoopback(have) == nil) {
		return false, nil // no native ClickHouse here, already bounded, or not the managed form
	}
	if err != nil {
		return false, err
	}
	unlock, err := c.lock()
	if err != nil {
		return false, err // an upgrade, backup or restore holds the lock: the next tick tries again
	}
	defer unlock()
	have, info, err := readClickHouseLoopback(c.path)
	if err != nil {
		return false, err
	}
	want := boundedClickHouseLoopback(have)
	if want == nil {
		return false, nil
	}
	if err := replaceClickHouseLoopback(c.path, want, info); err != nil {
		return false, err
	}
	if err := c.restart(ctx); err != nil {
		err = fmt.Errorf("restart clickhouse-server: %w", err)
		if restoreErr := replaceClickHouseLoopback(c.path, have, info); restoreErr != nil {
			return false, errors.Join(err, restoreErr)
		}
		if restartErr := c.restart(ctx); restartErr != nil {
			err = errors.Join(err, fmt.Errorf("restart with the earlier file: %w", restartErr))
		}
		if markErr := os.WriteFile(c.failed, []byte(err.Error()+"\n"), 0o600); markErr != nil {
			err = errors.Join(err, markErr)
		}
		return false, err
	}
	return true, nil
}

func readClickHouseLoopback(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 || info.Size() > 64<<10 {
		return nil, nil, errors.New("managed ClickHouse configuration is not a single regular file")
	}
	content, err := os.ReadFile(path)
	return content, info, err
}

// replaceClickHouseLoopback writes content with the owner and mode of the current file and renames it into place.
func replaceClickHouseLoopback(path string, content []byte, info os.FileInfo) error {
	stat := info.Sys().(*syscall.Stat_t)
	directory := filepath.Dir(path)
	// A dot name ending in .new is not a configuration file ClickHouse merges.
	temporary := filepath.Join(directory, "."+filepath.Base(path)+".new")
	if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, info.Mode().Perm())
	if err != nil {
		return err
	}
	err = errors.Join(file.Chown(int(stat.Uid), int(stat.Gid)), file.Chmod(info.Mode().Perm()))
	if err == nil {
		_, err = file.Write(content)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporary, path)
	}
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	parent, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
