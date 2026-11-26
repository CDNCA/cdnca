package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const earlierClickHouseLoopback = clickHouseLoopbackListeners + "</clickhouse>\n"

func clickHouseLoggerFixture(t *testing.T, content string) (*clickHouseLoggerConverge, *int, *[]error) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "cdnca-loopback.xml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	restarts, results := 0, []error{}
	converge := &clickHouseLoggerConverge{path: path, failed: filepath.Join(directory, "clickhouse-logger.failed"),
		lock: func() (func(), error) { return func() {}, nil },
		restart: func(context.Context) error {
			restarts++
			if len(results) == 0 {
				return nil
			}
			err := results[0]
			results = results[1:]
			return err
		}}
	return converge, &restarts, &results
}

func TestClickHouseLoggerBoundsEarlierManagedFile(t *testing.T) {
	converge, restarts, _ := clickHouseLoggerFixture(t, earlierClickHouseLoopback)
	changed, err := converge.run(context.Background())
	if err != nil || !changed || *restarts != 1 {
		t.Fatalf("changed=%v err=%v restarts=%d", changed, err, *restarts)
	}
	have, _ := os.ReadFile(converge.path)
	if string(have) != clickHouseLoopbackListeners+clickHouseLoggerBlock+"</clickhouse>\n" {
		t.Fatalf("content %q", have)
	}
	if info, _ := os.Stat(converge.path); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
	for _, want := range []string{"<level>information</level>", "<size>100M</size>", "<count>5</count>"} {
		if !strings.Contains(string(have), want) {
			t.Fatalf("missing %s", want)
		}
	}
	// Converged: the next tick neither writes nor restarts.
	if changed, err := converge.run(context.Background()); err != nil || changed || *restarts != 1 {
		t.Fatalf("second run changed=%v err=%v restarts=%d", changed, err, *restarts)
	}
	if entries, _ := os.ReadDir(filepath.Dir(converge.path)); len(entries) != 1 {
		t.Fatalf("leftover files %v", entries)
	}
}

func TestClickHouseLoggerKeepsMovedPortsAfterTheLogger(t *testing.T) {
	ports := "    <http_port>18123</http_port>\n    <tcp_port>19100</tcp_port>\n</clickhouse>\n"
	converge, _, _ := clickHouseLoggerFixture(t, clickHouseLoopbackListeners+ports)
	if _, err := converge.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	// configure-clickhouse.py native_clickhouse_loopback_content: ports follow LOOPBACK_DEFAULT's logger.
	if have, _ := os.ReadFile(converge.path); string(have) != clickHouseLoopbackListeners+clickHouseLoggerBlock+ports {
		t.Fatalf("content %q", have)
	}
}

func TestClickHouseLoggerLeavesOtherContentAlone(t *testing.T) {
	for _, content := range []string{
		clickHouseLoopbackListeners + clickHouseLoggerBlock + "</clickhouse>\n",
		clickHouseLoopbackListeners + "    <logger>\n        <level>debug</level>\n    </logger>\n</clickhouse>\n",
		"<clickhouse>\n    <listen_host>0.0.0.0</listen_host>\n</clickhouse>\n",
	} {
		converge, restarts, _ := clickHouseLoggerFixture(t, content)
		if changed, err := converge.run(context.Background()); err != nil || changed || *restarts != 0 {
			t.Fatalf("%q: changed=%v err=%v restarts=%d", content, changed, err, *restarts)
		}
		if have, _ := os.ReadFile(converge.path); string(have) != content {
			t.Fatalf("rewritten %q", have)
		}
	}
	converge, _, _ := clickHouseLoggerFixture(t, earlierClickHouseLoopback)
	converge.path += ".absent"
	if changed, err := converge.run(context.Background()); err != nil || changed {
		t.Fatalf("absent file: changed=%v err=%v", changed, err)
	}
}

func TestClickHouseLoggerWaitsForTheReleaseLock(t *testing.T) {
	converge, restarts, _ := clickHouseLoggerFixture(t, earlierClickHouseLoopback)
	converge.lock = func() (func(), error) { return nil, errors.New("busy") }
	if _, err := converge.run(context.Background()); err == nil || *restarts != 0 {
		t.Fatalf("err=%v restarts=%d", err, *restarts)
	}
	if have, _ := os.ReadFile(converge.path); string(have) != earlierClickHouseLoopback {
		t.Fatalf("written without the lock: %q", have)
	}
}

func TestClickHouseLoggerRestoresTheEarlierFileWhenRestartFails(t *testing.T) {
	converge, restarts, results := clickHouseLoggerFixture(t, earlierClickHouseLoopback)
	*results = []error{errors.New("start failed"), nil}
	if changed, err := converge.run(context.Background()); err == nil || changed || *restarts != 2 {
		t.Fatalf("changed=%v err=%v restarts=%d", changed, err, *restarts)
	}
	if have, _ := os.ReadFile(converge.path); string(have) != earlierClickHouseLoopback {
		t.Fatalf("not restored: %q", have)
	}
	// The failure marker stops a restart every tick.
	if changed, err := converge.run(context.Background()); err != nil || changed || *restarts != 2 {
		t.Fatalf("after failure changed=%v err=%v restarts=%d", changed, err, *restarts)
	}
}

// The fresh-install bytes (install-ubuntu-dependencies.sh, equal to configure-clickhouse.py LOOPBACK_DEFAULT by
// test_configure_clickhouse.py) are what an upgraded host converges to.
func TestClickHouseLoggerMatchesFreshInstall(t *testing.T) {
	script, err := os.ReadFile("../../../../scripts/native-runtime/install-ubuntu-dependencies.sh")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^DEPS_LOOPBACK_CONTENT=\$'(.*)'$`).FindSubmatch(script)
	if match == nil {
		t.Fatal("DEPS_LOOPBACK_CONTENT not found")
	}
	fresh := strings.ReplaceAll(string(match[1]), `\n`, "\n")
	if want := string(boundedClickHouseLoopback([]byte(earlierClickHouseLoopback))); fresh != want {
		t.Fatalf("fresh install %q, converge %q", fresh, want)
	}
}
