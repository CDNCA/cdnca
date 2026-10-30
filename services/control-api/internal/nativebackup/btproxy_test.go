package nativebackup

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fix-btenv2: a migration onto a BaoTa host writes the same bt-proxy.conf as
// a fresh BaoTa installation (testdata/bt-proxy.conf is also checked against
// install-control.sh bt_proxy_config by tests/install-control-bt-env.test.mjs).
func TestRestoreOntoBaoTaWritesTheInstallerProxyConfig(t *testing.T) {
	want, err := os.ReadFile("testdata/bt-proxy.conf")
	if err != nil {
		t.Fatal(err)
	}
	layout := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, layout, map[string]string{HostPortsFile: "ENV=bt\nWEB_PORT=18443\n",
		ConfigDirectory + "/nginx.conf":  plainNginx,
		ConfigDirectory + "/control.env": "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com\n"})
	var lines []string
	if err := RetargetPorts(context.Background(), layout, func(format string, values ...any) {
		lines = append(lines, fmt.Sprintf(format, values...))
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, layout, BaoTaProxyFile); got != string(want) {
		t.Fatalf("bt-proxy.conf =\n%s\nwant\n%s", got, want)
	}
	info, err := os.Stat(layout.Path(BaoTaProxyFile))
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("bt-proxy.conf mode = %v, %v", info, err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), BaoTaProxyFile) {
		t.Fatalf("progress must name the proxy config: %v", lines)
	}
	// A plain target removes a stale copy restored from a BaoTa source.
	plain := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, plain, map[string]string{BaoTaProxyFile: string(want),
		ConfigDirectory + "/nginx.conf":  btNginx,
		ConfigDirectory + "/control.env": "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com\n"})
	if err := RetargetPorts(context.Background(), plain, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plain.Path(BaoTaProxyFile)); !os.IsNotExist(err) {
		t.Fatalf("plain target keeps bt-proxy.conf: %v", err)
	}
}

func TestBaoTaProxyConfigNeedsADomain(t *testing.T) {
	if _, err := BaoTaProxyConfig("https://203.0.113.9", 18443); err == nil {
		t.Fatal("an IP origin has no BaoTa site")
	}
	if _, err := BaoTaProxyConfig("https://cdnca.com:8443", 18443); err != nil {
		t.Fatal(err)
	}
}

// The migration reports the target environment so the old host's run log and
// console can tell the operator to configure the BaoTa reverse proxy.
func TestPushMigrationReportsBaoTaTargetAndProxySteps(t *testing.T) {
	_, remote, migrator := migrationRig(t)
	remote.answers["test -d /www/server/panel"] = "bt\n"
	remote.answers["awk "] = "80\n443\n"
	var log []string
	result, err := migrator.Migrate(context.Background(), testTarget, func(line string) { log = append(log, line) })
	if err != nil {
		t.Fatal(err)
	}
	if result.TargetEnv != "bt" || result.BackupID == "" {
		t.Fatalf("result = %+v", result)
	}
	text := strings.Join(log, "\n")
	for _, want := range []string{"宝塔", BaoTaProxyFile, "反向代理", "https://127.0.0.1:18443"} {
		if !strings.Contains(text, want) {
			t.Fatalf("migration log lacks %q:\n%s", want, text)
		}
	}
	_, plainRemote, plainMigrator := migrationRig(t)
	plainRemote.answers["test -d /www/server/panel"] = ""
	result, err = plainMigrator.Migrate(context.Background(), testTarget, func(string) {})
	if err != nil || result.TargetEnv != "plain" {
		t.Fatalf("plain result = %+v, %v", result, err)
	}
}

func TestAgentRecordsTheMigrationTargetEnvironment(t *testing.T) {
	rig := newRig(t)
	target := testTarget
	run, err := SubmitRequest(rig.host.Layout, Request{Kind: RequestMigrate, Migration: &target}, rig.now())
	if err != nil {
		t.Fatal(err)
	}
	if err := rig.agent(&fakeMigrator{env: "bt"}).Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	finished, _ := ReadRun(rig.host.Layout, run.ID)
	if finished.State != RunSucceeded || finished.TargetEnv != "bt" {
		t.Fatalf("run = %+v", finished)
	}
}
