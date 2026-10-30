package nativebackup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fix-btenv: a migration may move a control plane between a plain host
// (default dependency ports) and a BaoTa host (moved ports, recorded in the
// host port profile). The restored loopback URLs must follow the target.
func writeRetargetFixture(t *testing.T, layout Layout, files map[string]string) {
	t.Helper()
	for name, content := range files {
		path := layout.Path(name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func readFixture(t *testing.T, layout Layout, name string) string {
	t.Helper()
	content, err := os.ReadFile(layout.Path(name))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestReadHostPortsDefaultsAndProfile(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	ports, err := ReadHostPorts(layout)
	if err != nil || ports != DefaultHostPorts() {
		t.Fatalf("absent profile: %+v %v", ports, err)
	}
	writeRetargetFixture(t, layout, map[string]string{HostPortsFile: "ENV=bt\nWEB_PORT=18443\nNODE_DOWNLOAD_PORT=19445\nPG_PORT=15432\nREDIS_PORT=16379\nCH_HTTP_PORT=18123\nCH_TCP_PORT=19100\n"})
	ports, err = ReadHostPorts(layout)
	if err != nil || ports.Web != 18443 || ports.NodeDownload != 19445 || ports.PostgreSQL != 15432 || ports.Redis != 16379 || ports.ClickHouseHTTP != 18123 || ports.ClickHouseTCP != 19100 || ports.Env != "bt" {
		t.Fatalf("profile: %+v %v", ports, err)
	}
	for _, bad := range []string{"PG_PORT=80\n", "PG_PORT=1;id\n", "PG_PORT=15432\nPG_PORT=15433\n", "OTHER=1\n"} {
		writeRetargetFixture(t, layout, map[string]string{HostPortsFile: bad})
		if _, err := ReadHostPorts(layout); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRetargetPortsRewritesOnlyLoopbackDependencyURLs(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, layout, map[string]string{
		HostPortsFile: "ENV=bt\nPG_PORT=15432\nREDIS_PORT=16379\nCH_HTTP_PORT=18123\nCH_TCP_PORT=9000\n",
		ConfigDirectory + "/control.env": "DATABASE_URL=postgres://cdnca:pw@127.0.0.1:5432/cdnca?sslmode=disable\n" +
			"REDIS_URL=redis://127.0.0.1:6379/0\nNODE_PRESENCE_REDIS_URL=redis://127.0.0.1:6379/0\n" +
			"LICENSE_SERVICE_URL=https://auth.cdnca.com:5432/\nHTTP_ADDR=127.0.0.1:8080\n",
		ConfigDirectory + "/gateway.env":              "CDNCA_REDIS_URL=redis://127.0.0.1:6379/0\n",
		ConfigDirectory + "/gateway-access.env":       "REDIS_URL=redis://:p@127.0.0.1:6379/0\n",
		ConfigDirectory + "/gateway-access-local.env": "CDNCA_REDIS_URL=redis://:p@127.0.0.1:6379/0\n",
		AnalyticsConfig + "/runtime.env":              "CLICKHOUSE_URL=http://127.0.0.1:8123\nANALYTICS_INGEST_CLICKHOUSE_URL=http://127.0.0.1:8123\n",
	})
	var log []string
	if err := RetargetPorts(context.Background(), layout, func(format string, values ...any) { log = append(log, format) }); err != nil {
		t.Fatal(err)
	}
	control := readFixture(t, layout, ConfigDirectory+"/control.env")
	for _, want := range []string{"@127.0.0.1:15432/cdnca", "REDIS_URL=redis://127.0.0.1:16379/0", "NODE_PRESENCE_REDIS_URL=redis://127.0.0.1:16379/0",
		"LICENSE_SERVICE_URL=https://auth.cdnca.com:5432/", "HTTP_ADDR=127.0.0.1:8080"} {
		if !strings.Contains(control, want) {
			t.Errorf("control.env lacks %q:\n%s", want, control)
		}
	}
	if got := readFixture(t, layout, ConfigDirectory+"/gateway.env"); got != "CDNCA_REDIS_URL=redis://127.0.0.1:16379/0\n" {
		t.Errorf("gateway.env = %q", got)
	}
	if got := readFixture(t, layout, ConfigDirectory+"/gateway-access.env"); got != "REDIS_URL=redis://:p@127.0.0.1:16379/0\n" {
		t.Errorf("gateway-access.env = %q", got)
	}
	if got := readFixture(t, layout, AnalyticsConfig+"/runtime.env"); strings.Count(got, "http://127.0.0.1:18123") != 2 {
		t.Errorf("analytics runtime.env = %q", got)
	}
	info, err := os.Stat(layout.Path(ConfigDirectory + "/control.env"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode must be preserved: %v %v", info.Mode(), err)
	}
	if len(log) == 0 {
		t.Fatal("a retarget must be reported")
	}
}

func TestRetargetPortsBackToDefaultsAndNoopWhenEqual(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	source := "DATABASE_URL=postgres://cdnca:pw@127.0.0.1:15432/cdnca?sslmode=disable\nREDIS_URL=redis://127.0.0.1:16379/0\n"
	writeRetargetFixture(t, layout, map[string]string{ConfigDirectory + "/control.env": source})
	if err := RetargetPorts(context.Background(), layout, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, layout, ConfigDirectory+"/control.env"); got != "DATABASE_URL=postgres://cdnca:pw@127.0.0.1:5432/cdnca?sslmode=disable\nREDIS_URL=redis://127.0.0.1:6379/0\n" {
		t.Fatalf("plain target must get default ports: %q", got)
	}
	before := readFixture(t, layout, ConfigDirectory+"/control.env")
	if err := RetargetPorts(context.Background(), layout, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if readFixture(t, layout, ConfigDirectory+"/control.env") != before {
		t.Fatal("second run must be a no-op")
	}
}

func TestRetargetPortsLeavesExternalDatabaseAlone(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	source := "DATABASE_URL=postgres://cdnca:pw@db.internal:5432/cdnca?sslmode=require\nREDIS_URL=redis://cache.internal:6379/0\n"
	writeRetargetFixture(t, layout, map[string]string{ConfigDirectory + "/control.env": source,
		HostPortsFile: "ENV=bt\nPG_PORT=15432\nREDIS_PORT=16379\n"})
	if err := RetargetPorts(context.Background(), layout, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, layout, ConfigDirectory+"/control.env"); got != source {
		t.Fatalf("external services must not change: %q", got)
	}
}

// The PostgreSQL client programs follow the target port (socket name
// .s.PGSQL.<port>); a plain target keeps the client defaults.
func TestDatabaseTargetFollowsHostPorts(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	target := DefaultDatabaseTarget().WithHostPorts(layout)
	if len(target.Env) != 0 {
		t.Fatalf("plain target env = %v", target.Env)
	}
	writeRetargetFixture(t, layout, map[string]string{HostPortsFile: "ENV=bt\nPG_PORT=15432\n"})
	target = DefaultDatabaseTarget().WithHostPorts(layout)
	if strings.Join(target.Env, " ") != "PGPORT=15432" {
		t.Fatalf("bt target env = %v", target.Env)
	}
}

func TestRestoreRetargetsPortsToTheBaoTaTarget(t *testing.T) {
	rig := newRig(t)
	bundle := rig.backupBundle()
	writeRetargetFixture(t, rig.host.Layout, map[string]string{
		HostPortsFile:                    "ENV=bt\nPG_PORT=15432\nREDIS_PORT=16379\n",
		ConfigDirectory + "/control.env": "DATABASE_URL=postgres://cdnca:pw@127.0.0.1:5432/cdnca?sslmode=disable\nREDIS_URL=redis://127.0.0.1:6379/0\n",
	})
	if _, err := rig.restorer(nil).Run(context.Background(), RestoreRequest{Bundle: bundle, Identity: rig.keys.Identity}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, rig.host.Layout, ConfigDirectory+"/control.env"); got !=
		"DATABASE_URL=postgres://cdnca:pw@127.0.0.1:15432/cdnca?sslmode=disable\nREDIS_URL=redis://127.0.0.1:16379/0\n" {
		t.Fatalf("control.env = %q", got)
	}
}

const plainNginx = "    server {\n        listen 443 ssl http2;\n        server_name _;\n        root /web;\n"
const btNginx = "    server {\n        listen 127.0.0.1:18443 ssl http2;\n        server_name _;\n        set_real_ip_from 127.0.0.1;\n        real_ip_header X-Real-IP;\n        root /web;\n"

func TestRetargetWebListenerBetweenPlainAndBaoTa(t *testing.T) {
	layout := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, layout, map[string]string{HostPortsFile: "ENV=bt\nWEB_PORT=18443\n",
		ConfigDirectory + "/nginx.conf":  plainNginx,
		ConfigDirectory + "/control.env": "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com\n"})
	if err := RetargetPorts(context.Background(), layout, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, layout, ConfigDirectory+"/nginx.conf"); got != btNginx {
		t.Fatalf("plain -> bt nginx.conf = %q", got)
	}
	// Back to a plain host: the public port comes from the control origin.
	plain := Layout{Root: t.TempDir()}
	writeRetargetFixture(t, plain, map[string]string{ConfigDirectory + "/nginx.conf": btNginx,
		ConfigDirectory + "/control.env": "PAYMENT_CHANNELS_NOTIFY_BASE=https://cdnca.com:8443\n"})
	if err := RetargetPorts(context.Background(), plain, func(string, ...any) {}); err != nil {
		t.Fatal(err)
	}
	if got := readFixture(t, plain, ConfigDirectory+"/nginx.conf"); got != strings.Replace(plainNginx, "listen 443", "listen 8443", 1) {
		t.Fatalf("bt -> plain nginx.conf = %q", got)
	}
}
