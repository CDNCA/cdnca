package edgeconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteTelemetryHTTPForSmoke writes the http{} level telemetry (maps and
// log formats) for scripts/analytics/telemetry-fields-smoke.sh, which runs it
// in the pinned OpenResty. Skipped unless CDNCA_TELEMETRY_SMOKE_OUT is set.
func TestWriteTelemetryHTTPForSmoke(t *testing.T) {
	out := os.Getenv("CDNCA_TELEMETRY_SMOKE_OUT")
	if out == "" {
		t.Skip("CDNCA_TELEMETRY_SMOKE_OUT not set")
	}
	if err := os.WriteFile(filepath.Join(out, "telemetry-http.conf"), []byte(RenderTelemetryHTTP()), 0o644); err != nil {
		t.Fatal(err)
	}
	server := RenderTelemetryServer(TelemetryServer{
		TenantID: "11111111-1111-4111-8111-111111111111", SiteID: "33333333-3333-4333-8333-333333333333",
		ConfigVersionID: "cfg", AccessLogPath: "/work/logs/access.json", SecurityLogPath: "/work/logs/security.json",
	})
	if err := os.WriteFile(filepath.Join(out, "telemetry-server.conf"), []byte(server), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestWritePackageBandwidthForSmoke writes one subscription's bandwidth limit
// (16 Mbit/s) for scripts/analytics/package-bandwidth-smoke.sh.
func TestWritePackageBandwidthForSmoke(t *testing.T) {
	out := os.Getenv("CDNCA_PACKAGE_BANDWIDTH_SMOKE_OUT")
	if out == "" {
		t.Skip("CDNCA_PACKAGE_BANDWIDTH_SMOKE_OUT not set")
	}
	limit := PackageConnectionLimit{SubscriptionID: "22222222-2222-4222-8222-222222222222", Connections: -1, BandwidthBPS: 16_000_000}
	directive, err := PackageBandwidthDirective(limit)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"package-http.conf":   PackageBandwidthHTTP([]PackageConnectionLimit{limit}),
		"package-server.conf": directive + "    log_by_lua_block {\n      " + PackageBandwidthLogLua(limit) + "    }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(out, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
