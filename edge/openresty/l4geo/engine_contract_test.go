package l4geo_contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixture struct {
	SchemaVersion string `json:"schema_version"`
	VersionID     string `json:"version_id"`
	Revision      uint64 `json:"revision"`
	Listeners     []struct {
		ID       string `json:"id"`
		TenantID string `json:"tenant_id"`
		SiteID   string `json:"site_id"`
		StreamID string `json:"stream_id"`
		Geo      *struct {
			Enabled             bool     `json:"enabled"`
			TenantID            string   `json:"tenant_id"`
			SiteID              string   `json:"site_id"`
			StreamID            string   `json:"stream_id"`
			Revision            uint64   `json:"revision"`
			UnknownRegionAction string   `json:"unknown_region_action"`
			BlockedRegions      []string `json:"blocked_regions"`
			TrustedProxyCIDRs   []string `json:"trusted_proxy_cidrs"`
			RegionCIDRs         []struct {
				Region string   `json:"region"`
				CIDRs  []string `json:"cidrs"`
			} `json:"region_cidrs"`
		} `json:"geo"`
	} `json:"listeners"`
}

func testRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate contract test")
	}
	return filepath.Dir(file)
}

func readFixture(t *testing.T, name string) fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(testRoot(t), "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAggregatedV2FixtureCarriesExactStreamScopeAndDualStackLPM(t *testing.T) {
	got := readFixture(t, "config-v2.json")
	if got.SchemaVersion != "cdnca.edge.l4/v2" || got.VersionID == "" || got.Revision != 7 || len(got.Listeners) != 2 {
		t.Fatalf("invalid aggregate authority: %+v", got)
	}
	listener := got.Listeners[0]
	if listener.Geo == nil || !listener.Geo.Enabled || listener.ID != listener.StreamID || listener.Geo.TenantID != listener.TenantID ||
		listener.Geo.SiteID != listener.SiteID || listener.Geo.StreamID != listener.StreamID ||
		listener.Geo.Revision != got.Revision || listener.Geo.UnknownRegionAction != "block" {
		t.Fatalf("geo scope is not exact: %+v", listener)
	}
	joined := strings.Join(append(append([]string{}, listener.Geo.TrustedProxyCIDRs...),
		listener.Geo.RegionCIDRs[0].CIDRs...), ",")
	if !strings.Contains(joined, "192.0.2.0/24") || !strings.Contains(joined, "2001:db8:200::/48") ||
		!strings.Contains(strings.Join(listener.Geo.RegionCIDRs[1].CIDRs, ","), "203.0.113.128/25") {
		t.Fatalf("fixture does not discriminate IPv4, IPv6, and longest prefix: %+v", listener.Geo)
	}
	if got.Listeners[1].Geo != nil {
		t.Fatal("a stream without geo must remain independent")
	}
}

func TestCrossScopeFixtureIsActuallyCrossScope(t *testing.T) {
	got := readFixture(t, "config-v2-cross-scope.json")
	listener := got.Listeners[0]
	if listener.Geo == nil || listener.Geo.SiteID == listener.SiteID {
		t.Fatal("negative fixture no longer proves cross-site rejection")
	}
}

func TestLuaSourceKeepsVerifiedLKGAndNeverTurnsProxyTrustIntoBypass(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(testRoot(t), "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, required := range []string{
		`SCHEMA = "cdnca.edge.l4/v2"`,
		`candidate_rejected_lkg`,
		`candidate_rejected_cold`,
		`geo_scope_mismatch`,
		`unknown_region_action`,
		`proxy_protocol_addr`,
		`remote_addr`,
		`prefix_length`,
		`geo_unknown_allowed`,
		`geo_unknown_blocked`,
		`geo_blocked`,
		`ngx.exit(ngx.ERROR)`,
		// new_conn_rate (tcp/udp v6): the bucket and ban keys #8 reuses.
		`function _M.limit_new_connections(stream_id, client, rate, burst, ban_seconds, log)`,
		`ngx.shared.l4_v2_rate`,
		`"ban:" .. stream_id .. ":" .. client`,
		`"rate:" .. stream_id .. ":" .. client`,
		// session_log (tcp/udp v7): reasons, live registry, agent control.
		`function _M.enforce(listener_id, log)`,
		`ngx.var.cdnca_l4_end_reason`,
		`function _M.session_track(stream_id, listener_id, client, dispatched)`,
		`function _M.session_end()`,
		`function _M.control()`,
		`local LIVE_DICT = "l4_v2_live"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("engine is missing contract %q", required)
		}
	}
	if strings.Contains(source, "geoip") || strings.Contains(source, "http_x_forwarded_for") {
		t.Fatal("stream geo must not depend on external geo or HTTP proxy headers")
	}
	shim, err := os.ReadFile(filepath.Join(testRoot(t), "cdnca_l4_geo.lua"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(shim)) != `return require("l4geo.engine")` {
		t.Fatal("canonical cdnca_l4_geo module shim drifted")
	}
}
