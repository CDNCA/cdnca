package originroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileOriginDNSUsesBackgroundResolverAndSharedLKG(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "origin.example.com"
	artifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	config := string(artifact.Nginx)
	for _, required := range []string{
		"lua_shared_dict cdnca_originroute_dns_state 8m;",
		"init_worker_by_lua_block {",
		`require("engine").start_dns()`,
		`set $cdnca_origin_dns_state "";`,
		`set $cdnca_origin_dns_reason "";`,
	} {
		if !strings.Contains(config, required) {
			t.Errorf("compiled Nginx missing DNS runtime contract %q", required)
		}
	}
	if strings.Contains(config, "resolver ") || strings.Contains(config, "resolver_timeout") {
		t.Fatal("compiled Nginx delegates hostname resolution outside the bounded Lua LKG contract")
	}
	if !strings.Contains(string(artifact.Policy), `"dns":{"resolver":"","query_timeout_ms":1000,"min_ttl_seconds":5,"max_ttl_seconds":300,"stale_ttl_seconds":900}`) {
		t.Fatalf("canonical policy missing explicit DNS defaults: %s", artifact.Policy)
	}
}

func TestCompileOriginDNSHealthRequiresCurrentRevisionReadiness(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "origin.example.com"
	artifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	config := string(artifact.Nginx)
	if !strings.Contains(config, `content_by_lua_block { require("engine").health("route-v1") }`) {
		t.Fatal("DNS health endpoint must delegate readiness to the active Lua revision")
	}
	if strings.Contains(config, `return 200 "ok:route-v1\n"`) {
		t.Fatal("DNS health endpoint must not report success before hostname state is ready")
	}
}

func TestOriginDNSEngineRefreshesOffRequestPathAndFailsClosedAfterStale(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	engine := string(raw)
	for _, required := range []string{
		`local dns_resolver = require "resty.dns.resolver"`,
		"local DNS_MAX_CNAME_HOPS = 8",
		"local DNS_MAX_ANSWERS = 32",
		"local DNS_MAX_INFLIGHT = 32",
		"local dns_inflight = {}",
		"local function dns_refresh_tick(premature)",
		"function _M.start_dns()",
		"ngx.timer.every(1, dns_refresh_tick)",
		"local function dns_select_address(endpoint, now)",
		`return address, "fresh", "dns_fresh"`,
		`return address, "stale", state.reason`,
		`return nil, "expired", "dns_stale_expired"`,
		`return nil, "unavailable", "dns_unresolved"`,
		`ngx.var.cdnca_origin_dns_state = dns_state`,
		`ngx.var.cdnca_origin_dns_reason = dns_reason`,
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("DNS engine missing %q", required)
		}
	}

	access := functionBody(t, engine, "function _M.access(listener_id)", "local function retryable_last_failure")
	balance := functionBody(t, engine, "function _M.balance()", "function _M.log_result()")
	if strings.Contains(access, "resolver:query") || strings.Contains(balance, "resolver:query") {
		t.Fatal("request path performs synchronous DNS resolution")
	}
	if !strings.Contains(balance, "dns_select_address(candidate.endpoint, ngx.now())") {
		t.Fatal("balancer does not consume bounded shared DNS state")
	}
}

func TestOriginDNSEngineRound2ReadinessOwnerAndMappedIPv6Contracts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	engine := string(raw)
	for _, required := range []string{
		"function _M.health(version_id)",
		"ngx.HTTP_SERVICE_UNAVAILABLE",
		"dns_owner_mismatch",
		"local function ipv4_mapped_ipv6(address)",
		"ipv4_mapped_ipv6(address)",
		"answer.name",
		"dns_cname_chain",
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("Round-2 DNS engine missing %q", required)
		}
	}
	if !strings.Contains(engine, "target.key") || !strings.Contains(engine, "active.revision") {
		t.Fatal("DNS readiness must inspect state keys for the active revision targets")
	}
}

func functionBody(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing function marker %q", startMarker)
	}
	end := strings.Index(source[start:], endMarker)
	if end < 0 {
		t.Fatalf("missing function end marker %q", endMarker)
	}
	return source[start : start+end]
}
