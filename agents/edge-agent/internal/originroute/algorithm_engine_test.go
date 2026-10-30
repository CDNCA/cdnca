package originroute

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func originRouteAlgorithmEngine(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestOriginRouteAlgorithmEngineConsumesScopedContract(t *testing.T) {
	engine := originRouteAlgorithmEngine(t)
	for _, required := range []string{
		"tenant_id = true, site_id = true",
		"algorithm = true",
		`local algorithm = pool.algorithm or "round_robin"`,
		`round_robin = true`,
		`ip_hash = true`,
		`url_hash = true`,
		`least_conn = true`,
		`random = true`,
		`state_key = table.concat({`,
		`"v1|tenant=", policy.tenant_id, "|site=", policy.site_id, "|version=", policy.version_id`,
		`local function algorithm_state_key(pool, endpoint, suffix)`,
		`active.state_key`,
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("engine missing scoped algorithm contract %q", required)
		}
	}
}

func TestOriginRouteAlgorithmEngineHasFiveDistinctBaselineAlgorithms(t *testing.T) {
	engine := originRouteAlgorithmEngine(t)
	for _, required := range []string{
		"local function weighted_slot_sequence(pool, slot)",
		"local function round_robin_sequence(pool)",
		`algorithm_state_key(pool, nil, "round-robin"), 1, 0, active.state_ttl)`,
		"local function canonical_client_ip(client)",
		"local function ip_hash_sequence(pool, client)",
		"local function url_hash_sequence(pool, request_uri)",
		"local function request_random_seed()",
		`not request_id:match("^[0-9A-Fa-f]+$")`,
		"local function random_sequence(pool)",
		"local function least_conn_sequence(pool, seed)",
		"(inflight + 1) / endpoint.weight",
		`if pool.algorithm == "round_robin" then`,
		`elseif pool.algorithm == "ip_hash" then`,
		`elseif pool.algorithm == "url_hash" then`,
		`elseif pool.algorithm == "least_conn" then`,
		`elseif pool.algorithm == "random" then`,
		`return nil, "unknown origin route algorithm"`,
		"request_uri = ngx.var.request_uri",
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("engine missing baseline algorithm behavior %q", required)
		}
	}
	if strings.Contains(engine, "math.random") {
		t.Fatal("random selection must not use process-global math.random state")
	}
	if strings.Contains(engine, "weighted_sequence") {
		t.Fatal("engine retains the pre-contract single weighted-hash selector")
	}
	algorithmStart := strings.Index(engine, "local function algorithm_sequence(pool, request)")
	if algorithmStart < 0 {
		t.Fatal("cannot isolate baseline algorithm dispatch")
	}
	algorithmEnd := strings.Index(engine[algorithmStart:], "\nend\n\nlocal function baseline_inflight")
	if algorithmEnd < 0 || strings.Contains(
		engine[algorithmStart:algorithmStart+algorithmEnd], "adaptive_",
	) {
		t.Fatal("baseline algorithm dispatch is coupled to adaptive enhancement")
	}
}

func TestOriginRouteLeastConnFailsClosedAndReclaimsInflight(t *testing.T) {
	engine := originRouteAlgorithmEngine(t)
	for _, required := range []string{
		"local function baseline_inflight(candidate, delta)",
		"candidate.baseline_inflight_recorded",
		"local function baseline_observe(context, candidate)",
		`context.algorithm_unavailable = true`,
		`ngx.var.cdnca_origin_event = "algorithm_state_unavailable"`,
		"local baseline_state_ok = baseline_observe(context, context.previous)",
		"if not baseline_state_ok then",
		"baseline_observe(context, context.previous)",
		"baseline_inflight(candidate, -1)",
		"abandon_candidate(context, candidate)",
		"local function copy_candidate_sequence(source)",
		"append_adaptive_sequence(adaptive_sequence_values, pool, seed, ngx.now(), primary_baseline)",
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("engine missing least-conn fail-closed lifecycle %q", required)
		}
	}
}

func TestOriginRouteInvalidAlgorithmPolicyPreservesActiveLKG(t *testing.T) {
	engine := originRouteAlgorithmEngine(t)
	start := strings.Index(engine, "function _M.init_file(path)")
	end := strings.Index(engine[start:], "\nend\n\nlocal function path_matches")
	if start < 0 || end < 0 {
		t.Fatal("cannot isolate init_file function")
	}
	initFile := engine[start : start+end]
	validated := strings.Index(initFile, "local compiled, validation_err = validate_policy(decoded)")
	leased := strings.Index(initFile, "local lease_ok, lease_err = lease_protocol_init")
	activated := strings.Index(initFile, "active = compiled")
	if validated < 0 || leased < 0 || activated < 0 || validated > leased || leased > activated ||
		strings.Count(initFile, "active = compiled") != 1 {
		t.Fatalf("policy validation/LKG activation order is unsafe: validate=%d lease=%d active=%d", validated, leased, activated)
	}
}

func TestOriginRouteHealthAndFallbackPrecedeBaselineAlgorithm(t *testing.T) {
	engine := originRouteAlgorithmEngine(t)
	accessStart := strings.Index(engine, "function _M.access(listener_id)")
	accessEnd := strings.Index(engine[accessStart:], "\nend\n\nlocal function retryable_last_failure")
	if accessStart < 0 || accessEnd < 0 {
		t.Fatal("cannot isolate access function")
	}
	access := engine[accessStart : accessStart+accessEnd]
	circuit := strings.Index(access, "circuit_allow(pool)")
	primary := strings.Index(access, "append_sequence(baseline_sequence, pool")
	fallback := strings.Index(access, "append_sequence(baseline_sequence, fallback")
	if circuit < 0 || primary < 0 || fallback < 0 || circuit > primary || primary > fallback {
		t.Fatalf("health/circuit/fallback ordering is not unified before selection: circuit=%d primary=%d fallback=%d", circuit, primary, fallback)
	}
}
