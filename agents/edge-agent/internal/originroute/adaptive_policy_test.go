package originroute

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	baselineCanonicalSHA256 = "b07ea2f9d2119d564379afc91dc5c4cf6e657f5552cf7112572f0480d4b9f222"
	baselineNginxSHA256     = "f7a99037a3a405325f1e52af1efe33f7c7fd7457afbf1c305d928450a5873f8b"
	baselineArtifactDigest  = "c694f16e495f0b8d3811734246d5facc2c9463316c41d95e449df80a5bff010c"
)

func adaptivePolicy(mode AdaptiveMode) *AdaptivePolicy {
	return &AdaptivePolicy{
		Version:            1,
		Mode:               mode,
		MinimumSamples:     4,
		SampleFreshnessMS:  30000,
		PeakEWMAHalfLifeMS: 10000,
		ExplorationPercent: 2,
		SlowStart: SlowStartPolicy{
			InitialWeightPercent: 10,
			RampMS:               30000,
			HardTimeoutMS:        120000,
		},
		Outlier: OutlierPolicy{
			MinimumSamples:          8,
			ConsecutiveFailures:     3,
			FailureRatioPercent:     50,
			MaxEjectionPercent:      50,
			BaseEjectionMS:          1000,
			MaxEjectionMS:           60000,
			RecoveryProbeIntervalMS: 1000,
		},
	}
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func TestAdaptiveDisabledPreservesBaselineArtifactBytes(t *testing.T) {
	policy := testPolicy()
	canonical, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	if got := digestBytes(canonical); got != baselineCanonicalSHA256 {
		t.Fatalf("baseline canonical drift=%s", got)
	}
	if got := digestBytes(artifact.Nginx); got != baselineNginxSHA256 {
		t.Fatalf("baseline nginx drift=%s", got)
	}
	if artifact.Digest != baselineArtifactDigest {
		t.Fatalf("baseline artifact drift=%s", artifact.Digest)
	}
	if strings.Contains(string(canonical), "adaptive") ||
		strings.Contains(string(artifact.Nginx), "cdnca_originroute_adaptive_state") {
		t.Fatal("disabled baseline unexpectedly contains adaptive bytes")
	}

	policy.Adaptive = adaptivePolicy(AdaptiveOff)
	offCanonical, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	offArtifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	if string(offCanonical) != string(canonical) || string(offArtifact.Nginx) != string(artifact.Nginx) ||
		offArtifact.Digest != artifact.Digest {
		t.Fatal("explicit adaptive off must normalize to byte-identical baseline")
	}
}

func TestAdaptivePolicyIsStrictVersionedAndOptIn(t *testing.T) {
	for _, mode := range []AdaptiveMode{AdaptiveShadow, AdaptiveActive} {
		policy := testPolicy()
		policy.Adaptive = adaptivePolicy(mode)
		normalized, err := Normalize(policy)
		if err != nil {
			t.Fatalf("mode=%s: %v", mode, err)
		}
		if normalized.Adaptive == nil || normalized.Adaptive.Version != 1 || normalized.Adaptive.Mode != mode {
			t.Fatalf("mode=%s normalized=%+v", mode, normalized.Adaptive)
		}
		artifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
		if err != nil {
			t.Fatal(err)
		}
		config := string(artifact.Nginx)
		for _, expected := range []string{
			"lua_shared_dict cdnca_originroute_adaptive_state 2m;",
			"set $cdnca_origin_reason \"\";",
			"set $cdnca_origin_shadow_reason \"\";",
			"set $cdnca_origin_diagnostic \"\";",
		} {
			if !strings.Contains(config, expected) {
				t.Fatalf("mode=%s config missing %q", mode, expected)
			}
		}
	}

	tests := []struct {
		name   string
		mutate func(*AdaptivePolicy)
	}{
		{"unknown version", func(value *AdaptivePolicy) { value.Version = 2 }},
		{"unknown mode", func(value *AdaptivePolicy) { value.Mode = "automatic" }},
		{"minimum samples", func(value *AdaptivePolicy) { value.MinimumSamples = 1 }},
		{"freshness", func(value *AdaptivePolicy) { value.SampleFreshnessMS = 99 }},
		{"half life", func(value *AdaptivePolicy) { value.PeakEWMAHalfLifeMS = 0 }},
		{"exploration", func(value *AdaptivePolicy) { value.ExplorationPercent = 11 }},
		{"slow start initial", func(value *AdaptivePolicy) { value.SlowStart.InitialWeightPercent = 0 }},
		{"slow start ramp", func(value *AdaptivePolicy) { value.SlowStart.RampMS = 0 }},
		{"slow start hard timeout", func(value *AdaptivePolicy) { value.SlowStart.HardTimeoutMS = value.SlowStart.RampMS - 1 }},
		{"outlier samples", func(value *AdaptivePolicy) { value.Outlier.MinimumSamples = value.MinimumSamples - 1 }},
		{"outlier consecutive", func(value *AdaptivePolicy) { value.Outlier.ConsecutiveFailures = 0 }},
		{"outlier ratio", func(value *AdaptivePolicy) { value.Outlier.FailureRatioPercent = 0 }},
		{"ejection cap", func(value *AdaptivePolicy) { value.Outlier.MaxEjectionPercent = 100 }},
		{"ejection bounds", func(value *AdaptivePolicy) { value.Outlier.MaxEjectionMS = value.Outlier.BaseEjectionMS - 1 }},
		{"probe interval", func(value *AdaptivePolicy) { value.Outlier.RecoveryProbeIntervalMS = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			policy.Adaptive = adaptivePolicy(AdaptiveActive)
			test.mutate(policy.Adaptive)
			if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("Normalize() error=%v", err)
			}
		})
	}
}

func TestAdaptiveCanonicalIsStableAndJSONStrict(t *testing.T) {
	policy := testPolicy()
	policy.Adaptive = adaptivePolicy(AdaptiveShadow)
	first, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Canonical(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("adaptive canonical bytes are not stable")
	}
	bad := strings.Replace(string(first), `"mode":"shadow"`, `"mode":"shadow","unknown":true`, 1)
	if _, err := Parse([]byte(bad)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown adaptive field error=%v", err)
	}
}

func TestPolicyRevisionMatchesLuaExactIntegerCeiling(t *testing.T) {
	policy := testPolicy()
	policy.Revision = 1<<53 - 1
	if _, err := Normalize(policy); err != nil {
		t.Fatalf("maximum exact Lua revision rejected: %v", err)
	}
	policy.Revision++
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("inexact Lua revision error=%v", err)
	}
}

func TestParseRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	policy := testPolicy()
	policy.Adaptive = adaptivePolicy(AdaptiveActive)
	canonical, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(canonical)
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{"top-level revision", `"revision":1`, `"revision":1,"revision":2`},
		{"adaptive mode", `"mode":"active"`, `"mode":"active","mode":"shadow"`},
		{"endpoint weight", `"weight":3`, `"weight":3,"weight":100`},
		{"nested threshold", `"consecutive_failures":3`, `"consecutive_failures":3,"consecutive_failures":4`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			duplicate := strings.Replace(raw, test.old, test.new, 1)
			if duplicate == raw {
				t.Fatalf("canonical policy lacks %q", test.old)
			}
			if _, err := Parse([]byte(duplicate)); !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("duplicate key accepted: error=%v", err)
			}
		})
	}
}

func TestAdaptiveRunbookMatchesRuntimeBenchmarkCorpus(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "runbooks", "edge-origin-routing.md"))
	if err != nil {
		t.Fatal(err)
	}
	runbook := string(raw)
	for _, expected := range []string{
		"96 个 baseline 请求、96 个 adaptive 延迟样本和后续 32 个 steady 请求",
		"2000 次 Lua 决策循环",
	} {
		if !strings.Contains(runbook, expected) {
			t.Fatalf("adaptive runbook is missing exact benchmark corpus %q", expected)
		}
	}
	if strings.Contains(runbook, "180 个请求") {
		t.Fatal("adaptive runbook retains the stale 180-request claim")
	}
}

func TestOriginRouteLeaseWritesAreGenerationFenced(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	engine := string(raw)
	for _, required := range []string{
		"local function probe_generation_next(",
		"local function probe_owner_key(key, generation, slot_token)",
		"local function lease_state_value_key(base_key, generation, slot_token)",
		"local function lease_slot_current(",
		"local function lease_commit_key(key, generation)",
		"local function lease_generation_retire(",
		"local function lease_cleanup_history(",
		"local captured = {}",
		"local function lease_committed_generations(",
		"local function lease_state_write(",
		"local function circuit_state_write(",
		"local function adaptive_cooldown_active(",
		"-- CDNCA_TEST_PROBE_AFTER_MUTATION_ACQUIRE_BARRIER",
		"-- CDNCA_TEST_PROBE_BEFORE_OWNER_PUBLICATION_BARRIER",
		"-- CDNCA_TEST_LEASE_STATE_WRITE_BARRIER",
		"-- CDNCA_TEST_LEASE_STATE_AFTER_ADD_BARRIER",
		"-- CDNCA_TEST_LEASE_CLEANUP_CAPTURE_BARRIER",
		"lease_generation_retire(dictionary, key, prior.generation)",
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("origin route lease protocol is missing %q", required)
		}
	}
	for _, unsafe := range []string{
		"local function probe_owner_key(key, generation)\n",
		"local function lease_state_value_key(base_key, generation)\n",
		"dictionary:delete(probe_owner_key(key, prior))",
		"dictionary:delete(lease_state_value_key(base_key, prior))",
		"dictionary:delete(probe_slot_key(key, prior))",
		"dictionary:delete(probe_slot_key(base_key, prior))",
		"local prior_slot = dictionary:get(probe_slot_key(key, prior))\n    if prior_slot then\n      cleanup(prior, prior_slot)",
		"dictionary:set(probe_fence_key(key), generation, ttl)",
		"not adaptive_write_state(dictionary, candidate.pool, candidate.endpoint, state)",
		"dictionary:set(\n    cooldown_key, true, active.adaptive.recovery_probe_interval)",
	} {
		if strings.Contains(engine, unsafe) {
			t.Errorf("origin route lease protocol retains unfenced write %q", unsafe)
		}
	}
}

func TestOriginRouteLeaseGenerationsAreImmutableAndFailClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	engine := string(raw)
	for _, required := range []string{
		"local LEASE_EPOCH_KEY = \"__cdnca_originroute_lease_epoch\"",
		"local LEASE_PROTOCOL_KEY = \"__cdnca_originroute_lease_protocol_v1\"",
		"local LEASE_MAX_GENERATION = 9007199254740990",
		"local function lease_protocol_init(",
		"local function lease_generation_key(key)",
		"local function lease_generation_epoch_key(key)",
		"local function lease_generation_state_key(key)",
		"local function lease_fallback_key(key, generation)",
		"local function lease_metadata_ttl(",
		"local function lease_commit_key(key, generation)",
		"local function lease_generation_retire(",
		"local function lease_fallback_write(",
		"local function lease_fallback_read(",
		"local function lease_committed_generations(",
		"-- CDNCA_TEST_LEASE_AFTER_COMMIT_BARRIER",
	} {
		if !strings.Contains(engine, required) {
			t.Errorf("origin route immutable lease protocol is missing %q", required)
		}
	}
	for _, unsafe := range []string{
		"dictionary:incr(LEASE_ORDER_KEY, 1, 0)",
		"lease_generation_retire(dictionary, key, generation - LEASE_SCAN_LIMIT)",
		"local function lease_generation_keys_exist(",
		"local function lease_slot_delete(",
		"dictionary:delete(key .. \":mutation-lock\")",
		"dictionary:delete(lock_key)",
		"dictionary:expire(probe_fence_key(key), history_ttl)",
	} {
		if strings.Contains(engine, unsafe) {
			t.Errorf("origin route immutable lease protocol retains unsafe operation %q", unsafe)
		}
	}
}

func TestOriginRouteLeaseRound8RuntimeMatrixIsPresent(t *testing.T) {
	raw, err := os.ReadFile("runtime_smoke_test.go")
	if err != nil {
		t.Fatal(err)
	}
	smoke := string(raw)
	for _, required := range []string{
		"func verifyOriginRouteLeaseRound8(",
		"/__originroute_test_round8_precommit?failures=65",
		"/__originroute_test_round8_metadata?revisions=96",
		"{kind: \"half-init\", want: \"recovered\"}",
		"{kind: \"allocation-pressure\", want: \"recovered\"}",
		"{kind: \"fallback-pressure\", want: \"recovered\"}",
		"{kind: \"global-loss\", want: \"rejected\"}",
		"{kind: \"local-restart\", want: \"restarted\"}",
		"originRouteSmokeDistinctWorkerClients(t, port)",
	} {
		if !strings.Contains(smoke, required) {
			t.Errorf("origin route Round-8 runtime matrix is missing %q", required)
		}
	}
}

func TestOriginRouteLeaseRound7RuntimeMatrixIsPresent(t *testing.T) {
	raw, err := os.ReadFile("runtime_smoke_test.go")
	if err != nil {
		t.Fatal(err)
	}
	smoke := string(raw)
	for _, required := range []string{
		"func verifyOriginRouteLeaseRound7(",
		"/__originroute_test_round7_lock_release?token=stale",
		"/__originroute_test_round7_lock_seed?token=successor&ttl=1",
		"{kind: \"probe\", want: []int{64, 64, 64, 0, 64}}",
		"{kind: \"state\", want: []int{0, 64, 0, 64, 64}}",
		"/__originroute_test_round7_late_write?value=round7-older",
		"/__originroute_test_round7_late_write?value=round7-newer",
		"\"counter-missing\", \"overflow\", \"restart-mismatch\", \"order-missing\"",
	} {
		if !strings.Contains(smoke, required) {
			t.Errorf("origin route Round-7 runtime matrix is missing %q", required)
		}
	}
}
