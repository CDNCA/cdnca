package originroute

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type adaptiveOriginRouteEvidence struct {
	ShadowEquivalent       bool `json:"shadow_equivalent"`
	ColdFallback           bool `json:"cold_fallback"`
	P2CPreferredFast       bool `json:"p2c_preferred_fast"`
	SlowStart              bool `json:"slow_start"`
	OutlierEjected         bool `json:"outlier_ejected"`
	EjectionCap            bool `json:"ejection_cap"`
	RecoveryProbe          bool `json:"recovery_probe"`
	SingleCandidate        bool `json:"single_candidate"`
	StaleFallback          bool `json:"stale_fallback"`
	StateLossFallback      bool `json:"state_loss_fallback"`
	RevisionIsolation      bool `json:"revision_isolation"`
	GETRetry               bool `json:"get_retry"`
	HEADRetry              bool `json:"head_retry"`
	POSTNotReplayed        bool `json:"post_not_replayed"`
	ReasonAndDiagnosticCap bool `json:"reason_and_diagnostic_cap"`
	ClockRollbackFallback  bool `json:"clock_rollback_fallback"`
	StateBounded           bool `json:"state_bounded"`
	StateFailureBaseline   bool `json:"state_failure_baseline"`
	StateFailureRetries    bool `json:"state_failure_retries"`
	NoPartialInflight      bool `json:"no_partial_inflight"`
	StrictEjectionFloor    bool `json:"strict_ejection_floor"`
	ProbeSingleInflight    bool `json:"probe_single_inflight"`
	ProbeFencedOwner       bool `json:"probe_fenced_owner"`
	ProbeOwnerSuccess      bool `json:"probe_owner_success"`
	ProbeOwnerFailure      bool `json:"probe_owner_failure"`
	ProbeOwnerAbort        bool `json:"probe_owner_abort"`
	ProbeLeaseExpiry       bool `json:"probe_lease_expiry"`
	NoStarvation           bool `json:"no_starvation"`
	AllAbnormalBounded     bool `json:"all_abnormal_bounded"`
	WeightCapacityBounded  bool `json:"weight_capacity_bounded"`
	AttemptScopedProbe     bool `json:"attempt_scoped_probe"`
	FallbackDiagnostic     bool `json:"fallback_diagnostic"`
	MalformedStateFallback bool `json:"malformed_state_fallback"`
	AtomicEjectionFloor    bool `json:"atomic_ejection_floor"`
	FailureEWMAPreference  bool `json:"failure_ewma_preference"`
	ComparatorMatrix       bool `json:"comparator_matrix"`
	EjectionLockRecovery   bool `json:"ejection_lock_recovery"`
}

type adaptiveOriginRouteBenchmark struct {
	Requests                 int            `json:"requests"`
	BaselineP50MS            float64        `json:"baseline_p50_ms"`
	BaselineP95MS            float64        `json:"baseline_p95_ms"`
	BaselineP99MS            float64        `json:"baseline_p99_ms"`
	AdaptiveP50MS            float64        `json:"adaptive_p50_ms"`
	AdaptiveP95MS            float64        `json:"adaptive_p95_ms"`
	AdaptiveP99MS            float64        `json:"adaptive_p99_ms"`
	Selection                map[string]int `json:"selection"`
	RetryAmplification       float64        `json:"retry_amplification"`
	StateKeys                int            `json:"state_keys"`
	StateFreeBytes           int            `json:"state_free_bytes"`
	BaselineDecisionMSMedian float64        `json:"baseline_decision_ms_median"`
	AdaptiveDecisionMSMedian float64        `json:"adaptive_decision_ms_median"`
	BaselineHeapKBMedian     float64        `json:"baseline_heap_kb_median"`
	AdaptiveHeapKBMedian     float64        `json:"adaptive_heap_kb_median"`
}

type adaptiveLuaBenchmarkSample struct {
	Iterations        int     `json:"iterations"`
	BaselineElapsedMS float64 `json:"baseline_elapsed_ms"`
	AdaptiveElapsedMS float64 `json:"adaptive_elapsed_ms"`
	BaselineHeapKB    float64 `json:"baseline_heap_kb"`
	AdaptiveHeapKB    float64 `json:"adaptive_heap_kb"`
}

const adaptiveLuaBenchmarkIterations = 2000

func TestAdaptiveRuntimeRequestOutcomeReasonHasPriority(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "edge", "openresty", "originroute", "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	engine := string(raw)
	if !strings.Contains(engine,
		`local reason = context.adaptive_reason or candidate.adaptive_reason or "telemetry_stale_fallback"`) {
		t.Fatal("adaptive retry can overwrite the request outcome reason with a stale candidate reason")
	}
}

func verifyAdaptiveOriginRouteSmoke(t *testing.T, binary, luaRoot string) bool {
	t.Helper()
	fast := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "ADAPTIVE-FAST", 0)
	medium := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "ADAPTIVE-MEDIUM", 12*time.Millisecond)
	slow := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "ADAPTIVE-SLOW", 45*time.Millisecond)
	postOnly := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "ADAPTIVE-POST-ONLY", 0)
	port := reserveOriginRouteSmokePort(t)
	root := privateOriginRouteSmokeDir(t)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		content, _ := os.ReadFile(filepath.Join(root, "shared", "originroute-error.log"))
		if len(content) > 16384 {
			content = content[len(content)-16384:]
		}
		t.Logf("adaptive OpenResty error log:\n%s", content)
	})
	for _, path := range []string{
		"versions", "staging", "shared", "shared/client-body-temp", "shared/proxy-temp",
		"shared/fastcgi-temp", "shared/uwsgi-temp", "shared/scgi-temp",
	} {
		if err := ensurePrivateDirectory(filepath.Join(root, path)); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := NewOpenRestyRuntime(binary, root, originRouteHealthProbe(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Stop(ctx)
	})

	policy := adaptiveOriginRoutePolicy(t, port, fast, medium, slow, postOnly)
	baselineBodies := make(map[string]string)
	baselineSeeds := make([]string, 0, 512)
	baselineDurations := make([]time.Duration, 0, 512)
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	for index := 0; index < 512; index++ {
		seed := fmt.Sprintf("fixed-%03d", index)
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", seed, nil)
		baselineBodies[seed] = response.body
		baselineSeeds = append(baselineSeeds, seed)
		baselineDurations = append(baselineDurations, response.elapsed)
	}
	baselineOrigins := make(map[string]bool, 3)
	for _, body := range baselineBodies {
		baselineOrigins[body] = true
	}
	if !baselineOrigins[fast.id] || !baselineOrigins[medium.id] || !baselineOrigins[slow.id] {
		t.Fatalf("baseline corpus did not cover all weighted endpoints: %v", baselineOrigins)
	}
	stateFailureBaseline := adaptiveOriginRouteRequest(
		t, port, http.MethodGet, "/state-failure", "state-failure", nil)
	if !baselineOrigins[stateFailureBaseline.body] {
		t.Fatalf("state failure baseline selected unknown endpoint %q", stateFailureBaseline.body)
	}

	policy.Revision++
	policy.VersionID = "adaptive-shadow"
	policy.Adaptive = adaptivePolicy(AdaptiveShadow)
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	evidence := adaptiveOriginRouteEvidence{ShadowEquivalent: true}
	for _, seed := range baselineSeeds[:24] {
		expected := baselineBodies[seed]
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", seed, nil)
		if response.body != expected || response.headers.Get("X-CDNCA-Origin-Reason") != "baseline_weighted_selected" {
			evidence.ShadowEquivalent = false
			break
		}
	}

	policy.Revision++
	policy.VersionID = "adaptive-active"
	policy.Adaptive = adaptivePolicy(AdaptiveActive)
	policy.Adaptive.MinimumSamples = 2
	policy.Adaptive.SampleFreshnessMS = 5000
	policy.Adaptive.PeakEWMAHalfLifeMS = 100
	policy.Adaptive.ExplorationPercent = 10
	policy.Adaptive.SlowStart.RampMS = 1000
	policy.Adaptive.SlowStart.HardTimeoutMS = 2000
	policy.Adaptive.Outlier.MinimumSamples = 4
	policy.Adaptive.Outlier.BaseEjectionMS = 150
	policy.Adaptive.Outlier.MaxEjectionMS = 600
	policy.Adaptive.Outlier.RecoveryProbeIntervalMS = 100
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	for index := 0; index < 5 && !evidence.ColdFallback; index++ {
		cold := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("cold-%d", index), nil)
		evidence.ColdFallback = cold.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"
	}

	reasons := make(map[string]bool)
	resetAdaptiveCandidatePackedStates(t, port, policy, "multi")
	warming := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "warming-fixture", nil)
	reasons[warming.headers.Get("X-CDNCA-Origin-Reason")] = true
	explorationSeed := ""
	for index := 0; index < 4096 && explorationSeed == ""; index++ {
		resetAdaptiveCandidatePackedStates(t, port, policy, "multi")
		seed := fmt.Sprintf("no-starvation-%d", index)
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", seed, nil)
		if response.body == slow.id &&
			strings.Contains(response.headers.Get("X-CDNCA-Origin-Diagnostic"), "explore=1") {
			explorationSeed = seed
		}
	}
	if explorationSeed == "" {
		t.Fatal("deterministic exploration never reached the slow endpoint")
	}
	resetAdaptiveCandidatePackedStates(t, port, policy, "multi")
	adaptiveDurations := make([]time.Duration, 0, 96)
	beforeFast, beforeMedium, beforeSlow := fast.requests.Load(), medium.requests.Load(), slow.requests.Load()
	exploredSlow := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", explorationSeed, nil)
	if exploredSlow.body != slow.id ||
		!strings.Contains(exploredSlow.headers.Get("X-CDNCA-Origin-Diagnostic"), "explore=1") {
		t.Fatalf("deterministic exploration did not reach slow endpoint: body=%q diagnostic=%q",
			exploredSlow.body, exploredSlow.headers.Get("X-CDNCA-Origin-Diagnostic"))
	}
	for index := 0; index < 96; index++ {
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("warm-%03d", index), nil)
		adaptiveDurations = append(adaptiveDurations, response.elapsed)
		reasons[response.headers.Get("X-CDNCA-Origin-Reason")] = true
		if len(response.headers.Get("X-CDNCA-Origin-Diagnostic")) > 160 {
			t.Fatalf("adaptive diagnostic exceeded cap: %q", response.headers.Get("X-CDNCA-Origin-Diagnostic"))
		}
	}
	time.Sleep(1050 * time.Millisecond)
	for index := 0; index < 32; index++ {
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("steady-%03d", index), nil)
		reasons[response.headers.Get("X-CDNCA-Origin-Reason")] = true
	}
	fastCount := fast.requests.Load() - beforeFast
	mediumCount := medium.requests.Load() - beforeMedium
	slowCount := slow.requests.Load() - beforeSlow
	evidence.P2CPreferredFast = reasons["p2c_ewma_selected"] && fastCount > mediumCount && fastCount > slowCount
	if !evidence.P2CPreferredFast {
		t.Logf("adaptive selection counts fast=%d medium=%d slow=%d reasons=%v",
			fastCount, mediumCount, slowCount, reasons)
	}
	evidence.SlowStart = reasons["slow_start_active"]
	evidence.NoStarvation = fastCount > 0 && mediumCount > 0 && slowCount > 0
	evidence.ReasonAndDiagnosticCap = true
	resetAdaptiveCandidatePackedStates(t, port, policy, "pressure")
	fastBeforePressure, mediumBeforePressure, slowBeforePressure :=
		fast.requests.Load(), medium.requests.Load(), slow.requests.Load()
	pressure := originRouteSmokeRequestWithHeaders(t, port, http.MethodGet, "/state-failure", nil, map[string]string{
		"X-CDNCA-Test-Seed": "state-failure", "X-CDNCA-Test-Fill-Adaptive": "1",
	})
	fastDelta := fast.requests.Load() - fastBeforePressure
	mediumDelta := medium.requests.Load() - mediumBeforePressure
	slowDelta := slow.requests.Load() - slowBeforePressure
	exactBaselineAttempt :=
		(stateFailureBaseline.body == fast.id && fastDelta == 1 && mediumDelta == 0 && slowDelta == 0) ||
			(stateFailureBaseline.body == medium.id && fastDelta == 0 && mediumDelta == 1 && slowDelta == 0) ||
			(stateFailureBaseline.body == slow.id && fastDelta == 0 && mediumDelta == 0 && slowDelta == 1)
	evidence.StateFailureBaseline = pressure.body == stateFailureBaseline.body && exactBaselineAttempt &&
		pressure.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback" &&
		fastDelta+mediumDelta+slowDelta == 1
	if !evidence.StateFailureBaseline {
		stateKeys, freeBytes := adaptiveOriginRouteStateStats(t, port)
		t.Logf("adaptive state failure baseline status=%d body=%q reason=%q expected_body=%q deltas=%d/%d/%d keys=%d free=%d",
			pressure.status, pressure.body, pressure.headers.Get("X-CDNCA-Origin-Reason"),
			stateFailureBaseline.body, fastDelta, mediumDelta, slowDelta, stateKeys, freeBytes)
	}
	time.Sleep(300 * time.Millisecond)
	resetCooldown := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_cooldown_reset", nil)
	if resetCooldown.status != http.StatusOK || resetCooldown.body != "ok" {
		t.Fatalf("reset adaptive pressure cooldown status=%d body=%q", resetCooldown.status, resetCooldown.body)
	}
	evidence.NoPartialInflight = adaptiveOriginRouteInflightTotal(t, port) == 0

	baselineFastSeed := ""
	for seed, baseline := range baselineBodies {
		if baseline == fast.id {
			baselineFastSeed = seed
			break
		}
	}
	fast.fail.Store(true)
	medium.fail.Store(true)
	fastBeforePressure, mediumBeforePressure, slowBeforePressure =
		fast.requests.Load(), medium.requests.Load(), slow.requests.Load()
	pressureRetry := originRouteSmokeRequestWithHeaders(t, port, http.MethodGet, "/multi", nil, map[string]string{
		"X-CDNCA-Test-Seed": baselineFastSeed, "X-CDNCA-Test-Fill-Adaptive": "1",
	})
	evidence.StateFailureRetries = pressureRetry.body == slow.id &&
		pressureRetry.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback" &&
		fast.requests.Load() == fastBeforePressure+1 && medium.requests.Load() == mediumBeforePressure+1 &&
		slow.requests.Load() == slowBeforePressure+1
	fast.fail.Store(false)
	medium.fail.Store(false)
	time.Sleep(300 * time.Millisecond)
	resetCooldown = originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_cooldown_reset", nil)
	if resetCooldown.status != http.StatusOK || resetCooldown.body != "ok" {
		t.Fatalf("reset adaptive retry pressure cooldown status=%d body=%q", resetCooldown.status, resetCooldown.body)
	}
	evidence.NoPartialInflight = evidence.NoPartialInflight && adaptiveOriginRouteInflightTotal(t, port) == 0

	benchmark := adaptiveOriginRouteBenchmark{
		Requests:      len(baselineDurations),
		BaselineP50MS: durationPercentileMS(baselineDurations, 0.50),
		BaselineP95MS: durationPercentileMS(baselineDurations, 0.95),
		BaselineP99MS: durationPercentileMS(baselineDurations, 0.99),
		AdaptiveP50MS: durationPercentileMS(adaptiveDurations, 0.50),
		AdaptiveP95MS: durationPercentileMS(adaptiveDurations, 0.95),
		AdaptiveP99MS: durationPercentileMS(adaptiveDurations, 0.99),
		Selection:     map[string]int{fast.id: int(fastCount), medium.id: int(mediumCount), slow.id: int(slowCount)},
	}
	benchmark.StateKeys, benchmark.StateFreeBytes = adaptiveOriginRouteStateStats(t, port)
	evidence.StateBounded = benchmark.StateKeys <= 128 && benchmark.StateFreeBytes >= 16384
	benchmark.BaselineDecisionMSMedian, benchmark.AdaptiveDecisionMSMedian,
		benchmark.BaselineHeapKBMedian, benchmark.AdaptiveHeapKBMedian = adaptiveOriginRouteLuaBenchmark(t, port)

	slow.fail.Store(true)
	for index := 0; index < 240 && !reasons["endpoint_ejected"]; index++ {
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("eject-%03d", index), nil)
		reasons[response.headers.Get("X-CDNCA-Origin-Reason")] = true
	}
	evidence.OutlierEjected = reasons["endpoint_ejected"]

	medium.fail.Store(true)
	for index := 0; index < 240 && !reasons["ejection_cap_reached"]; index++ {
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("cap-%03d", index), nil)
		reasons[response.headers.Get("X-CDNCA-Origin-Reason")] = true
	}
	evidence.EjectionCap = reasons["ejection_cap_reached"] && fast.requests.Load() > beforeFast

	policy.Revision++
	policy.VersionID = "adaptive-strict-cap"
	policy.Adaptive.MinimumSamples = 2
	policy.Adaptive.ExplorationPercent = 10
	policy.Adaptive.SlowStart.RampMS = 100
	policy.Adaptive.SlowStart.HardTimeoutMS = 100
	policy.Adaptive.Outlier.MinimumSamples = 2
	policy.Adaptive.Outlier.ConsecutiveFailures = 1
	policy.Adaptive.Outlier.FailureRatioPercent = 1
	policy.Adaptive.Outlier.MaxEjectionPercent = 1
	policy.Adaptive.Outlier.RecoveryProbeIntervalMS = 30000
	medium.fail.Store(false)
	slow.fail.Store(false)
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	resetAdaptiveWorkerCooldown(t, port, policy.VersionID)
	strictSeeds := make(map[string]string)
	for seed, body := range baselineBodies {
		if strictSeeds[body] == "" {
			strictSeeds[body] = seed
		}
	}
	for _, origin := range []string{slow.id, medium.id, fast.id} {
		for sample := 0; sample < int(policy.Adaptive.MinimumSamples); sample++ {
			_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", strictSeeds[origin], nil)
		}
	}
	time.Sleep(110 * time.Millisecond)
	strictSlowSeed := ""
	for index := 0; index < 4096 && strictSlowSeed == ""; index++ {
		resetAdaptiveCandidatePackedStates(t, port, policy, "multi")
		seed := fmt.Sprintf("strict-cap-%03d", index)
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", seed, nil)
		if response.body == slow.id && strings.Contains(
			response.headers.Get("X-CDNCA-Origin-Diagnostic"), "explore=1",
		) {
			strictSlowSeed = seed
		}
	}
	if strictSlowSeed == "" {
		t.Fatal("strict cap deterministic exploration never selected the slow endpoint")
	}
	resetAdaptiveCandidatePackedStates(t, port, policy, "multi")
	slow.fail.Store(true)
	var strictCapacityResponse originRouteSmokeResponse
	var ejectedAt float64
	var ejectionCount int
	var capReached bool
	for sample := 0; sample < int(policy.Adaptive.Outlier.MinimumSamples)+3; sample++ {
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", strictSlowSeed, nil)
		ejectedAt, ejectionCount, capReached = adaptiveOriginRouteEjectionState(t, port)
		if capReached {
			strictCapacityResponse = response
			_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", strictSeeds[fast.id], nil)
			break
		}
	}
	ejectedAt, ejectionCount, capReached = adaptiveOriginRouteEjectionState(t, port)
	evidence.StrictEjectionFloor = strictCapacityResponse.headers.Get("X-CDNCA-Origin-Reason") == "ejection_cap_reached" &&
		ejectedAt == 0 && ejectionCount == 0 && capReached
	medium.fail.Store(true)
	slow.fail.Store(true)
	fastBeforeAbnormal, mediumBeforeAbnormal, slowBeforeAbnormal :=
		fast.requests.Load(), medium.requests.Load(), slow.requests.Load()
	fast.fail.Store(true)
	const abnormalRequests = 24
	for index := 0; index < abnormalRequests; index++ {
		_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", fmt.Sprintf("all-bad-%03d", index), nil)
	}
	abnormalAttempts := (fast.requests.Load() - fastBeforeAbnormal) +
		(medium.requests.Load() - mediumBeforeAbnormal) + (slow.requests.Load() - slowBeforeAbnormal)
	touched := 0
	for _, count := range []int64{
		fast.requests.Load() - fastBeforeAbnormal,
		medium.requests.Load() - mediumBeforeAbnormal,
		slow.requests.Load() - slowBeforeAbnormal,
	} {
		if count > 0 {
			touched++
		}
	}
	evidence.AllAbnormalBounded = abnormalAttempts <= abnormalRequests*int64(policy.Retry.MaxAttempts) && touched >= 2
	benchmark.RetryAmplification = float64(abnormalAttempts) / abnormalRequests
	fast.fail.Store(false)
	medium.fail.Store(false)
	slow.fail.Store(false)

	policy.Revision++
	policy.VersionID = "adaptive-recovery"
	policy.Adaptive.MinimumSamples = 2
	policy.Adaptive.ExplorationPercent = 10
	policy.Adaptive.Outlier.MaxEjectionPercent = 50
	policy.Adaptive.Outlier.BaseEjectionMS = 100
	policy.Adaptive.Outlier.MaxEjectionMS = 100
	policy.Adaptive.Outlier.RecoveryProbeIntervalMS = 100
	policy.Retry.ReadTimeoutMS = 300
	policy.Retry.TotalBudgetMS = 400
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	seedAdaptiveRepairPool(t, port, policy, "multi", policy.Pools[0].Endpoints, 0.005, 20)
	setAdaptivePackedState(t, port, policy, "multi", "adaptive-slow",
		adaptivePackedState(20, 0.045, 1, 0, 3, -0.01, 1))
	slowProbeSeed := "recovery-slow"
	slow.fail.Store(false)
	slow.setDelay(200 * time.Millisecond)
	slowBeforeRecovery := slow.requests.Load()
	type asynchronousResult struct {
		response originRouteSmokeResponse
		err      error
	}
	firstProbe := make(chan asynchronousResult, 1)
	go func() {
		response, err := doOriginRouteSmokeRequest(context.Background(), port, http.MethodGet, "/multi", nil,
			map[string]string{"X-CDNCA-Test-Seed": slowProbeSeed})
		firstProbe <- asynchronousResult{response: response, err: err}
	}()
	waitOriginRouteRequestCount(t, slow, slowBeforeRecovery+1)
	time.Sleep(80 * time.Millisecond)
	if replacement := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe_replace", nil); replacement.status != http.StatusOK {
		t.Fatalf("replace recovery probe status=%d body=%q", replacement.status, replacement.body)
	}
	secondProbe := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "recovery-second", nil)
	firstResult := <-firstProbe
	if firstResult.err != nil {
		t.Fatal(firstResult.err)
	}
	evidence.ProbeSingleInflight = slow.requests.Load() == slowBeforeRecovery+1 && secondProbe.body != slow.id
	evidence.ProbeOwnerSuccess = firstResult.response.body == slow.id
	evidence.ProbeFencedOwner = adaptiveOriginRouteProbeValue(t, port) == "replacement-owner"
	_ = originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe_clear", nil)
	resetCooldown = originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_cooldown_reset", nil)
	if resetCooldown.status != http.StatusOK || resetCooldown.body != "ok" {
		t.Fatalf("reset adaptive test cooldown status=%d body=%q", resetCooldown.status, resetCooldown.body)
	}
	evidence.RecoveryProbe = evidence.ProbeSingleInflight && evidence.ProbeOwnerSuccess

	slow.setDelay(0)
	slow.fail.Store(true)
	setAdaptivePackedState(t, port, policy, "multi", "adaptive-slow",
		adaptivePackedState(20, 0.045, 1, 0, 3, -0.01, 1))
	slow.setDelay(200 * time.Millisecond)
	slowBeforeFailureProbe := slow.requests.Load()
	failureProbe := make(chan asynchronousResult, 1)
	go func() {
		response, err := doOriginRouteSmokeRequest(context.Background(), port, http.MethodGet, "/multi", nil,
			map[string]string{"X-CDNCA-Test-Seed": slowProbeSeed})
		failureProbe <- asynchronousResult{response: response, err: err}
	}()
	waitOriginRouteRequestCount(t, slow, slowBeforeFailureProbe+1)
	time.Sleep(80 * time.Millisecond)
	failureSecond := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "failure-second", nil)
	failureResult := <-failureProbe
	if failureResult.err != nil {
		t.Fatal(failureResult.err)
	}
	evidence.ProbeOwnerFailure = slow.requests.Load() == slowBeforeFailureProbe+1 &&
		failureSecond.body != slow.id && failureResult.response.body != slow.id && adaptiveOriginRouteProbeValue(t, port) == ""
	_ = originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe_clear", nil)

	slow.fail.Store(false)
	setAdaptivePackedState(t, port, policy, "multi", "adaptive-slow",
		adaptivePackedState(20, 0.045, 1, 0, 3, -0.01, 1))
	slowBeforeAbort := slow.requests.Load()
	abortContext, abort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, abortErr := doOriginRouteSmokeRequest(abortContext, port, http.MethodGet, "/multi", nil,
		map[string]string{"X-CDNCA-Test-Seed": slowProbeSeed})
	abort()
	waitOriginRouteRequestCount(t, slow, slowBeforeAbort+1)
	time.Sleep(120 * time.Millisecond)
	evidence.ProbeOwnerAbort = abortErr != nil && adaptiveOriginRouteProbeValue(t, port) == ""

	slow.setDelay(0)
	probeReset := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe_reset", nil)
	if probeReset.status != http.StatusOK || probeReset.body != "ok" {
		t.Fatalf("reset adaptive crash probe state status=%d body=%q", probeReset.status, probeReset.body)
	}
	crashLease := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe_crash", nil)
	if crashLease.status != http.StatusOK {
		t.Fatalf("inject crashed recovery probe status=%d body=%q", crashLease.status, crashLease.body)
	}
	slowBeforeCrashLease := slow.requests.Load()
	leaseBlocked := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", slowProbeSeed, nil)
	time.Sleep(time.Duration(policy.Retry.TotalBudgetMS) * time.Millisecond)
	leaseBudgetBlocked := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "crash-lease-budget", nil)
	leaseExpiryDeadline := time.Now().Add(2 * time.Second)
	for adaptiveOriginRouteProbeValue(t, port) != "" && time.Now().Before(leaseExpiryDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if owner := adaptiveOriginRouteProbeValue(t, port); owner != "" {
		t.Fatalf("crashed recovery probe lease did not expire: owner=%q", owner)
	}
	leaseRecovered := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "crash-lease-recovered", nil)
	evidence.ProbeLeaseExpiry = leaseBlocked.body != slow.id && leaseBudgetBlocked.body != slow.id &&
		slow.requests.Load() == slowBeforeCrashLease+1 && leaseRecovered.body == slow.id
	policy.Revision++
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	revisionCold := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "revision-isolation", nil)
	evidence.RevisionIsolation = revisionCold.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"

	single := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/single", "single", nil)
	evidence.SingleCandidate = single.headers.Get("X-CDNCA-Origin-Reason") == "single_candidate_fallback"
	mutated := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_future", nil)
	rollback := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "clock-rollback", nil)
	evidence.ClockRollbackFallback = mutated.status == http.StatusOK && mutated.body != "0" &&
		rollback.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"

	policy.Revision++
	policy.VersionID = "adaptive-stale"
	policy.Adaptive.SampleFreshnessMS = 200
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	seedsByOrigin := make(map[string][]string)
	for seed, body := range baselineBodies {
		if len(seedsByOrigin[body]) < 3 {
			seedsByOrigin[body] = append(seedsByOrigin[body], seed)
		}
	}
	for _, origin := range []string{fast.id, medium.id, slow.id} {
		if len(seedsByOrigin[origin]) < 2 {
			t.Fatalf("fixed seed corpus has insufficient samples for %s", origin)
		}
		for _, seed := range seedsByOrigin[origin][:2] {
			_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", seed, nil)
		}
	}
	time.Sleep(250 * time.Millisecond)
	stale := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "stale", nil)
	evidence.StaleFallback = stale.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"

	policy.Revision++
	policy.VersionID = "adaptive-state-lost"
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	lost := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", "state-lost", nil)
	evidence.StateLossFallback = lost.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"

	badSeed := ""
	for seed, body := range baselineBodies {
		if body == slow.id {
			badSeed = seed
			break
		}
	}
	if badSeed == "" {
		t.Fatal("fixed baseline seed set never selected the slow endpoint")
	}
	policy.Revision++
	policy.VersionID = "adaptive-retry"
	policy.Adaptive.Outlier.MinimumSamples = 100
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	slow.fail.Store(true)
	get := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/multi", badSeed, nil)
	head := adaptiveOriginRouteRequest(t, port, http.MethodHead, "/multi", badSeed, nil)
	postOnly.fail.Store(true)
	postOnlyBefore := postOnly.requests.Load()
	fastBeforePost, mediumBeforePost, slowBeforePost :=
		fast.requests.Load(), medium.requests.Load(), slow.requests.Load()
	post := adaptiveOriginRouteRequest(t, port, http.MethodPost, "/post-only", "post-only", strings.NewReader("body"))
	evidence.GETRetry = get.status == http.StatusOK && get.body != slow.id
	evidence.HEADRetry = head.status == http.StatusOK && head.headers.Get("X-Origin") != slow.id
	evidence.POSTNotReplayed = post.status >= http.StatusInternalServerError && post.status < 600 &&
		postOnly.requests.Load() == postOnlyBefore+1 && fast.requests.Load() == fastBeforePost &&
		medium.requests.Load() == mediumBeforePost && slow.requests.Load() == slowBeforePost
	postOnly.fail.Store(false)
	slow.fail.Store(false)
	evidence.WeightCapacityBounded, evidence.AttemptScopedProbe, evidence.FallbackDiagnostic,
		evidence.MalformedStateFallback, evidence.AtomicEjectionFloor, evidence.FailureEWMAPreference,
		evidence.ComparatorMatrix, evidence.EjectionLockRecovery =
		verifyAdaptiveOriginRouteRepairRegressions(t, runtime, root, luaRoot, port, fast, medium)

	encoded := mustJSON(t, evidence)
	t.Logf("ADAPTIVE_ORIGIN_ROUTE_BENCHMARK=%s", mustJSON(t, benchmark))
	for name, passed := range map[string]bool{
		"shadow": evidence.ShadowEquivalent, "cold": evidence.ColdFallback,
		"p2c": evidence.P2CPreferredFast, "slow-start": evidence.SlowStart,
		"ejection": evidence.OutlierEjected, "ejection cap": evidence.EjectionCap,
		"strict ejection floor": evidence.StrictEjectionFloor,
		"probe single inflight": evidence.ProbeSingleInflight, "probe fenced owner": evidence.ProbeFencedOwner,
		"probe owner success": evidence.ProbeOwnerSuccess, "probe owner failure": evidence.ProbeOwnerFailure,
		"probe owner abort": evidence.ProbeOwnerAbort, "probe lease expiry": evidence.ProbeLeaseExpiry,
		"recovery": evidence.RecoveryProbe, "single": evidence.SingleCandidate,
		"stale": evidence.StaleFallback, "state loss": evidence.StateLossFallback,
		"revision isolation": evidence.RevisionIsolation,
		"GET":                evidence.GETRetry, "HEAD": evidence.HEADRetry, "POST": evidence.POSTNotReplayed,
		"diagnostic":     evidence.ReasonAndDiagnosticCap,
		"clock rollback": evidence.ClockRollbackFallback, "state cap": evidence.StateBounded,
		"state failure baseline": evidence.StateFailureBaseline,
		"state failure retries":  evidence.StateFailureRetries, "inflight rollback": evidence.NoPartialInflight,
		"starvation": evidence.NoStarvation, "all abnormal": evidence.AllAbnormalBounded,
		"weight capacity": evidence.WeightCapacityBounded, "attempt-scoped probe": evidence.AttemptScopedProbe,
		"fallback diagnostic": evidence.FallbackDiagnostic, "malformed state": evidence.MalformedStateFallback,
		"atomic ejection floor": evidence.AtomicEjectionFloor, "failure EWMA": evidence.FailureEWMAPreference,
		"comparator matrix": evidence.ComparatorMatrix, "ejection lock recovery": evidence.EjectionLockRecovery,
	} {
		if !passed {
			t.Fatalf("adaptive %s smoke failed: %s", name, encoded)
		}
	}
	t.Logf("ADAPTIVE_ORIGIN_ROUTE_SMOKE_EVIDENCE=%s", encoded)
	return true
}

func verifyAdaptiveOriginRouteRepairRegressions(
	t *testing.T,
	runtime *OpenRestyRuntime,
	root, luaRoot string,
	port uint16,
	fast, medium *originRouteSmokeOrigin,
) (bool, bool, bool, bool, bool, bool, bool, bool) {
	t.Helper()
	fastEndpoint := fast.endpoint(t, "repair-fast", PoolOrigin, "")
	mediumEndpoint := medium.endpoint(t, "repair-medium", PoolOrigin, "")
	fastEndpoint.Weight, mediumEndpoint.Weight = 1, 100
	policy := adaptiveRepairPolicy(port, "repair-weight", 100,
		[]Pool{{ID: "repair-direct", Kind: PoolOrigin, Endpoints: []Endpoint{fastEndpoint, mediumEndpoint}}},
		"repair-direct", "")
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
		adaptivePackedState(20, 0.001, 0, 0, 2, 0, 0))
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
	fastBefore, mediumBefore := fast.requests.Load(), medium.requests.Load()
	for index := 0; index < 40; index++ {
		_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", fmt.Sprintf("capacity-%03d", index), nil)
	}
	fastSelected := fast.requests.Load() - fastBefore
	mediumSelected := medium.requests.Load() - mediumBefore
	weightCapacityBounded := fastSelected <= 6 && mediumSelected >= 34
	if !weightCapacityBounded {
		t.Logf("1:100 adaptive selection overloaded weight-1 endpoint: fast=%d medium=%d", fastSelected, mediumSelected)
	}

	malformed := []string{
		"",
		adaptivePackedRaw("1.5", "0.001", "0.001", "0", "0", "0"),
		adaptivePackedRaw("20", "0.001", "0.001", "0", "1.5", "0"),
		adaptivePackedRaw("20", "0.001", "0.001", "0", "0", "1.5"),
		adaptivePackedRaw("20", "0.001", "0.001", "1.5", "0", "0"),
		adaptivePackedRaw("20", "nan", "0.001", "0", "0", "0"),
		adaptivePackedRaw("20", "inf", "0.001", "0", "0", "0"),
	}
	validPacked := adaptivePackedRaw("20", "0.001", "0.001", "0", "0", "0")
	malformed = append(malformed,
		","+validPacked,
		validPacked+",",
		strings.Replace(validPacked, ",", ",,", 1),
	)
	malformedStateFallback := true
	for index, raw := range malformed {
		response := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__adaptive_test_state_decode?value="+url.QueryEscape(raw), nil)
		if response.status != http.StatusOK || response.body != "rejected" {
			malformedStateFallback = false
			t.Logf("malformed adaptive state %d decode=%d/%q", index, response.status, response.body)
		}
	}
	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID, malformed[1])
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
	malformedRequest := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "malformed-request", nil)
	malformedStateFallback = malformedStateFallback &&
		malformedRequest.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback"

	l2A := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "REPAIR-L2-A", 0)
	l2B := newOriginRouteSmokeOrigin(t, "tcp4", "127.0.0.1:0", "REPAIR-L2-B", 0)
	l2EndpointA := l2A.endpoint(t, "repair-l2-a", PoolL2, "repair-node-a")
	l2EndpointB := l2B.endpoint(t, "repair-l2-b", PoolL2, "repair-node-b")
	l2EndpointA.Weight, l2EndpointB.Weight = 1, 1
	fastEndpoint.Weight, mediumEndpoint.Weight = 1, 1
	policy = adaptiveRepairPolicy(port, "repair-probe", 200, []Pool{
		{ID: "repair-l2", Kind: PoolL2, Endpoints: []Endpoint{l2EndpointA, l2EndpointB}},
		{ID: "repair-direct", Kind: PoolOrigin, Endpoints: []Endpoint{fastEndpoint, mediumEndpoint}},
	}, "repair-l2", "repair-direct")
	policy.Retry.MaxAttempts = 4
	policy.L2.ProbeIntervalMS = 5000
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	resetAdaptiveWorkerCooldown(t, port, policy.VersionID)
	seedAdaptiveRepairPool(t, port, policy, "repair-l2", []Endpoint{l2EndpointA, l2EndpointB}, 0.005, 2)
	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
		adaptivePackedState(20, 0.001, 0, 0, 2, -0.01, 1))
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
	_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "healthy-l2", nil)
	resetAdaptiveWorkerCooldown(t, port, policy.VersionID)
	probeKey := adaptiveRepairKey(policy, "repair-direct", fastEndpoint.ID, "probe")
	probeUnclaimed := adaptiveLeaseValue(t, port, probeKey) == ""
	l2A.fail.Store(true)
	l2B.fail.Store(true)
	opened := originRouteSmokeRequest(t, port, http.MethodPost, "/__adaptive_test_circuit_open", nil)
	if opened.status != http.StatusOK || opened.body != "ok" {
		t.Fatalf("open adaptive repair L2 circuit status=%d body=%q", opened.status, opened.body)
	}
	time.Sleep(20 * time.Millisecond)
	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
		adaptivePackedState(20, 0.001, 0, 0, 2, -0.01, 1))
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
	l2BeforeFailover := l2A.requests.Load() + l2B.requests.Load()
	failover := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "actual-failover", nil)
	waitOriginRouteRequestCountStable(t, l2A, time.Second)
	waitOriginRouteRequestCountStable(t, l2B, time.Second)
	circuitOpen := l2A.requests.Load()+l2B.requests.Load() == l2BeforeFailover
	probeReleased := false
	if failover.body == fast.id {
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if adaptiveLeaseValue(t, port, probeKey) == "" {
				probeReleased = true
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	attemptScopedProbe := probeUnclaimed && failover.body == fast.id && probeReleased
	if !attemptScopedProbe {
		t.Logf("attempt-scoped probe unclaimed=%t failover=%q/%q released=%t remaining=%q circuitOpen=%t",
			probeUnclaimed, failover.body, failover.headers.Get("X-CDNCA-Origin-Reason"),
			probeReleased, adaptiveLeaseValue(t, port, probeKey), circuitOpen)
	}
	diagnostic := failover.headers.Get("X-CDNCA-Origin-Diagnostic")
	fallbackDiagnostic := failover.headers.Get("X-CDNCA-Origin-Reason") == "endpoint_ejected" &&
		strings.Contains(diagnostic, "p=repair-direct") && strings.Contains(diagnostic, "c=repair-fast")

	policy = adaptiveRepairPolicy(port, "repair-diagnostic", 201,
		[]Pool{{ID: "repair-direct", Kind: PoolOrigin, Endpoints: []Endpoint{fastEndpoint, mediumEndpoint}}},
		"repair-direct", "")
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
		adaptivePackedState(20, 0.001, 0, 10, 2, 0, 0))
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
	stale := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "stale-fallback", nil)
	fallbackDiagnostic = fallbackDiagnostic && stale.headers.Get("X-CDNCA-Origin-Reason") == "telemetry_stale_fallback" &&
		strings.Contains(stale.headers.Get("X-CDNCA-Origin-Diagnostic"), "p=repair-direct")

	setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
		adaptivePackedStateWarm(20, 0.001, 0, 0, 0, 0, 0, 0.1))
	setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
		adaptivePackedStateWarm(20, 0.012, 0, 0, 0, 0, 0, 0.1))
	slowStart := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "slow-fallback", nil)
	fallbackDiagnostic = fallbackDiagnostic && slowStart.headers.Get("X-CDNCA-Origin-Reason") == "slow_start_active" &&
		strings.Contains(slowStart.headers.Get("X-CDNCA-Origin-Diagnostic"), "p=repair-direct")

	policy.Revision++
	policy.VersionID = "repair-single"
	policy.Pools[0].Endpoints = []Endpoint{fastEndpoint}
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	single := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", "single-fallback", nil)
	fallbackDiagnostic = fallbackDiagnostic && single.headers.Get("X-CDNCA-Origin-Reason") == "single_candidate_fallback" &&
		strings.Contains(single.headers.Get("X-CDNCA-Origin-Diagnostic"), "p=repair-direct") &&
		strings.Contains(single.headers.Get("X-CDNCA-Origin-Diagnostic"), "c=repair-fast")
	if !fallbackDiagnostic {
		t.Logf("repair diagnostics failover=%q/%q stale=%q/%q slow=%q/%q single=%q/%q",
			failover.headers.Get("X-CDNCA-Origin-Reason"), diagnostic,
			stale.headers.Get("X-CDNCA-Origin-Reason"), stale.headers.Get("X-CDNCA-Origin-Diagnostic"),
			slowStart.headers.Get("X-CDNCA-Origin-Reason"), slowStart.headers.Get("X-CDNCA-Origin-Diagnostic"),
			single.headers.Get("X-CDNCA-Origin-Reason"), single.headers.Get("X-CDNCA-Origin-Diagnostic"))
	}
	l2A.fail.Store(false)
	l2B.fail.Store(false)

	fastEndpoint.Weight, mediumEndpoint.Weight = 1, 1
	policy = adaptiveRepairPolicy(port, "repair-failure-ewma", 202,
		[]Pool{{ID: "repair-direct", Kind: PoolOrigin, Endpoints: []Endpoint{fastEndpoint, mediumEndpoint}}},
		"repair-direct", "")
	policy.Adaptive.ExplorationPercent = 1
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, luaRoot, policy)
	fastBefore, mediumBefore = fast.requests.Load(), medium.requests.Load()
	for index := 0; index < 120; index++ {
		setAdaptivePackedState(t, port, policy, "repair-direct", fastEndpoint.ID,
			adaptivePackedState(20, 0.001, 0.25, 0, 2, 0, 0))
		setAdaptivePackedState(t, port, policy, "repair-direct", mediumEndpoint.ID,
			adaptivePackedState(20, 0.012, 0, 0, 2, 0, 0))
		_ = adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", fmt.Sprintf("failure-ewma-%03d", index), nil)
	}
	fastSelected = fast.requests.Load() - fastBefore
	mediumSelected = medium.requests.Load() - mediumBefore
	failureEWMAPreference := mediumSelected > fastSelected*2
	if !failureEWMAPreference {
		t.Logf("failure EWMA did not protect healthy endpoint: failed-fast=%d healthy-medium=%d", fastSelected, mediumSelected)
	}
	comparatorMatrix := verifyAdaptiveComparatorMatrix(t, port)
	ejectionLockRecovery := verifyAdaptiveLockCrashRecovery(t, port, policy)

	atomicEjectionFloor := verifyAdaptiveEjectionPublicationRace(
		t, runtime, root, luaRoot, port, fast, medium)
	return weightCapacityBounded, attemptScopedProbe, fallbackDiagnostic, malformedStateFallback,
		atomicEjectionFloor, failureEWMAPreference, comparatorMatrix, ejectionLockRecovery
}

func verifyAdaptiveComparatorMatrix(t *testing.T, port uint16) bool {
	t.Helper()
	tests := []struct {
		name, query, want string
	}{
		{"failure", "ff=0.1&fl=0.1&fw=1&fi=10&sf=0.2&sl=0.001&sw=100&si=0", "first"},
		{"latency", "ff=0.1&fl=0.001&fw=1&fi=2&sf=0.1&sl=0.01&sw=1&si=2", "first"},
		{"weight", "ff=0.1&fl=0.01&fw=10&fi=2&sf=0.1&sl=0.01&sw=1&si=2", "first"},
		{"inflight", "ff=0.1&fl=0.01&fw=1&fi=0&sf=0.1&sl=0.01&sw=1&si=5", "first"},
	}
	passed := true
	for _, test := range tests {
		response := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__adaptive_test_prefer?"+test.query, nil)
		if response.status != http.StatusOK || response.body != test.want {
			passed = false
			t.Logf("adaptive comparator %s=%d/%q, want %q", test.name, response.status, response.body, test.want)
		}
	}
	return passed
}

func verifyAdaptiveLockCrashRecovery(t *testing.T, port uint16, policy Policy) bool {
	t.Helper()
	key := adaptiveRepairKey(policy, "repair-direct", "", "ejection-lock")
	crash := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_lock_crash?key="+url.QueryEscape(key), nil)
	busy := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_lock_takeover?key="+url.QueryEscape(key), nil)
	time.Sleep(600 * time.Millisecond)
	takeover := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_lock_takeover?key="+url.QueryEscape(key), nil)
	return crash.status == http.StatusOK && busy.status == http.StatusConflict &&
		takeover.status == http.StatusOK && adaptiveLeaseValue(t, port, key) == ""
}

func adaptiveRepairPolicy(
	port uint16, version string, revision uint64, pools []Pool, primary, fallback string,
) Policy {
	adaptive := adaptivePolicy(AdaptiveActive)
	adaptive.MinimumSamples = 2
	adaptive.SampleFreshnessMS = 5000
	adaptive.PeakEWMAHalfLifeMS = 1000
	adaptive.ExplorationPercent = 10
	adaptive.SlowStart.RampMS = 1000
	adaptive.SlowStart.HardTimeoutMS = 2000
	adaptive.Outlier.MinimumSamples = 2
	return Policy{
		Schema: SchemaV1, Revision: revision,
		TenantID: "tenant-adaptive-repair", SiteID: "site-adaptive-repair", VersionID: version,
		Node:      Node{ID: "repair-l1", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1", Port: port}},
		Pools:     pools, DefaultPoolID: primary, DefaultFallbackPoolID: fallback,
		Routes: []Route{{ID: "repair", Priority: 10, PathPrefix: "/repair", PoolID: primary, FallbackPoolID: fallback}},
		Retry: RetryPolicy{Methods: []string{"GET", "HEAD"}, MaxAttempts: 3,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 200, TotalBudgetMS: 700},
		L2:       L2Policy{FailureThreshold: 3, RecoveryThreshold: 2, ProbeIntervalMS: 100, MaxHops: 2},
		Adaptive: adaptive,
	}
}

func TestAdaptiveRepairPolicyHasValidScopeIdentity(t *testing.T) {
	endpoint := Endpoint{ID: "repair-origin", Host: "127.0.0.1", Port: 8080, Weight: 1}
	policy := adaptiveRepairPolicy(18080, "repair-contract", 1,
		[]Pool{{ID: "repair-direct", Kind: PoolOrigin, Endpoints: []Endpoint{endpoint}}},
		"repair-direct", "")
	if _, err := Normalize(policy); err != nil {
		t.Fatalf("adaptive repair policy: %v", err)
	}
}

func adaptivePackedState(
	samples int, ewma, failure, lastAge float64, consecutive int, ejectedOffset float64, ejections int,
) string {
	return adaptivePackedStateWarm(samples, ewma, failure, lastAge, consecutive, ejectedOffset, ejections, 2)
}

func adaptivePackedStateWarm(
	samples int, ewma, failure, lastAge float64, consecutive int,
	ejectedOffset float64, ejections int, warmAge float64,
) string {
	now := float64(time.Now().Add(-50*time.Millisecond).UnixNano()) / float64(time.Second)
	last := math.Floor((now-lastAge)*1e6) / 1e6
	warm := math.Floor((now-warmAge)*1e6) / 1e6
	ejected := 0.0
	if ejectedOffset != 0 {
		ejected = math.Floor((now+ejectedOffset)*1e6) / 1e6
	}
	return fmt.Sprintf("1,%d,%.6f,%.6f,%.6f,%d,%.6f,%.6f,%.6f,%d",
		samples, ewma, ewma, failure, consecutive, last, warm, ejected, ejections)
}

func resetAdaptiveCandidatePackedStates(t *testing.T, port uint16, policy Policy, poolID string) {
	t.Helper()
	for _, pool := range policy.Pools {
		if pool.ID != poolID {
			continue
		}
		for index, endpoint := range pool.Endpoints {
			setAdaptivePackedState(t, port, policy, poolID, endpoint.ID,
				adaptivePackedStateWarm(2, 0.001+float64(index)*0.01, 0, 0, 0, 0, 0, 0.1))
		}
		return
	}
	t.Fatalf("adaptive candidate pool %q not found", poolID)
}

func adaptivePackedRaw(samples, ewma, peak, failure, consecutive, ejections string) string {
	now := float64(time.Now().Add(-50*time.Millisecond).UnixNano()) / float64(time.Second)
	return fmt.Sprintf("1,%s,%s,%s,%s,%s,%.6f,%.6f,0,%s",
		samples, ewma, peak, failure, consecutive, now, now-2, ejections)
}

func adaptiveRepairKey(policy Policy, poolID, endpointID, suffix string) string {
	stateKey := fmt.Sprintf("v1|tenant=%s|site=%s|version=%s", policy.TenantID, policy.SiteID, policy.VersionID)
	key := fmt.Sprintf("a1:%s:%d:%s", stateKey, policy.Revision, poolID)
	if endpointID != "" {
		key += ":" + endpointID
	}
	return key + ":" + suffix
}

func setAdaptivePackedState(t *testing.T, port uint16, policy Policy, poolID, endpointID, raw string) {
	t.Helper()
	key := adaptiveRepairKey(policy, poolID, endpointID, "state")
	reference := float64(time.Now().UnixNano()) / float64(time.Second)
	path := "/__adaptive_test_state_set?key=" + url.QueryEscape(key) +
		"&value=" + url.QueryEscape(raw) + "&reference=" + strconv.FormatFloat(reference, 'f', 9, 64)
	response := originRouteSmokeRequest(t, port, http.MethodGet, path, nil)
	if response.status != http.StatusOK || response.body != "ok" {
		t.Fatalf("set adaptive state status=%d body=%q key=%q", response.status, response.body, key)
	}
}

func adaptivePackedValue(t *testing.T, port uint16, key string) string {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__adaptive_test_state_get?key="+url.QueryEscape(key), nil)
	if response.status != http.StatusOK {
		t.Fatalf("get adaptive state status=%d body=%q key=%q", response.status, response.body, key)
	}
	return response.body
}

func adaptiveVisibleState(t *testing.T, port uint16, endpointID string) string {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__adaptive_test_fenced_state_value?endpoint="+url.QueryEscape(endpointID), nil)
	if response.status != http.StatusOK {
		t.Fatalf("get visible adaptive state status=%d body=%q endpoint=%q",
			response.status, response.body, endpointID)
	}
	return response.body
}

func adaptiveLeaseValue(t *testing.T, port uint16, key string) string {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet,
		"/__adaptive_test_lease_get?key="+url.QueryEscape(key), nil)
	if response.status != http.StatusOK {
		t.Fatalf("get adaptive lease status=%d body=%q key=%q", response.status, response.body, key)
	}
	return response.body
}

func waitAdaptiveBarrier(t *testing.T, port uint16, key string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__adaptive_test_barrier?key="+url.QueryEscape(key), nil)
		if response.status == http.StatusOK && response.body != "waiting" {
			return response.body
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("adaptive barrier %q was not reached", key)
	return ""
}

func adaptiveDistinctWorkerClients(t *testing.T, port uint16) []*http.Client {
	t.Helper()
	clients := make([]*http.Client, 0, 2)
	workers := make(map[string]struct{})
	for attempt := 0; attempt < 64 && len(clients) < 2; attempt++ {
		transport := &http.Transport{MaxIdleConnsPerHost: 1}
		client := &http.Client{Timeout: 30 * time.Second, Transport: transport}
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), client, port, "/__adaptive_test_worker", "")
		worker := response.headers.Get("X-CDNCA-Test-Worker")
		if requestErr != nil || response.status != http.StatusOK || worker == "" {
			transport.CloseIdleConnections()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if _, exists := workers[worker]; exists {
			transport.CloseIdleConnections()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		workers[worker] = struct{}{}
		clients = append(clients, client)
	}
	if len(clients) != 2 {
		t.Fatal("could not establish keepalive connections to both adaptive OpenResty workers")
	}
	return clients
}

func closeAdaptiveWorkerClients(clients []*http.Client) {
	for _, client := range clients {
		client.Transport.(*http.Transport).CloseIdleConnections()
	}
}

func verifyAdaptiveLeaseStateGenerationReuse(t *testing.T, port uint16, clients []*http.Client) {
	t.Helper()
	for _, kind := range []string{"ordinary", "ejection", "cap", "cooldown"} {
		reset := originRouteSmokeRequest(t, port, http.MethodPost,
			"/__adaptive_test_round5_reset?kind="+url.QueryEscape(kind), nil)
		if reset.status != http.StatusOK {
			t.Fatalf("adaptive %s generation reuse reset: status=%d body=%q", kind, reset.status, reset.body)
		}
		stalledResult := make(chan originRouteSmokeResponse, 1)
		go func() {
			response, requestErr := adaptiveOriginRouteClientRequest(
				context.Background(), clients[0], port,
				"/__adaptive_test_round5_write?kind="+url.QueryEscape(kind)+"&owner=stalled", "")
			if requestErr != nil {
				stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
				return
			}
			stalledResult <- response
		}()
		barrier := waitAdaptiveBarrier(t, port, "__cdnca_test_round5_"+kind+"_post_add")
		parts := strings.Split(barrier, ":")
		if len(parts) != 2 {
			t.Fatalf("adaptive %s generation reuse barrier=%q", kind, barrier)
		}
		stalledGeneration := mustOriginRouteGeneration(t, parts[1])
		time.Sleep(550 * time.Millisecond)
		replacement, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[1], port,
			"/__adaptive_test_round5_write?kind="+url.QueryEscape(kind)+"&owner=replacement", "")
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		value := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__adaptive_test_round5_value?kind="+url.QueryEscape(kind), nil)
		stalled := <-stalledResult
		if replacement.status != http.StatusOK ||
			mustOriginRouteGeneration(t, replacement.headers.Get("X-CDNCA-Test-Generation")) <= stalledGeneration ||
			stalled.status == http.StatusOK || value.body != "round5-replacement:"+kind {
			t.Fatalf("adaptive %s generation reuse replacement=%d/%q generation=%q stalled=%d/%q value=%q",
				kind, replacement.status, replacement.body,
				replacement.headers.Get("X-CDNCA-Test-Generation"), stalled.status, stalled.body, value.body)
		}
	}
	response := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_round6_history_bound?iterations=96", nil)
	counts := originRouteHistoryCounts(t, port, "/__adaptive_test_round6_history_bound_counts")
	if response.status != http.StatusOK || !slices.Equal(counts, []int{0, 1, 0, 1, 1}) {
		t.Fatalf("adaptive state history bound status=%d body=%q counts=%v",
			response.status, response.body, counts)
	}
}

func seedAdaptiveRepairPool(
	t *testing.T, port uint16, policy Policy, poolID string, endpoints []Endpoint, ewma float64, samples int,
) {
	t.Helper()
	for index, endpoint := range endpoints {
		setAdaptivePackedState(t, port, policy, poolID, endpoint.ID,
			adaptivePackedState(samples, ewma+float64(index)*0.001, 0, 0, 2, 0, 0))
	}
}

func verifyAdaptiveEjectionPublicationRace(
	t *testing.T,
	runtime *OpenRestyRuntime,
	root, luaRoot string,
	port uint16,
	fast, medium *originRouteSmokeOrigin,
) bool {
	t.Helper()
	engine, err := os.ReadFile(filepath.Join(luaRoot, "engine.lua"))
	if err != nil {
		t.Fatal(err)
	}
	instrumented := strings.Replace(string(engine),
		"  -- CDNCA_TEST_LEASE_STATE_WRITE_BARRIER\n",
		"  local cdnca_test_ejected = tonumber(string.match(raw,\n"+
			"    '^1,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,[^,]+,([^,]+),'))\n"+
			"  if string.find(base_key, ':race:race-fast:state', 1, true) then\n"+
			"    if string.find(raw, '^1,111,') and\n"+
			"      dictionary:add('__cdnca_test_adaptive_state_write', tostring(ngx.worker.pid()), 2) then\n"+
			"      ngx.sleep(0.7)\n"+
			"    elseif cdnca_test_ejected and cdnca_test_ejected > ngx.now() and\n"+
			"      dictionary:add('__cdnca_test_ejection_state_write', tostring(ngx.worker.pid()), 2) then\n"+
			"      local deadline = ngx.now() + 0.7\n"+
			"      repeat ngx.update_time() until ngx.now() >= deadline\n"+
			"    end\n"+
			"  end\n", 1)
	if instrumented == string(engine) {
		t.Fatal("adaptive ejection fenced-write instrumentation point is missing")
	}
	postAddInstrumented := strings.Replace(instrumented,
		"  -- CDNCA_TEST_LEASE_STATE_AFTER_ADD_BARRIER\n",
		"  local cdnca_test_round5_kind = string.match(raw, '^round5%-stalled:([a-z]+)$')\n"+
			"  if cdnca_test_round5_kind then\n"+
			"    dictionary:set('__cdnca_test_round5_' .. cdnca_test_round5_kind .. '_post_add',\n"+
			"      tostring(ngx.worker.pid()) .. ':' .. tostring(generation), 2)\n"+
			"    ngx.sleep(0.8)\n"+
			"  end\n", 1)
	if postAddInstrumented == instrumented {
		t.Fatal("adaptive post-add generation-reuse instrumentation point is missing")
	}
	instrumented = postAddInstrumented
	instrumentedRoot := filepath.Join(root, "adaptive-race-lua")
	if err := os.Mkdir(instrumentedRoot, 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instrumentedRoot, "engine.lua"), []byte(instrumented), 0o400); err != nil {
		t.Fatal(err)
	}

	fastEndpoint := fast.endpoint(t, "race-fast", PoolOrigin, "")
	mediumEndpoint := medium.endpoint(t, "race-medium", PoolOrigin, "")
	fastEndpoint.Weight, mediumEndpoint.Weight = 1, 1
	policy := adaptiveRepairPolicy(port, "repair-ejection-race", 300,
		[]Pool{{ID: "race", Kind: PoolOrigin, Endpoints: []Endpoint{fastEndpoint, mediumEndpoint}}}, "race", "")
	policy.Routes[0].PoolID = "race"
	policy.Retry.MaxAttempts = 1
	policy.Adaptive.MinimumSamples = 2
	policy.Adaptive.ExplorationPercent = 10
	policy.Adaptive.Outlier.MinimumSamples = 2
	policy.Adaptive.Outlier.ConsecutiveFailures = 1
	policy.Adaptive.Outlier.FailureRatioPercent = 1
	policy.Adaptive.Outlier.MaxEjectionPercent = 50
	policy.Adaptive.Outlier.BaseEjectionMS = 5000
	policy.Adaptive.Outlier.MaxEjectionMS = 5000

	policy.Revision++
	reusePolicy := policy
	reuseAdaptive := *policy.Adaptive
	reusePolicy.Adaptive = &reuseAdaptive
	reusePolicy.VersionID = "repair-ejection-race-reuse-1"
	reusePolicy.Adaptive.SampleFreshnessMS = 500
	reusePolicy.Adaptive.SlowStart.RampMS = 100
	reusePolicy.Adaptive.SlowStart.HardTimeoutMS = 100
	reusePolicy.Adaptive.Outlier.BaseEjectionMS = 100
	reusePolicy.Adaptive.Outlier.MaxEjectionMS = 100
	reusePolicy.Adaptive.Outlier.RecoveryProbeIntervalMS = 100
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, instrumentedRoot, reusePolicy)
	reuseClients := adaptiveDistinctWorkerClients(t, port)
	verifyAdaptiveLeaseStateGenerationReuse(t, port, reuseClients)
	closeAdaptiveWorkerClients(reuseClients)

	policy.Revision++
	policy.VersionID = "repair-ejection-race-2"
	activateAdaptiveOriginRouteTestRelease(t, runtime, root, instrumentedRoot, policy)

	seeds := make(map[string]string)
	for index := 0; index < 512 && (seeds[fast.id] == "" || seeds[medium.id] == ""); index++ {
		seedAdaptiveRepairPool(t, port, policy, "race", []Endpoint{fastEndpoint, mediumEndpoint}, 0.005, 1)
		seed := fmt.Sprintf("race-seed-%03d", index)
		response := adaptiveOriginRouteRequest(t, port, http.MethodGet, "/repair", seed, nil)
		seeds[response.body] = seed
	}
	if seeds[fast.id] == "" || seeds[medium.id] == "" {
		t.Fatal("could not select both race endpoints deterministically")
	}

	clients := adaptiveDistinctWorkerClients(t, port)
	defer func() {
		closeAdaptiveWorkerClients(clients)
	}()
	verifyAdaptiveStateWriteCAS(t, port, clients, policy, fastEndpoint)

	seedAdaptiveRepairPool(t, port, policy, "race", []Endpoint{fastEndpoint, mediumEndpoint}, 0.005, 1)
	for _, endpoint := range []Endpoint{fastEndpoint, mediumEndpoint} {
		key := adaptiveRepairKey(policy, "race", endpoint.ID, "state")
		raw := adaptivePackedValue(t, port, key)
		visible := adaptiveVisibleState(t, port, endpoint.ID)
		if visible == "" {
			t.Fatalf("adaptive ejection fixture is not visible: endpoint=%q raw=%q", endpoint.ID, raw)
		}
	}
	fast.fail.Store(true)
	medium.fail.Store(true)
	results := make(chan originRouteSmokeResponse, 2)
	firstCounts := map[string]int64{fast.id: fast.requests.Load(), medium.id: medium.requests.Load()}
	for index, seed := range []string{seeds[fast.id], seeds[medium.id]} {
		client, seed := clients[index], seed
		go func() {
			requestContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			response, requestErr := adaptiveOriginRouteClientRequest(requestContext, client, port, "/repair", seed)
			if requestErr != nil {
				results <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
				return
			}
			results <- response
		}()
		if index == 0 {
			waitOriginRouteRequestCount(t, fast, firstCounts[fast.id]+1)
			barrierDeadline := time.Now().Add(10 * time.Second)
			for {
				barrier := originRouteSmokeRequest(t, port, http.MethodGet,
					"/__adaptive_test_barrier?key=__cdnca_test_ejection_state_write", nil)
				if barrier.status == http.StatusOK && barrier.body != "waiting" {
					break
				}
				if time.Now().After(barrierDeadline) {
					t.Fatal("adaptive barrier \"__cdnca_test_ejection_state_write\" was not reached")
				}
				time.Sleep(5 * time.Millisecond)
			}
			time.Sleep(600 * time.Millisecond)
		}
	}
	first, second := <-results, <-results
	fast.fail.Store(false)
	medium.fail.Store(false)
	time.Sleep(1100 * time.Millisecond)
	if first.headers.Get("X-CDNCA-Test-Worker") == "" ||
		first.headers.Get("X-CDNCA-Test-Worker") == second.headers.Get("X-CDNCA-Test-Worker") {
		return false
	}
	ejected := 0
	for _, endpoint := range []Endpoint{fastEndpoint, mediumEndpoint} {
		raw := adaptiveVisibleState(t, port, endpoint.ID)
		parts := strings.Split(raw, ",")
		if len(parts) != 10 {
			return false
		}
		until, parseErr := strconv.ParseFloat(parts[8], 64)
		if parseErr != nil {
			return false
		}
		if until > float64(time.Now().UnixNano())/float64(time.Second) {
			ejected++
		}
	}
	lockFree := adaptiveLeaseValue(t, port, adaptiveRepairKey(policy, "race", "", "ejection-lock")) == "" &&
		adaptiveLeaseValue(t, port, adaptiveRepairKey(policy, "race", fastEndpoint.ID, "lock")) == "" &&
		adaptiveLeaseValue(t, port, adaptiveRepairKey(policy, "race", mediumEndpoint.ID, "lock")) == ""
	fast.fail.Store(false)
	medium.fail.Store(false)
	passed := ejected == 1 && lockFree
	if !passed {
		t.Logf("adaptive ejection publication race ejected=%d lockFree=%t first=%q second=%q",
			ejected, lockFree, first.body, second.body)
	}
	return passed
}

func verifyAdaptiveStateWriteCAS(
	t *testing.T, port uint16, clients []*http.Client, policy Policy, endpoint Endpoint,
) {
	t.Helper()
	reset := originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_round5_reset?kind=ordinary", nil)
	if reset.status != http.StatusOK {
		t.Fatalf("adaptive state CAS reset: status=%d body=%q", reset.status, reset.body)
	}
	stalledResult := make(chan originRouteSmokeResponse, 1)
	go func() {
		response, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), clients[0], port, "/__adaptive_test_fenced_state_write?owner=stalled", "")
		if requestErr != nil {
			stalledResult <- originRouteSmokeResponse{body: "error:" + requestErr.Error()}
			return
		}
		stalledResult <- response
	}()
	barrierDeadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case early := <-stalledResult:
			t.Fatalf("adaptive state write completed before barrier: status=%d body=%q", early.status, early.body)
		default:
		}
		barrier := originRouteSmokeRequest(t, port, http.MethodGet,
			"/__adaptive_test_barrier?key=__cdnca_test_adaptive_state_write", nil)
		if barrier.status == http.StatusOK && barrier.body != "waiting" {
			break
		}
		if time.Now().After(barrierDeadline) {
			t.Fatal("adaptive barrier \"__cdnca_test_adaptive_state_write\" was not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(600 * time.Millisecond)
	replacement, requestErr := adaptiveOriginRouteClientRequest(
		context.Background(), clients[1], port, "/__adaptive_test_fenced_state_write?owner=replacement", "")
	if requestErr != nil {
		t.Fatal(requestErr)
	}
	stalled := <-stalledResult
	raw := adaptiveVisibleState(t, port, endpoint.ID)
	parts := strings.Split(raw, ",")
	if replacement.status != http.StatusOK || stalled.status == http.StatusOK ||
		len(parts) != 10 || parts[1] != "222" {
		t.Fatalf("adaptive state write replacement=%d/%q stalled=%d/%q raw=%q",
			replacement.status, replacement.body, stalled.status, stalled.body, raw)
	}
	reset = originRouteSmokeRequest(t, port, http.MethodPost,
		"/__adaptive_test_round5_reset?kind=ordinary", nil)
	if reset.status != http.StatusOK {
		t.Fatalf("adaptive state CAS cleanup: status=%d body=%q", reset.status, reset.body)
	}
	for _, client := range clients {
		cooldown, requestErr := adaptiveOriginRouteClientRequest(
			context.Background(), client, port, "/__adaptive_test_cooldown_reset", "")
		if requestErr != nil || cooldown.status != http.StatusOK || cooldown.body != "ok" {
			t.Fatalf("adaptive state CAS cooldown reset: status=%d body=%q err=%v",
				cooldown.status, cooldown.body, requestErr)
		}
	}
}

func adaptiveOriginRoutePolicy(
	t *testing.T, port uint16, fast, medium, slow, postOnly *originRouteSmokeOrigin,
) Policy {
	t.Helper()
	fastEndpoint := fast.endpoint(t, "adaptive-fast", PoolOrigin, "")
	mediumEndpoint := medium.endpoint(t, "adaptive-medium", PoolOrigin, "")
	slowEndpoint := slow.endpoint(t, "adaptive-slow", PoolOrigin, "")
	fastEndpoint.Weight, mediumEndpoint.Weight, slowEndpoint.Weight = 80, 15, 5
	pressureFast := fast.endpoint(t, "pressure-fast", PoolOrigin, "")
	pressureMedium := medium.endpoint(t, "pressure-medium", PoolOrigin, "")
	pressureSlow := slow.endpoint(t, "pressure-slow", PoolOrigin, "")
	pressureFast.Weight, pressureMedium.Weight, pressureSlow.Weight = 80, 15, 5
	return Policy{
		Schema: SchemaV1, Revision: 1, TenantID: "tenant-adaptive", SiteID: "site-adaptive", VersionID: "adaptive-off",
		Node:      Node{ID: "l1-adaptive", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1", Port: port}},
		Pools: []Pool{
			{ID: "multi", Kind: PoolOrigin, Endpoints: []Endpoint{
				fastEndpoint, mediumEndpoint, slowEndpoint,
			}},
			{ID: "single", Kind: PoolOrigin, Endpoints: []Endpoint{
				fast.endpoint(t, "adaptive-single", PoolOrigin, ""),
			}},
			{ID: "pressure", Kind: PoolOrigin, Algorithm: "url_hash", Endpoints: []Endpoint{
				pressureFast, pressureMedium, pressureSlow,
			}},
			{ID: "post-only", Kind: PoolOrigin, Endpoints: []Endpoint{
				postOnly.endpoint(t, "adaptive-post-only", PoolOrigin, ""),
			}},
		},
		DefaultPoolID: "multi",
		Routes: []Route{
			{ID: "multi", Priority: 10, PathPrefix: "/multi", PoolID: "multi"},
			{ID: "single", Priority: 10, PathPrefix: "/single", PoolID: "single"},
			{ID: "state-failure", Priority: 10, PathPrefix: "/state-failure", PoolID: "pressure"},
			{ID: "post-only", Priority: 10, PathPrefix: "/post-only", PoolID: "post-only"},
		},
		Retry: RetryPolicy{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: 3,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 3000, TotalBudgetMS: 10000,
		},
		L2: L2Policy{FailureThreshold: 3, RecoveryThreshold: 3, ProbeIntervalMS: 10000, MaxHops: 2},
	}
}

func activateAdaptiveOriginRouteTestRelease(
	t *testing.T, runtime *OpenRestyRuntime, root, luaRoot string, policy Policy,
) {
	t.Helper()
	artifact, err := Compile(policy, root, luaRoot)
	if err != nil {
		t.Fatal(err)
	}
	config := string(artifact.Nginx)
	if strings.HasPrefix(policy.VersionID, "repair-ejection-race-") {
		config = strings.Replace(config, "worker_processes 1;", "worker_processes 2;", 1)
	}
	if !strings.Contains(config, "cdnca_originroute_adaptive_state") {
		config = strings.Replace(config,
			"  lua_shared_dict cdnca_originroute_state 1m;\n",
			"  lua_shared_dict cdnca_originroute_state 1m;\n  lua_shared_dict cdnca_originroute_adaptive_state 2m;\n", 1)
	}
	if !strings.Contains(config, "$cdnca_origin_reason") {
		config = strings.Replace(config,
			"    set $cdnca_origin_hop \"0\";\n",
			"    set $cdnca_origin_hop \"0\";\n    set $cdnca_origin_reason \"\";\n    set $cdnca_origin_shadow_reason \"\";\n    set $cdnca_origin_diagnostic \"\";\n", 1)
	}
	probeLeaseSeconds := float64(policy.Retry.TotalBudgetMS)/1000 + 1
	adaptiveStateTTLSeconds := 60.0
	if policy.Adaptive != nil {
		adaptiveStateTTLSeconds = float64(policy.Adaptive.SampleFreshnessMS) / 1000 * 4
	}
	historyBoundKey := fmt.Sprintf("a1:%s:%d:race:race-fast:round6-history", policy.VersionID, policy.Revision)
	access := `access_by_lua_block { require("engine").access("http") }`
	seeded := `access_by_lua_block {
        ngx.ctx.cdnca_origin_test_seed = ngx.var.http_x_cdnca_test_seed
        if ngx.var.http_x_cdnca_test_fill_adaptive == "1" then
          local dictionary = ngx.shared.cdnca_originroute_adaptive_state
          -- 引擎判容量前会 flush_expired 回收过期键（engine.lua state_capacity_available），
          -- 先清掉，保证填充后的压力不能被回收抵消。
          dictionary:flush_expired(0)
          for index = 1, 1024 do
            if dictionary:free_space() < 12288 then break end
		          local ok = dictionary:safe_set("test-pressure:" .. index, string.rep("x", 2048), 2)
	          if not ok then break end
          end
        end
		require("engine").access("http")
      }`
	config = strings.Replace(config, access, seeded, 1)
	testLocations := fmt.Sprintf(`    location = /__adaptive_test_state_set {
	      content_by_lua_block {
	        local args = ngx.req.get_uri_args(3)
	        if type(args.key) ~= "string" or string.sub(args.key, 1, 3) ~= "a1:" or
	          type(args.value) ~= "string" or #args.value > 256 or
	          type(args.reference) ~= "string" then
	          ngx.status = 400; ngx.say("invalid"); return
	        end
	        local reference = tonumber(args.reference)
	        local values = {}
	        for part in string.gmatch(args.value, "[^,]+") do values[#values + 1] = part end
	        if reference and reference > 0 and #values == 10 then
	          local delta = ngx.now() - reference
	          for _, index in ipairs({7, 8, 9}) do
	            local value = tonumber(values[index])
	            if value and value ~= 0 then values[index] = tostring(value + delta) end
	          end
	          args.value = table.concat(values, ",")
	        end
		        local engine = require("engine")
		        local cleared, clear_err = engine.test_lease_state_clear(
		          "cdnca_originroute_adaptive_state", args.key)
		        if not cleared then ngx.status = 500; ngx.say(clear_err); return end
		        local ok, err = ngx.shared.cdnca_originroute_adaptive_state:set(args.key, args.value, 60)
	        if not ok then ngx.status = 500; ngx.say(err); return end
	        ngx.say("ok")
	      }
	    }
	    location = /__adaptive_test_circuit_open {
	      content_by_lua_block {
	        local ok, err = require("engine").test_circuit_state_write(
	          "repair-l2", 0, ngx.now() + 30)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__adaptive_test_worker {
	      content_by_lua_block {
	        ngx.header["X-CDNCA-Test-Worker"] = tostring(ngx.worker.pid())
	        ngx.say("ok")
	      }
	    }
	    location = /__adaptive_test_round5_reset {
	      content_by_lua_block {
	        local ok, err = require("engine").test_adaptive_lease_reset(
	          "race", "race-fast", ngx.var.arg_kind)
	        if not ok then ngx.status = 400 end
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__adaptive_test_round5_write {
	      content_by_lua_block {
	        local kind = ngx.var.arg_kind
	        local owner = ngx.var.arg_owner
	        if owner ~= "stalled" and owner ~= "replacement" then
	          ngx.status = 400; ngx.say("invalid"); return
	        end
	        local marker = "round5-" .. owner .. ":" .. (kind or "")
	        local ok, err, generation = require("engine").test_adaptive_lease_write(
	          "race", "race-fast", kind, marker)
	        if not ok then ngx.status = 500 end
	        ngx.header["X-CDNCA-Test-Worker"] = tostring(ngx.worker.pid())
	        ngx.header["X-CDNCA-Test-Generation"] = tostring(generation or "")
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__adaptive_test_round5_value {
	      content_by_lua_block {
	        local value, err = require("engine").test_adaptive_lease_value(
	          "race", "race-fast", ngx.var.arg_kind)
	        if not value then ngx.status = 404 end
	        ngx.say(value or err)
	      }
	    }
	    location = /__adaptive_test_round6_history_bound {
	      content_by_lua_block {
	        local iterations = tonumber(ngx.var.arg_iterations)
	        local ok, err = require("engine").test_lease_state_history_bound(
	          "cdnca_originroute_adaptive_state", %q, iterations)
	        if not ok then ngx.status = 500 end
	        ngx.say(ok and "ok" or err)
	      }
	    }
	    location = /__adaptive_test_round6_history_bound_counts {
	      content_by_lua_block {
		        local owners, slots, releases, values, commits = require("engine").test_lease_key_counts(
		          "cdnca_originroute_adaptive_state", %q)
		        ngx.say(table.concat({owners, slots, releases, values, commits}, ","))
	      }
	    }
		    location = /__adaptive_test_state_get {
	      content_by_lua_block {
	        local args = ngx.req.get_uri_args(1)
	        if type(args.key) ~= "string" or string.sub(args.key, 1, 3) ~= "a1:" then
	          ngx.status = 400; ngx.say("invalid"); return
	        end
		        ngx.say(ngx.shared.cdnca_originroute_adaptive_state:get(args.key) or "")
	      }
	    }
		    location = /__adaptive_test_lease_get {
	      content_by_lua_block {
	        local args = ngx.req.get_uri_args(1)
	        if type(args.key) ~= "string" or string.sub(args.key, 1, 3) ~= "a1:" then
	          ngx.status = 400; ngx.say("invalid"); return
	        end
	        ngx.say(require("engine").test_probe_value(
	          "cdnca_originroute_adaptive_state", args.key) or "")
		    }
		    }
		    location = /__adaptive_test_fenced_state_write {
		      content_by_lua_block {
		        local owner = ngx.var.arg_owner
		        local marker = owner == "stalled" and 111 or owner == "replacement" and 222 or nil
		        if not marker then ngx.status = 400; ngx.say("invalid"); return end
		        local ok, err = require("engine").test_adaptive_state_write("race", "race-fast", marker)
		        if not ok then ngx.status = 500 end
		        ngx.say(ok and "ok" or err)
		      }
		    }
		    location = /__adaptive_test_fenced_state_value {
		      content_by_lua_block {
		        local endpoint = ngx.var.arg_endpoint
		        if endpoint ~= "race-fast" and endpoint ~= "race-medium" then
		          ngx.status = 400; ngx.say("invalid"); return
		        end
		        ngx.say(require("engine").test_adaptive_state_value("race", endpoint) or "")
		      }
		    }
		    location = /__adaptive_test_barrier {
		      content_by_lua_block {
		        local args = ngx.req.get_uri_args(1)
		        if type(args.key) ~= "string" or
		          not string.find(args.key, "^__cdnca_test_[a-z0-9_]+$") then
		          ngx.status = 400; ngx.say("invalid"); return
		        end
		        ngx.say(ngx.shared.cdnca_originroute_adaptive_state:get(args.key) or "waiting")
		      }
		    }
	    location = /__adaptive_test_state_decode {
	      content_by_lua_block {
	        local args = ngx.req.get_uri_args(1)
	        if type(args.value) ~= "string" or #args.value > 256 then
	          ngx.status = 400; ngx.say("invalid"); return
	        end
	        ngx.say(require("engine").test_decode_state(args.value) and "rejected" or "accepted")
	      }
	    }
	    location = /__adaptive_test_cooldown_reset {
		      content_by_lua_block {
		        local dictionary = ngx.shared.cdnca_originroute_adaptive_state
		        local prefix = "test-pressure:"
		        for _, key in ipairs(dictionary:get_keys(0)) do
		          if string.sub(key, 1, #prefix) == prefix then dictionary:delete(key) end
		        end
		        dictionary:flush_expired(0)
		        ngx.header["X-CDNCA-Test-Version"] = %q
		        ngx.say(require("engine").test_reset_state_cooldown() and "ok" or "failed")
		      }
		    }
	    location = /__adaptive_test_probe_reset {
      content_by_lua_block {
        local engine = require("engine")
        local ok, err = engine.test_adaptive_lease_reset(
          "multi", "adaptive-slow", "cooldown")
        if not ok then ngx.status = 500; ngx.say(err or "failed"); return end
        if not engine.test_reset_state_cooldown() then
          ngx.status = 500; ngx.say("failed"); return
        end
        ngx.say("ok")
      }
    }
	    location = /__adaptive_test_future {
      content_by_lua_block {
        local dictionary = ngx.shared.cdnca_originroute_adaptive_state
        local prefix = "a1:" .. %q .. ":"
        local changed = 0
        for _, key in ipairs(dictionary:get_keys(0)) do
          if string.sub(key, 1, #prefix) == prefix and string.sub(key, -6) == ":state" then
            local values = {}
            for part in string.gmatch(dictionary:get(key) or "", "[^,]+") do values[#values + 1] = part end
            if #values == 10 then
              values[7] = tostring(ngx.now() + 60)
              values[8] = tostring(ngx.now() + 60)
              dictionary:set(key, table.concat(values, ","), 60)
              changed = changed + 1
            end
          end
        end
        ngx.say(changed)
      }
    }
    location = /__adaptive_test_stats {
      content_by_lua_block {
        local dictionary = ngx.shared.cdnca_originroute_adaptive_state
        dictionary:flush_expired(0)
        ngx.say(#dictionary:get_keys(0) .. "," .. dictionary:free_space())
      }
    }
    location = /__adaptive_test_inflight {
      content_by_lua_block {
        local dictionary = ngx.shared.cdnca_originroute_adaptive_state
        dictionary:flush_expired(0)
        local total = 0
        for _, key in ipairs(dictionary:get_keys(0)) do
          if string.sub(key, -9) == ":inflight" then total = total + (tonumber(dictionary:get(key)) or 0) end
        end
        ngx.say(total)
      }
    }
	    location = /__adaptive_test_ejection {
	      content_by_lua_block {
	        local engine = require("engine")
	        local raw = engine.test_adaptive_state_value("multi", "adaptive-slow")
	        local values = {}
	        for part in string.gmatch(raw or "", "[^,]+") do values[#values + 1] = part end
	        if #values ~= 10 then ngx.status = 409; ngx.say("state missing"); return end
	        local cap = engine.test_lease_state_value("cdnca_originroute_adaptive_state", %q)
	        ngx.say(values[9] .. "," .. values[10] .. "," .. (cap and "1" or "0"))
	      }
	    }
	    location = /__adaptive_test_probe {
	      content_by_lua_block {
	        local value = require("engine").test_probe_value(
	          "cdnca_originroute_adaptive_state", %q)
	        ngx.say(value or "")
	      }
    }
    location = /__adaptive_test_probe_replace {
      content_by_lua_block {
        local ok = require("engine").test_probe_replace(
          "cdnca_originroute_adaptive_state", %q, "replacement-owner", %.3f)
        if not ok then ngx.status = 500 end
        ngx.say(ok and "ok" or "failed")
      }
    }
		    location = /__adaptive_test_probe_clear {
		      content_by_lua_block {
		        require("engine").test_probe_clear(
		          "cdnca_originroute_adaptive_state", %q)
		        ngx.shared.cdnca_originroute_adaptive_state:delete(%q)
		        ngx.say("ok")
	      }
    }
	    location = /__adaptive_test_probe_crash {
	      content_by_lua_block {
	        local dictionary = ngx.shared.cdnca_originroute_adaptive_state
	        local engine = require("engine")
	        local raw = engine.test_adaptive_state_value("multi", "adaptive-slow")
	        local values = {}
	        for part in string.gmatch(raw or "", "[^,]+") do values[#values + 1] = part end
	        if #values ~= 10 then ngx.status = 409; ngx.say("state missing"); return end
	        values[9] = tostring(ngx.now() - 0.001)
	        local cleared, clear_err = engine.test_lease_state_clear(
	          "cdnca_originroute_adaptive_state", %q)
	        if not cleared then ngx.status = 500; ngx.say(clear_err); return end
	        dictionary:set(%q, table.concat(values, ","), %.3f)
		local ok = engine.test_probe_seed(
		  "cdnca_originroute_adaptive_state", %q, "crashed-owner", %.3f)
        if not ok then ngx.status = 500 end
        ngx.say(ok and "ok" or "failed")
      }
    }
	location = /__adaptive_test_prefer {
	  content_by_lua_block {
		local args = ngx.req.get_uri_args(8)
		local values = {
		  tonumber(args.ff), tonumber(args.fl), tonumber(args.fw), tonumber(args.fi),
		  tonumber(args.sf), tonumber(args.sl), tonumber(args.sw), tonumber(args.si),
		}
		for _, value in ipairs(values) do
		  if not value then ngx.status = 400; ngx.say("invalid"); return end
		end
		local preferred, err = require("engine").test_adaptive_prefer(
		  values[1], values[2], values[3], values[4],
		  values[5], values[6], values[7], values[8])
		if not preferred then ngx.status = 500; ngx.say(err); return end
		ngx.say(preferred)
	  }
	}
	location = /__adaptive_test_lock_crash {
	  content_by_lua_block {
		local args = ngx.req.get_uri_args(1)
		if type(args.key) ~= "string" or string.sub(args.key, 1, 3) ~= "a1:" then
		  ngx.status = 400; ngx.say("invalid"); return
		end
		local ok, err = require("engine").test_adaptive_lock_crash(
		  "cdnca_originroute_adaptive_state", args.key)
		if not ok then ngx.status = 500 end
		ngx.say(ok and "ok" or err)
	  }
	}
	location = /__adaptive_test_lock_takeover {
	  content_by_lua_block {
		local args = ngx.req.get_uri_args(1)
		if type(args.key) ~= "string" or string.sub(args.key, 1, 3) ~= "a1:" then
		  ngx.status = 400; ngx.say("invalid"); return
		end
		local ok, err = require("engine").test_adaptive_lock_takeover(
		  "cdnca_originroute_adaptive_state", args.key)
		if not ok then ngx.status = 409 end
		ngx.say(ok and "ok" or err)
	  }
	}
    location = /__adaptive_test_benchmark {
      content_by_lua_block {
	        local value, err = require("engine").test_benchmark("multi", %d)
        if not value then ngx.status = 500; ngx.say(err); return end
        ngx.header.content_type = "application/json"
        ngx.say(require("cjson.safe").encode(value))
      }
    }
	`, historyBoundKey, historyBoundKey, policy.VersionID,
		fmt.Sprintf("v1|tenant=%s|site=%s|version=%s", policy.TenantID, policy.SiteID, policy.VersionID),
		adaptiveRepairKey(policy, "multi", "", "cap"),
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "probe"),
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "probe"),
		probeLeaseSeconds,
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "probe"),
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "probe-cooldown"),
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "state"),
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "state"),
		adaptiveStateTTLSeconds,
		adaptiveRepairKey(policy, "multi", "adaptive-slow", "probe"),
		probeLeaseSeconds, adaptiveLuaBenchmarkIterations)
	config = strings.Replace(config, "    location / {\n", testLocations+"    location / {\n", 1)
	config = strings.Replace(config, "      proxy_http_version 1.1;\n",
		"      add_header X-CDNCA-Origin-Reason $cdnca_origin_reason always;\n"+
			"      add_header X-CDNCA-Origin-Shadow-Reason $cdnca_origin_shadow_reason always;\n"+
			"      add_header X-CDNCA-Origin-Diagnostic $cdnca_origin_diagnostic always;\n"+
			"      add_header X-CDNCA-Test-Worker $pid always;\n"+
			"      proxy_http_version 1.1;\n", 1)

	release := filepath.Join(root, "versions", artifact.Digest)
	if err := os.MkdirAll(release, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "policy.json"), artifact.Policy, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(release, "nginx.conf"), []byte(config), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(release, 0o500); err != nil {
		t.Fatal(err)
	}
	activateOriginRouteStateTestRelease(t, runtime, root, release, policy.VersionID, policy.Listeners[0].Port)
}

func adaptiveOriginRouteRequest(
	t *testing.T, port uint16, method, path, seed string, body io.Reader,
) originRouteSmokeResponse {
	t.Helper()
	return originRouteSmokeRequestWithHeaders(t, port, method, path, body,
		map[string]string{"X-CDNCA-Test-Seed": seed})
}

func resetAdaptiveWorkerCooldown(t *testing.T, port uint16, version string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		response := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_cooldown_reset", nil)
		if response.status == http.StatusOK && response.body == "ok" &&
			response.headers.Get("X-CDNCA-Test-Version") == version {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("adaptive worker cooldown reset never reached version %q", version)
}

func adaptiveOriginRouteClientRequest(
	ctx context.Context, client *http.Client, port uint16, path, seed string,
) (originRouteSmokeResponse, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://127.0.0.1:%d%s", port, path), nil)
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	request.Header.Set("X-CDNCA-Test-Seed", seed)
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return originRouteSmokeResponse{}, err
	}
	return originRouteSmokeResponse{
		status: response.StatusCode, headers: response.Header.Clone(),
		body: strings.TrimSpace(string(content)), elapsed: time.Since(started),
	}, nil
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func adaptiveOriginRouteStateStats(t *testing.T, port uint16) (int, int) {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_stats", nil)
	parts := strings.Split(response.body, ",")
	if response.status != http.StatusOK || len(parts) != 2 {
		t.Fatalf("adaptive state stats status=%d body=%q", response.status, response.body)
	}
	keys, err := strconv.Atoi(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	free, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return keys, free
}

func adaptiveOriginRouteInflightTotal(t *testing.T, port uint16) int {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_inflight", nil)
	if response.status != http.StatusOK {
		t.Fatalf("adaptive inflight status=%d body=%q", response.status, response.body)
	}
	total, err := strconv.Atoi(response.body)
	if err != nil {
		t.Fatalf("adaptive inflight total %q: %v", response.body, err)
	}
	return total
}

func adaptiveOriginRouteEjectionState(t *testing.T, port uint16) (float64, int, bool) {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_ejection", nil)
	parts := strings.Split(response.body, ",")
	if response.status != http.StatusOK || len(parts) != 3 {
		t.Fatalf("adaptive ejection state status=%d body=%q", response.status, response.body)
	}
	ejectedAt, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		t.Fatalf("adaptive ejected-at %q: %v", parts[0], err)
	}
	ejections, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatalf("adaptive ejection count %q: %v", parts[1], err)
	}
	return ejectedAt, ejections, parts[2] == "1"
}

func adaptiveOriginRouteProbeValue(t *testing.T, port uint16) string {
	t.Helper()
	response := originRouteSmokeRequest(t, port, http.MethodGet, "/__adaptive_test_probe", nil)
	if response.status != http.StatusOK {
		t.Fatalf("adaptive probe status=%d body=%q", response.status, response.body)
	}
	return response.body
}

func waitOriginRouteRequestCount(t *testing.T, origin *originRouteSmokeOrigin, expected int64) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if origin.requests.Load() >= expected {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("origin %s request count=%d, expected at least %d", origin.id, origin.requests.Load(), expected)
}

func adaptiveOriginRouteLuaBenchmark(t *testing.T, port uint16) (float64, float64, float64, float64) {
	t.Helper()
	baselineElapsed := make([]float64, 0, 5)
	adaptiveElapsed := make([]float64, 0, 5)
	baselineHeap := make([]float64, 0, 5)
	adaptiveHeap := make([]float64, 0, 5)
	for index := 0; index < 5; index++ {
		response := originRouteSmokeRequestWithTimeout(
			t, port, http.MethodGet, "/__adaptive_test_benchmark", 10*time.Second)
		if response.status != http.StatusOK {
			t.Fatalf("adaptive benchmark status=%d body=%q", response.status, response.body)
		}
		var sample adaptiveLuaBenchmarkSample
		if err := json.Unmarshal([]byte(response.body), &sample); err != nil {
			t.Fatal(err)
		}
		if sample.Iterations != adaptiveLuaBenchmarkIterations {
			t.Fatalf("adaptive benchmark iterations=%d", sample.Iterations)
		}
		baselineElapsed = append(baselineElapsed, sample.BaselineElapsedMS)
		adaptiveElapsed = append(adaptiveElapsed, sample.AdaptiveElapsedMS)
		baselineHeap = append(baselineHeap, sample.BaselineHeapKB)
		adaptiveHeap = append(adaptiveHeap, sample.AdaptiveHeapKB)
	}
	return medianFloat(baselineElapsed), medianFloat(adaptiveElapsed),
		medianFloat(baselineHeap), medianFloat(adaptiveHeap)
}

func durationPercentileMS(values []time.Duration, percentile float64) float64 {
	copyValues := append([]time.Duration(nil), values...)
	sort.Slice(copyValues, func(left, right int) bool { return copyValues[left] < copyValues[right] })
	index := int(float64(len(copyValues)-1) * percentile)
	return float64(copyValues[index]) / float64(time.Millisecond)
}

func medianFloat(values []float64) float64 {
	copyValues := append([]float64(nil), values...)
	sort.Float64s(copyValues)
	return copyValues[len(copyValues)/2]
}
