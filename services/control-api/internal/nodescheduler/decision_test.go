package nodescheduler

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDecisionAuditPayloadIncludesActualPlanSnapshotWithoutStableKey(t *testing.T) {
	groupID, endpointID := uuid.New(), uuid.New()
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	endpoint := Endpoint{ID: endpointID, Address: "192.0.2.10", Port: 443, Priority: 10, Weight: 100,
		Health: HealthState{Status: HealthHealthy, RowRevision: 12, LastReceivedAt: &now}}
	plan := Plan{
		GroupID: groupID, Revision: 4, Priority: 10, TierReason: ReasonBackupPrioritySelected,
		Candidates: []Endpoint{endpoint}, Digest: [32]byte{0x42}, EvaluatedAt: now,
		Evaluations: []EndpointEvaluation{{Endpoint: endpoint, Disposition: EndpointDispositionCandidate}},
	}
	payload := decisionAuditPayload(groupID, 4, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "private-client-key", RequestID: "decision-request",
	}, Decision{Endpoint: endpoint, Plan: plan, Strategy: StrategyWeightedBaseline, Reason: ReasonBaselineWeightedSelected})
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, fragment := range []string{
		`"tier_reason":"backup_priority_selected"`, `"evaluated_at":"2026-08-09T09:00:00Z"`,
		`"disposition":"candidate"`, `"health_row_revision":12`, `"endpoint_id":"` + endpointID.String() + `"`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("audit payload missing %s: %s", fragment, text)
		}
	}
	if strings.Contains(text, "private-client-key") {
		t.Fatalf("audit payload leaked stable key: %s", text)
	}
}

func TestDecisionModesAndTelemetryFallback(t *testing.T) {
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	candidates := []Endpoint{
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000001"), Weight: 1},
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000002"), Weight: 9},
	}
	plan := Plan{Candidates: candidates}

	baseline, err := Decide(plan, DecisionRequest{Strategy: StrategyWeightedBaseline, StableKey: "request-a"}, nil, now)
	if err != nil || baseline.Reason != ReasonBaselineWeightedSelected || baseline.Fallback {
		t.Fatalf("baseline = %#v, %v", baseline, err)
	}
	hr, err := Decide(plan, DecisionRequest{Strategy: StrategyWeightedRendezvous, StableKey: "request-a"}, nil, now)
	if err != nil || hr.Reason != ReasonWeightedRendezvousSelected || hr.Fallback {
		t.Fatalf("rendezvous = %#v, %v", hr, err)
	}
	loads := map[uuid.UUID]LoadSample{
		candidates[0].ID: {Inflight: 50, ObservedAt: now},
		candidates[1].ID: {Inflight: 0, ObservedAt: now},
	}
	p2c, err := Decide(plan, DecisionRequest{Strategy: StrategyP2CLeastLoaded, StableKey: "request-a"}, loads, now)
	if err != nil || p2c.Endpoint.ID != candidates[1].ID || p2c.Reason != ReasonP2CLeastLoadedSelected {
		t.Fatalf("p2c = %#v, %v", p2c, err)
	}
	delete(loads, candidates[0].ID)
	fallback, err := Decide(plan, DecisionRequest{Strategy: StrategyP2CLeastLoaded, StableKey: "request-a"}, loads, now)
	if err != nil || !fallback.Fallback || fallback.Reason != ReasonTelemetryInsufficient {
		t.Fatalf("insufficient fallback = %#v, %v", fallback, err)
	}
	loads[candidates[0].ID] = LoadSample{Inflight: 1, ObservedAt: now.Add(-time.Minute)}
	stale, err := Decide(plan, DecisionRequest{Strategy: StrategyP2CLeastLoaded, StableKey: "request-a"}, loads, now)
	if err != nil || !stale.Fallback || stale.Reason != ReasonTelemetryStaleFallback {
		t.Fatalf("stale fallback = %#v, %v", stale, err)
	}
}

func TestDecisionSingleAndNoHealthyReasons(t *testing.T) {
	endpoint := Endpoint{ID: uuid.New(), Weight: 1}
	baseline, err := Decide(Plan{Candidates: []Endpoint{endpoint}}, DecisionRequest{
		Strategy: StrategyWeightedBaseline, StableKey: "single-baseline",
	}, nil, time.Now())
	if err != nil || baseline.Endpoint.ID != endpoint.ID ||
		baseline.Reason != ReasonBaselineWeightedSelected || baseline.Fallback {
		t.Fatalf("single baseline = %#v, %v", baseline, err)
	}
	decision, err := Decide(Plan{Candidates: []Endpoint{endpoint}}, DecisionRequest{
		Strategy: StrategyWeightedRendezvous, StableKey: "single",
	}, nil, time.Now())
	if err != nil || decision.Endpoint.ID != endpoint.ID || decision.Reason != ReasonSingleCandidateFallback || !decision.Fallback {
		t.Fatalf("single = %#v, %v", decision, err)
	}
	decision, err = Decide(Plan{}, DecisionRequest{Strategy: StrategyWeightedBaseline, StableKey: "none"}, nil, time.Now())
	if !errors.Is(err, ErrNoHealthyEndpoint) || decision.Reason != ReasonNoHealthyEndpoint {
		t.Fatalf("empty = %#v, %v", decision, err)
	}
}

func TestSchedulingAlgorithmComparisonFixedSeed(t *testing.T) {
	candidates := []Endpoint{
		{ID: uuid.MustParse("20000000-0000-0000-0000-000000000001"), Weight: 1},
		{ID: uuid.MustParse("20000000-0000-0000-0000-000000000002"), Weight: 3},
		{ID: uuid.MustParse("20000000-0000-0000-0000-000000000003"), Weight: 6},
	}
	plan := Plan{Candidates: candidates}
	const samples = 30000
	baselineCounts := make(map[uuid.UUID]int)
	hrCounts := make(map[uuid.UUID]int)
	wrrCounts := make(map[uuid.UUID]int)
	for index := range samples {
		key := fmt.Sprintf("fixed-%08d", index)
		baseline, err := Decide(plan, DecisionRequest{Strategy: StrategyWeightedBaseline, StableKey: key}, nil, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		hr, err := Decide(plan, DecisionRequest{Strategy: StrategyWeightedRendezvous, StableKey: key}, nil, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		baselineCounts[baseline.Endpoint.ID]++
		hrCounts[hr.Endpoint.ID]++
		wrr, err := simpleWeightedRoundRobin(candidates, uint64(index))
		if err != nil {
			t.Fatal(err)
		}
		wrrCounts[wrr.ID]++
	}
	assertWeightAccuracy(t, candidates, baselineCounts, samples, 0.02)
	assertWeightAccuracy(t, candidates, hrCounts, samples, 0.02)
	assertWeightAccuracy(t, candidates, wrrCounts, samples, 0)
	baselineError := weightDistributionError(candidates, baselineCounts, samples)
	hrError := weightDistributionError(candidates, hrCounts, samples)
	wrrError := weightDistributionError(candidates, wrrCounts, samples)
	for _, endpoint := range candidates {
		if baselineCounts[endpoint.ID] == 0 || hrCounts[endpoint.ID] == 0 || wrrCounts[endpoint.ID] == 0 {
			t.Fatalf("starvation baseline=%v rendezvous=%v wrr=%v", baselineCounts, hrCounts, wrrCounts)
		}
	}

	extended := Plan{Candidates: append(append([]Endpoint{}, candidates...), Endpoint{
		ID: uuid.MustParse("20000000-0000-0000-0000-000000000004"), Weight: 2,
	})}
	baselineRemap, hrRemap, wrrRemap := 0, 0, 0
	for index := range 10000 {
		key := fmt.Sprintf("churn-%08d", index)
		beforeBaseline, _ := Decide(plan, DecisionRequest{Strategy: StrategyWeightedBaseline, StableKey: key}, nil, time.Unix(0, 0))
		afterBaseline, _ := Decide(extended, DecisionRequest{Strategy: StrategyWeightedBaseline, StableKey: key}, nil, time.Unix(0, 0))
		beforeHR, _ := Decide(plan, DecisionRequest{Strategy: StrategyWeightedRendezvous, StableKey: key}, nil, time.Unix(0, 0))
		afterHR, _ := Decide(extended, DecisionRequest{Strategy: StrategyWeightedRendezvous, StableKey: key}, nil, time.Unix(0, 0))
		if beforeBaseline.Endpoint.ID != afterBaseline.Endpoint.ID {
			baselineRemap++
		}
		if beforeHR.Endpoint.ID != afterHR.Endpoint.ID {
			hrRemap++
		}
		beforeWRR, _ := simpleWeightedRoundRobin(candidates, uint64(index))
		afterWRR, _ := simpleWeightedRoundRobin(extended.Candidates, uint64(index))
		if beforeWRR.ID != afterWRR.ID {
			wrrRemap++
		}
	}
	if hrRemap >= baselineRemap {
		t.Fatalf("rendezvous remap=%d, baseline remap=%d", hrRemap, baselineRemap)
	}

	latency := map[uuid.UUID]float64{candidates[0].ID: 80, candidates[1].ID: 20, candidates[2].ID: 10}
	baselineTail := weightedTailProxy(baselineCounts, latency, samples)
	hrTail := weightedTailProxy(hrCounts, latency, samples)
	wrrTail := weightedTailProxy(wrrCounts, latency, samples)
	loads := map[uuid.UUID]LoadSample{
		candidates[0].ID: {Inflight: 80, ObservedAt: time.Unix(0, 0)},
		candidates[1].ID: {Inflight: 20, ObservedAt: time.Unix(0, 0)},
		candidates[2].ID: {Inflight: 0, ObservedAt: time.Unix(0, 0)},
	}
	p2cCounts := make(map[uuid.UUID]int)
	for index := range samples {
		decision, err := Decide(plan, DecisionRequest{Strategy: StrategyP2CLeastLoaded,
			StableKey: fmt.Sprintf("tail-%08d", index)}, loads, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		p2cCounts[decision.Endpoint.ID]++
	}
	p2cTail := weightedTailProxy(p2cCounts, latency, samples)
	p2cError := weightDistributionError(candidates, p2cCounts, samples)
	if p2cError <= baselineError || p2cError <= hrError || p2cError <= wrrError {
		t.Fatalf("load-aware p2c unexpectedly preserved weight accuracy: p2c=%f baseline=%f hrw=%f wrr=%f",
			p2cError, baselineError, hrError, wrrError)
	}
	if p2cCounts[candidates[0].ID] != 0 || p2cCounts[candidates[1].ID] == 0 || p2cCounts[candidates[2].ID] == 0 {
		t.Fatalf("p2c sustained-load starvation comparison counts=%v", p2cCounts)
	}
	if p2cTail >= baselineTail || p2cTail >= hrTail || p2cTail >= wrrTail {
		t.Fatalf("tail proxy p2c=%f baseline=%f hrw=%f wrr=%f counts=%v",
			p2cTail, baselineTail, hrTail, wrrTail, p2cCounts)
	}
	extendedLoads := map[uuid.UUID]LoadSample{
		candidates[0].ID:          {Inflight: 80, ObservedAt: time.Unix(0, 0)},
		candidates[1].ID:          {Inflight: 20, ObservedAt: time.Unix(0, 0)},
		candidates[2].ID:          {Inflight: 0, ObservedAt: time.Unix(0, 0)},
		extended.Candidates[3].ID: {Inflight: 0, ObservedAt: time.Unix(0, 0)},
	}
	p2cRemap := 0
	for index := range 10000 {
		key := fmt.Sprintf("churn-%08d", index)
		before, err := Decide(plan, DecisionRequest{Strategy: StrategyP2CLeastLoaded, StableKey: key}, loads, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		after, err := Decide(extended, DecisionRequest{Strategy: StrategyP2CLeastLoaded, StableKey: key}, extendedLoads, time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		if before.Endpoint.ID != after.Endpoint.ID {
			p2cRemap++
		}
	}
	if p2cRemap == 0 || p2cRemap == 10000 {
		t.Fatalf("p2c membership jitter comparison remap=%d", p2cRemap)
	}
	restartedCounts := make(map[uuid.UUID]int)
	for index := range samples {
		endpoint, err := simpleWeightedRoundRobin(candidates, uint64(index%5))
		if err != nil {
			t.Fatal(err)
		}
		restartedCounts[endpoint.ID]++
	}
	continuousError := wrrError
	restartError := weightDistributionError(candidates, restartedCounts, samples)
	if restartError <= continuousError {
		t.Fatalf("WRR restart phase error=%f continuous=%f restarted=%v", restartError, continuousError, restartedCounts)
	}
	t.Logf("fixed-seed comparison baseline=%v rendezvous=%v wrr=%v p2c=%v accuracy_error baseline=%.4f hrw=%.4f wrr=%.4f p2c=%.4f remap baseline=%d hrw=%d wrr=%d p2c=%d tail_proxy baseline=%.1f hrw=%.1f wrr=%.1f p2c=%.1f restart_error=%.3f",
		baselineCounts, hrCounts, wrrCounts, p2cCounts, baselineError, hrError, wrrError, p2cError,
		baselineRemap, hrRemap, wrrRemap, p2cRemap, baselineTail, hrTail, wrrTail, p2cTail, restartError)
}

func simpleWeightedRoundRobin(candidates []Endpoint, phase uint64) (Endpoint, error) {
	return (Plan{Candidates: candidates}).ChooseWeighted(phase)
}

func weightDistributionError(endpoints []Endpoint, counts map[uuid.UUID]int, samples int) float64 {
	totalWeight := 0
	for _, endpoint := range endpoints {
		totalWeight += endpoint.Weight
	}
	var result float64
	for _, endpoint := range endpoints {
		actual := float64(counts[endpoint.ID]) / float64(samples)
		expected := float64(endpoint.Weight) / float64(totalWeight)
		result += math.Abs(actual - expected)
	}
	return result
}

func assertWeightAccuracy(t *testing.T, endpoints []Endpoint, counts map[uuid.UUID]int, samples int, tolerance float64) {
	t.Helper()
	totalWeight := 0
	for _, endpoint := range endpoints {
		totalWeight += endpoint.Weight
	}
	for _, endpoint := range endpoints {
		actual := float64(counts[endpoint.ID]) / float64(samples)
		expected := float64(endpoint.Weight) / float64(totalWeight)
		if math.Abs(actual-expected) > tolerance {
			t.Fatalf("endpoint %s actual=%f expected=%f counts=%v", endpoint.ID, actual, expected, counts)
		}
	}
}

func weightedTailProxy(counts map[uuid.UUID]int, latency map[uuid.UUID]float64, samples int) float64 {
	threshold := int(float64(samples) * 0.95)
	seen := 0
	for _, bound := range []float64{10, 20, 80} {
		for endpointID, count := range counts {
			if latency[endpointID] == bound {
				seen += count
			}
		}
		if seen >= threshold {
			return bound
		}
	}
	return 80
}
