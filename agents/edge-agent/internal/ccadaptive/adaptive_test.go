package ccadaptive

import (
	"fmt"
	"sync"
	"testing"
)

func TestAdaptiveShadowWarmupSuggestionAndStaleFallback(t *testing.T) {
	config := testAdaptiveConfig()
	config.Mode = AdaptiveShadow
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	for index := int64(0); index < 4; index++ {
		suggestion := analyzer.Observe(key, Sample{AtMicros: index * 1_000_000, Requests: 50, WindowMicros: 1_000_000}, baseline)
		if suggestion.Reason != ReasonAdaptiveInsufficientSamples || suggestion.Apply {
			t.Fatalf("warmup %d = %+v", index, suggestion)
		}
	}
	suggestion := analyzer.Observe(key, Sample{AtMicros: 4_000_000, Requests: 50, WindowMicros: 1_000_000}, baseline)
	if suggestion.Reason != ReasonAdaptiveShadowOnly || suggestion.Apply || suggestion.RatePerSecond == 0 || suggestion.ConfidencePermille == 0 {
		t.Fatalf("shadow suggestion = %+v", suggestion)
	}
	stale := analyzer.Suggest(key, baseline, 4_000_000+config.SampleFreshnessMicros+1)
	if stale.Reason != ReasonAdaptiveBaselineStale || stale.Apply || stale.RatePerSecond != baseline.RatePerSecond {
		t.Fatalf("stale fallback = %+v", stale)
	}
}

func TestAdaptiveAutoRequiresApprovalAndNeverRelaxesHardLimit(t *testing.T) {
	config := testAdaptiveConfig()
	config.Mode = AdaptiveAuto
	if _, err := NewAnalyzer(config); err == nil {
		t.Fatal("unapproved auto mode accepted")
	}
	config.AutoApproved = true
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	var suggestion Suggestion
	for index := int64(0); index < 5; index++ {
		suggestion = analyzer.Observe(key, Sample{AtMicros: index * 1_000_000, Requests: 10_000, WindowMicros: 1_000_000}, baseline)
	}
	if !suggestion.Apply || suggestion.RatePerSecond > baseline.RatePerSecond || suggestion.Burst > baseline.Burst ||
		suggestion.Reason != ReasonAdaptiveChangeCapped {
		t.Fatalf("auto hard-cap suggestion = %+v", suggestion)
	}
}

func TestAdaptiveShadowRejectsStaleAutoApproval(t *testing.T) {
	config := testAdaptiveConfig()
	config.AutoApproved = true
	if _, err := NewAnalyzer(config); err == nil {
		t.Fatal("shadow mode accepted auto approval")
	}
}

func TestAdaptiveMaxStepCooldownHysteresisAndManualFreeze(t *testing.T) {
	config := testAdaptiveConfig()
	config.Mode = AdaptiveAuto
	config.AutoApproved = true
	config.MaxStepPermille = 200
	config.HysteresisPermille = 100
	config.CooldownMicros = 5_000_000
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	var first Suggestion
	for index := int64(0); index < 5; index++ {
		first = analyzer.Observe(key, Sample{AtMicros: index * 1_000_000, Requests: 10, WindowMicros: 1_000_000}, baseline)
	}
	if first.RatePerSecond < 80 || first.RatePerSecond > 100 || !first.Apply {
		t.Fatalf("max-step suggestion = %+v", first)
	}
	cooling := analyzer.Observe(key, Sample{AtMicros: 4_500_000, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if cooling.RatePerSecond != first.RatePerSecond {
		t.Fatalf("cooldown changed suggestion: first=%+v cooling=%+v", first, cooling)
	}
	analyzer.Freeze(key, true)
	frozen := analyzer.Suggest(key, baseline, 4_500_001)
	if frozen.Reason != ReasonManualThresholdFrozen || frozen.Apply || frozen.RatePerSecond != baseline.RatePerSecond {
		t.Fatalf("frozen suggestion = %+v", frozen)
	}
}

func TestAdaptiveAutoOnlyTightensWithinRevision(t *testing.T) {
	config := testAdaptiveConfig()
	config.Mode = AdaptiveAuto
	config.AutoApproved = true
	config.MaxStepPermille = 1000
	config.HysteresisPermille = 0
	config.CooldownMicros = 0
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	var tightened Suggestion
	for index := int64(0); index < 5; index++ {
		tightened = analyzer.Observe(key, Sample{AtMicros: index, Requests: 10, WindowMicros: 1_000_000}, baseline)
	}
	if tightened.RatePerSecond != 10 || tightened.Burst != 2 {
		t.Fatalf("tightened = %+v", tightened)
	}
	var high Suggestion
	for index := int64(5); index < 15; index++ {
		high = analyzer.Observe(key, Sample{AtMicros: index, Requests: 100, WindowMicros: 1_000_000}, baseline)
	}
	if high.RatePerSecond != tightened.RatePerSecond || high.Burst != tightened.Burst {
		t.Fatalf("same revision relaxed: tightened=%+v high=%+v", tightened, high)
	}

	resetKey := key
	resetKey.Revision++
	var reset Suggestion
	for index := int64(0); index < 5; index++ {
		reset = analyzer.Observe(resetKey, Sample{AtMicros: index, Requests: 100, WindowMicros: 1_000_000}, baseline)
	}
	if reset.RatePerSecond != baseline.RatePerSecond || reset.Burst != baseline.Burst {
		t.Fatalf("new revision did not reset model: %+v", reset)
	}
}

func TestAdaptiveSameTimestampDoesNotAdvanceWarmup(t *testing.T) {
	analyzer, err := NewAnalyzer(testAdaptiveConfig())
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	first := analyzer.Observe(key, Sample{AtMicros: 1, Requests: 50, WindowMicros: 1_000_000}, baseline)
	if first.Reason != ReasonAdaptiveInsufficientSamples {
		t.Fatalf("first = %+v", first)
	}
	for index := 0; index < 10; index++ {
		duplicate := analyzer.Observe(key, Sample{AtMicros: 1, Requests: 50, WindowMicros: 1_000_000}, baseline)
		if duplicate.Reason != ReasonClockRegression || duplicate.Apply {
			t.Fatalf("duplicate %d = %+v", index, duplicate)
		}
	}
	if got := len(analyzer.groups[key].rates); got != 1 {
		t.Fatalf("duplicate timestamps counted as %d samples", got)
	}
}

func TestAdaptiveGroupsExpireAndReleaseCapacity(t *testing.T) {
	config := testAdaptiveConfig()
	config.SampleFreshnessMicros = 1_000_000
	config.MaxGroups = 1
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	ttlMicros := int64(4_000_000)
	oldKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "old", Revision: 7}
	newKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "new", Revision: 7}

	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	analyzer.Observe(oldKey, Sample{AtMicros: 0, Requests: 1, WindowMicros: 1_000_000}, baseline)
	blocked := analyzer.Observe(newKey, Sample{AtMicros: ttlMicros - 1, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if blocked.Reason != ReasonLimiterStateUnavailable || analyzer.groups[oldKey] == nil || analyzer.groups[newKey] != nil {
		t.Fatalf("active group was not protected: blocked=%+v groups=%v", blocked, analyzer.groups)
	}
	recovered := analyzer.Observe(newKey, Sample{AtMicros: ttlMicros, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if recovered.Reason != ReasonAdaptiveInsufficientSamples || analyzer.groups[oldKey] != nil || analyzer.groups[newKey] == nil {
		t.Fatalf("expired capacity was not recovered: recovered=%+v groups=%v", recovered, analyzer.groups)
	}

	atLimit, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	atLimit.Observe(oldKey, Sample{AtMicros: MaxTimestampMicros - ttlMicros, Requests: 1, WindowMicros: 1_000_000}, baseline)
	atLimitResult := atLimit.Observe(newKey, Sample{AtMicros: MaxTimestampMicros, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if atLimitResult.Reason != ReasonAdaptiveInsufficientSamples || atLimit.groups[oldKey] != nil || atLimit.groups[newKey] == nil {
		t.Fatalf("timestamp-limit capacity was not recovered: result=%+v groups=%v", atLimitResult, atLimit.groups)
	}
	atLimitRead := atLimit.Suggest(newKey, baseline, MaxTimestampMicros)
	if atLimitRead.Reason != ReasonAdaptiveInsufficientSamples || atLimit.groups[newKey] == nil {
		t.Fatalf("active timestamp-limit group was removed: result=%+v groups=%v", atLimitRead, atLimit.groups)
	}
}

func TestAdaptiveConcurrentExpiryAdmissionKeepsOneActiveGroup(t *testing.T) {
	config := testAdaptiveConfig()
	config.SampleFreshnessMicros = 1_000_000
	config.MaxGroups = 1
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "old", Revision: 7}
	analyzer.Observe(oldKey, Sample{AtMicros: 0, Requests: 1, WindowMicros: 1_000_000}, baseline)

	const contenders = 32
	var wait sync.WaitGroup
	var countMu sync.Mutex
	winners := 0
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: fmt.Sprintf("new-%d", index), Revision: 7}
			got := analyzer.Observe(key, Sample{AtMicros: 4_000_000, Requests: 1, WindowMicros: 1_000_000}, baseline)
			if got.Reason == ReasonAdaptiveInsufficientSamples {
				countMu.Lock()
				winners++
				countMu.Unlock()
			} else if got.Reason != ReasonLimiterStateUnavailable {
				t.Errorf("contender %d = %+v", index, got)
			}
		}(index)
	}
	wait.Wait()
	if winners != 1 || len(analyzer.groups) != 1 || analyzer.groups[oldKey] != nil {
		t.Fatalf("winners=%d groups=%v", winners, analyzer.groups)
	}
}

func TestAdaptiveSuggestRejectsClockRegressionWithoutMutation(t *testing.T) {
	config := testAdaptiveConfig()
	config.Mode = AdaptiveAuto
	config.AutoApproved = true
	config.MinSamples = 3
	config.MaxStepPermille = 1000
	config.HysteresisPermille = 0
	config.CooldownMicros = 0
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "clock", Revision: 7}
	for at := int64(0); at <= 2; at++ {
		analyzer.Observe(key, Sample{AtMicros: at, Requests: 10, WindowMicros: 1_000_000}, baseline)
	}
	equal := analyzer.Suggest(key, baseline, 2)
	if equal.Reason == ReasonClockRegression || !equal.Apply {
		t.Fatalf("equal timestamp = %+v", equal)
	}
	state := analyzer.groups[key]
	beforeRate, beforeBurst, beforeChange := state.currentRate, state.currentBurst, state.lastChange
	regressed := analyzer.Suggest(key, baseline, 1)
	if regressed.Reason != ReasonClockRegression || regressed.Apply || regressed.RatePerSecond != baseline.RatePerSecond ||
		state.currentRate != beforeRate || state.currentBurst != beforeBurst || state.lastChange != beforeChange {
		t.Fatalf("regressed suggestion mutated state: got=%+v state=%+v", regressed, state)
	}

	extremeKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "extreme", Revision: 7}
	for at := int64(MaxTimestampMicros - 2); at <= MaxTimestampMicros; at++ {
		analyzer.Observe(extremeKey, Sample{AtMicros: at, Requests: 10, WindowMicros: 1_000_000}, baseline)
	}
	extremeRegression := analyzer.Suggest(extremeKey, baseline, MaxTimestampMicros-1)
	if extremeRegression.Reason != ReasonClockRegression || extremeRegression.Apply {
		t.Fatalf("extreme regression = %+v", extremeRegression)
	}
	if got := analyzer.Suggest(extremeKey, baseline, MaxTimestampMicros); got.Reason == ReasonClockRegression {
		t.Fatalf("equal extreme timestamp = %+v", got)
	}
	newRevision := key
	newRevision.Revision++
	if got := analyzer.Suggest(newRevision, baseline, 0); got.Reason != ReasonAdaptiveInsufficientSamples || got.Apply {
		t.Fatalf("new revision inherited old clock = %+v", got)
	}
}

func TestAdaptiveSampleSafeIntegerBounds(t *testing.T) {
	config := testAdaptiveConfig()
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "sample-bound", Revision: 7}
	accepted := analyzer.Observe(key, Sample{
		AtMicros: 0, Requests: MaxAdaptiveSample, WindowMicros: MaxAdaptiveSample,
	}, baseline)
	if accepted.Reason != ReasonAdaptiveInsufficientSamples {
		t.Fatalf("maximum exact sample = %+v", accepted)
	}
	for _, sample := range []Sample{
		{AtMicros: 1, Requests: MaxAdaptiveSample + 1, WindowMicros: MaxAdaptiveSample},
		{AtMicros: 1, Requests: 1, WindowMicros: MaxAdaptiveSample + 1},
	} {
		if got := analyzer.Observe(key, sample, baseline); got.Reason != ReasonInvalidInput || got.Apply {
			t.Fatalf("unsafe sample accepted: sample=%+v got=%+v", sample, got)
		}
	}
}

func TestAdaptiveRevisionChangeReleasesCapacityAndRejectsLateSamples(t *testing.T) {
	config := testAdaptiveConfig()
	config.MaxGroups = 1
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 7}
	activeKey := oldKey
	activeKey.Revision = 8
	if got := analyzer.Observe(oldKey, Sample{AtMicros: 1, Requests: 10, WindowMicros: 1_000_000}, baseline); got.Reason != ReasonAdaptiveInsufficientSamples {
		t.Fatalf("old revision first sample = %+v", got)
	}
	if got := analyzer.Observe(activeKey, Sample{AtMicros: 1, Requests: 100, WindowMicros: 1_000_000}, baseline); got.Reason != ReasonAdaptiveInsufficientSamples {
		t.Fatalf("active revision first sample = %+v", got)
	}
	if analyzer.groups[oldKey] != nil || analyzer.groups[activeKey] == nil || len(analyzer.groups) != 1 {
		t.Fatalf("revision switch retained old capacity: groups=%v", analyzer.groups)
	}

	const lateSamples = 32
	results := make(chan Suggestion, lateSamples)
	var wait sync.WaitGroup
	for index := 0; index < lateSamples; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			lateKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: fmt.Sprintf("late-%d", index), Revision: 7}
			results <- analyzer.Observe(lateKey, Sample{AtMicros: int64(index + 2), Requests: 10, WindowMicros: 1_000_000}, baseline)
		}(index)
	}
	wait.Wait()
	close(results)
	for got := range results {
		if got.Reason != ReasonLimiterStateUnavailable || got.Apply {
			t.Fatalf("late revision sample = %+v", got)
		}
	}
	continued := analyzer.Observe(activeKey, Sample{AtMicros: 100, Requests: 100, WindowMicros: 1_000_000}, baseline)
	if continued.Reason != ReasonAdaptiveInsufficientSamples || len(analyzer.groups[activeKey].rates) != 2 || len(analyzer.groups) != 1 {
		t.Fatalf("late revision polluted active state: suggestion=%+v groups=%v", continued, analyzer.groups)
	}
	otherActiveKey := activeKey
	otherActiveKey.RuleID = "rule-b"
	if got := analyzer.Observe(otherActiveKey, Sample{AtMicros: 101, Requests: 10, WindowMicros: 1_000_000}, baseline); got.Reason != ReasonLimiterStateUnavailable {
		t.Fatalf("active revision capacity reason = %+v", got)
	}
}

func TestAdaptiveSaturatedExpiryReleasesCapacityAtMaximumTimestamp(t *testing.T) {
	config := testAdaptiveConfig()
	config.SampleFreshnessMicros = 1_000_000
	config.MaxGroups = 1
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	ttlMicros := int64(4_000_000)
	oldKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "old-max", Revision: 7}
	newKey := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "new-max", Revision: 7}
	analyzer.Observe(oldKey, Sample{AtMicros: MaxTimestampMicros - ttlMicros + 1, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if got := analyzer.Observe(newKey, Sample{AtMicros: MaxTimestampMicros - 1, Requests: 1, WindowMicros: 1_000_000}, baseline); got.Reason != ReasonLimiterStateUnavailable {
		t.Fatalf("state expired before saturated boundary: %+v", got)
	}
	admitted := analyzer.Observe(newKey, Sample{AtMicros: MaxTimestampMicros, Requests: 1, WindowMicros: 1_000_000}, baseline)
	if admitted.Reason != ReasonAdaptiveInsufficientSamples || analyzer.groups[oldKey] != nil || analyzer.groups[newKey] == nil {
		t.Fatalf("saturated expiry did not release capacity: suggestion=%+v groups=%v", admitted, analyzer.groups)
	}
	if got := analyzer.Suggest(newKey, baseline, MaxTimestampMicros); got.Reason != ReasonAdaptiveInsufficientSamples || analyzer.groups[newKey] == nil {
		t.Fatalf("active maximum-timestamp state was removed: suggestion=%+v groups=%v", got, analyzer.groups)
	}
}

func testAdaptiveConfig() AdaptiveConfig {
	return AdaptiveConfig{
		Mode: AdaptiveShadow, Fallback: "static", MinSamples: 5, MaxSamples: 32, SampleFreshnessMicros: 10_000_000,
		EWMAAlphaPermille: 250, MADMultiplierMilli: 3000, MinRatePerSecond: 1,
		MaxRatePerSecond: 1000, MinBurst: 1, MaxBurst: 100, MaxStepPermille: 200,
		HysteresisPermille: 50, CooldownMicros: 1_000_000, MaxGroups: 32,
	}
}

func TestPolicyFrozenUsesStaticFallbackWithoutLearning(t *testing.T) {
	config := testAdaptiveConfig()
	config.Frozen = true
	analyzer, err := NewAnalyzer(config)
	if err != nil {
		t.Fatal(err)
	}
	key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "rule-a", Revision: 1}
	baseline := Limit{RatePerSecond: 100, Burst: 20}
	observed := analyzer.Observe(key, Sample{AtMicros: 1_000_000, Requests: 50, WindowMicros: 1_000_000}, baseline)
	if observed.Reason != ReasonManualThresholdFrozen || observed.RatePerSecond != 100 || observed.Burst != 20 || len(analyzer.groups) != 0 {
		t.Fatalf("frozen observe = %+v groups=%d", observed, len(analyzer.groups))
	}
	if suggested := analyzer.Suggest(key, baseline, 2_000_000); suggested.Reason != ReasonManualThresholdFrozen {
		t.Fatalf("frozen suggest = %+v", suggested)
	}
}
