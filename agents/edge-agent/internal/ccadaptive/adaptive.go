package ccadaptive

import (
	"container/heap"
	"errors"
	"sort"
	"sync"
)

type AdaptiveMode string

const (
	AdaptiveShadow AdaptiveMode = "shadow"
	AdaptiveAuto   AdaptiveMode = "auto"
)

type AdaptiveConfig struct {
	Mode                  AdaptiveMode `json:"mode"`
	AutoApproved          bool         `json:"auto_approved,omitempty"`
	Frozen                bool         `json:"frozen,omitempty"`
	Fallback              string       `json:"fallback"`
	MinSamples            uint32       `json:"min_samples"`
	MaxSamples            uint32       `json:"max_samples"`
	SampleFreshnessMicros int64        `json:"sample_freshness_micros"`
	EWMAAlphaPermille     uint32       `json:"ewma_alpha_permille"`
	MADMultiplierMilli    uint32       `json:"mad_multiplier_milli"`
	MinRatePerSecond      uint64       `json:"min_rate_per_second"`
	MaxRatePerSecond      uint64       `json:"max_rate_per_second"`
	MinBurst              uint64       `json:"min_burst"`
	MaxBurst              uint64       `json:"max_burst"`
	MaxStepPermille       uint32       `json:"max_step_permille"`
	HysteresisPermille    uint32       `json:"hysteresis_permille"`
	CooldownMicros        int64        `json:"cooldown_micros"`
	MaxGroups             uint32       `json:"max_groups"`
}

func (config AdaptiveConfig) validate() error {
	if config.Mode != AdaptiveShadow && config.Mode != AdaptiveAuto {
		return errors.New("adaptive mode must be shadow or auto")
	}
	if config.Mode == AdaptiveAuto && !config.AutoApproved {
		return errors.New("adaptive auto mode requires explicit approval")
	}
	if config.Mode == AdaptiveShadow && config.AutoApproved {
		return errors.New("adaptive shadow mode must not carry auto approval")
	}
	if config.Fallback != "static" {
		return errors.New("adaptive fallback must be static")
	}
	if config.MinSamples < 3 || config.MaxSamples < config.MinSamples || config.MaxSamples > 4096 ||
		config.SampleFreshnessMicros < 1_000_000 || config.SampleFreshnessMicros > MaxTimestampMicros ||
		config.EWMAAlphaPermille < 1 || config.EWMAAlphaPermille > 1000 ||
		config.MADMultiplierMilli < 1000 || config.MADMultiplierMilli > 10_000 ||
		config.MinRatePerSecond < 1 || config.MaxRatePerSecond < config.MinRatePerSecond || config.MaxRatePerSecond > MaxRatePerSecond ||
		config.MinBurst < 1 || config.MaxBurst < config.MinBurst || config.MaxBurst > MaxBurst ||
		config.MaxStepPermille < 1 || config.MaxStepPermille > 1000 || config.HysteresisPermille > 1000 ||
		config.CooldownMicros < 0 || config.CooldownMicros > MaxTimestampMicros ||
		config.MaxGroups < 1 || config.MaxGroups > 100_000 {
		return errors.New("adaptive bounds are invalid")
	}
	return nil
}

type ModelKey struct {
	TenantID string `json:"tenant_id"`
	SiteID   string `json:"site_id"`
	RuleID   string `json:"rule_id"`
	Revision uint64 `json:"revision"`
}

func (key ModelKey) valid() bool {
	return validIdentifier(key.TenantID) && validIdentifier(key.SiteID) && validIdentifier(key.RuleID) &&
		key.Revision >= 1 && key.Revision <= MaxRevision
}

type Sample struct {
	AtMicros     int64  `json:"at_micros"`
	Requests     uint64 `json:"requests"`
	WindowMicros uint64 `json:"window_micros"`
}

type Suggestion struct {
	RatePerSecond      uint64
	Burst              uint64
	ConfidencePermille uint32
	Reason             ReasonCode
	Apply              bool
	Fact               FactKind
}

type modelState struct {
	key          ModelKey
	rates        []uint64
	ewma         uint64
	lastSample   int64
	currentRate  uint64
	currentBurst uint64
	lastChange   int64
	frozen       bool
	capped       bool
	expiresAt    int64
	heapIndex    int
}

type Analyzer struct {
	config         AdaptiveConfig
	mu             sync.Mutex
	activeRevision uint64
	groups         map[ModelKey]*modelState
	expiry         modelExpiryHeap
}

type modelExpiryHeap []*modelState

func (states modelExpiryHeap) Len() int { return len(states) }

func (states modelExpiryHeap) Less(left, right int) bool {
	if states[left].expiresAt == states[right].expiresAt {
		return states[left].lastSample < states[right].lastSample
	}
	return states[left].expiresAt < states[right].expiresAt
}

func (states modelExpiryHeap) Swap(left, right int) {
	states[left], states[right] = states[right], states[left]
	states[left].heapIndex = left
	states[right].heapIndex = right
}

func (states *modelExpiryHeap) Push(value any) {
	state := value.(*modelState)
	state.heapIndex = len(*states)
	*states = append(*states, state)
}

func (states *modelExpiryHeap) Pop() any {
	old := *states
	last := len(old) - 1
	state := old[last]
	old[last] = nil
	state.heapIndex = -1
	*states = old[:last]
	return state
}

func NewAnalyzer(config AdaptiveConfig) (*Analyzer, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Analyzer{config: config, groups: make(map[ModelKey]*modelState)}, nil
}

func (analyzer *Analyzer) Observe(key ModelKey, sample Sample, baseline Limit) Suggestion {
	if analyzer == nil || !key.valid() || !baseline.valid() || sample.AtMicros < 0 ||
		sample.AtMicros > MaxTimestampMicros || sample.Requests == 0 || sample.Requests > MaxAdaptiveSample ||
		sample.WindowMicros == 0 || sample.WindowMicros > MaxAdaptiveSample {
		return fallbackSuggestion(baseline, ReasonInvalidInput)
	}
	if analyzer.config.Frozen {
		return fallbackSuggestion(baseline, ReasonManualThresholdFrozen)
	}
	analyzer.mu.Lock()
	defer analyzer.mu.Unlock()
	if key.Revision < analyzer.activeRevision {
		return fallbackSuggestion(baseline, ReasonLimiterStateUnavailable)
	}
	if key.Revision > analyzer.activeRevision {
		analyzer.activeRevision = key.Revision
		analyzer.groups = make(map[ModelKey]*modelState)
		analyzer.expiry = nil
	}
	analyzer.reclaimExpiredLocked(sample.AtMicros)
	state := analyzer.groups[key]
	if state == nil {
		if uint32(len(analyzer.groups)) >= analyzer.config.MaxGroups {
			return fallbackSuggestion(baseline, ReasonLimiterStateUnavailable)
		}
		state = &modelState{key: key, currentRate: baseline.RatePerSecond, currentBurst: baseline.Burst, heapIndex: -1}
		analyzer.groups[key] = state
	}
	if len(state.rates) > 0 && sample.AtMicros <= state.lastSample {
		return fallbackSuggestion(baseline, ReasonClockRegression)
	}
	rate, capped := sampleRate(sample, analyzer.config.MaxRatePerSecond)
	state.capped = state.capped || capped
	state.rates = append(state.rates, rate)
	if len(state.rates) > int(analyzer.config.MaxSamples) {
		copy(state.rates, state.rates[len(state.rates)-int(analyzer.config.MaxSamples):])
		state.rates = state.rates[:analyzer.config.MaxSamples]
	}
	if state.ewma == 0 {
		state.ewma = rate
	} else {
		alpha := uint64(analyzer.config.EWMAAlphaPermille)
		state.ewma = (alpha*rate + (1000-alpha)*state.ewma + 500) / 1000
	}
	state.lastSample = sample.AtMicros
	analyzer.touchExpiryLocked(state)
	return analyzer.suggestLocked(state, baseline, sample.AtMicros)
}

func (analyzer *Analyzer) Suggest(key ModelKey, baseline Limit, nowMicros int64) Suggestion {
	if analyzer == nil || !key.valid() || !baseline.valid() || nowMicros < 0 || nowMicros > MaxTimestampMicros {
		return fallbackSuggestion(baseline, ReasonInvalidInput)
	}
	if analyzer.config.Frozen {
		return fallbackSuggestion(baseline, ReasonManualThresholdFrozen)
	}
	analyzer.mu.Lock()
	defer analyzer.mu.Unlock()
	analyzer.reclaimExpiredLocked(nowMicros)
	state := analyzer.groups[key]
	if state == nil {
		return fallbackSuggestion(baseline, ReasonAdaptiveInsufficientSamples)
	}
	return analyzer.suggestLocked(state, baseline, nowMicros)
}

func (analyzer *Analyzer) Freeze(key ModelKey, frozen bool) {
	if analyzer == nil {
		return
	}
	analyzer.mu.Lock()
	defer analyzer.mu.Unlock()
	if state := analyzer.groups[key]; state != nil {
		state.frozen = frozen
	}
}

func (analyzer *Analyzer) suggestLocked(state *modelState, baseline Limit, nowMicros int64) Suggestion {
	if nowMicros < state.lastSample {
		return fallbackSuggestion(baseline, ReasonClockRegression)
	}
	if state.frozen {
		return fallbackSuggestion(baseline, ReasonManualThresholdFrozen)
	}
	if len(state.rates) < int(analyzer.config.MinSamples) {
		return fallbackSuggestion(baseline, ReasonAdaptiveInsufficientSamples)
	}
	if nowMicros-state.lastSample > analyzer.config.SampleFreshnessMicros {
		return fallbackSuggestion(baseline, ReasonAdaptiveBaselineStale)
	}
	values := append([]uint64(nil), state.rates...)
	medianRate := median(values)
	deviations := make([]uint64, len(values))
	for index, value := range values {
		if value > medianRate {
			deviations[index] = value - medianRate
		} else {
			deviations[index] = medianRate - value
		}
	}
	mad := median(deviations)
	candidate := medianRate + (mad*uint64(analyzer.config.MADMultiplierMilli)+999)/1000
	if state.ewma > candidate {
		candidate = state.ewma
	}
	candidate, capped := clamp(candidate, analyzer.config.MinRatePerSecond, analyzer.config.MaxRatePerSecond)
	if candidate > baseline.RatePerSecond {
		candidate = baseline.RatePerSecond
		capped = true
	}
	burst := baseline.Burst
	if baseline.RatePerSecond > 0 && candidate < baseline.RatePerSecond {
		burst = (baseline.Burst*candidate + baseline.RatePerSecond - 1) / baseline.RatePerSecond
	}
	burst, burstCapped := clamp(burst, analyzer.config.MinBurst, analyzer.config.MaxBurst)
	if burst > baseline.Burst {
		burst = baseline.Burst
		burstCapped = true
	}
	capped = capped || burstCapped || state.capped

	if analyzer.config.Mode == AdaptiveAuto {
		candidate, burst, capped = analyzer.boundChange(state, candidate, burst, nowMicros, capped)
		state.currentRate, state.currentBurst = candidate, burst
	}
	confidence := uint32(len(values) * 1000 / int(analyzer.config.MaxSamples))
	if confidence > 1000 {
		confidence = 1000
	}
	reason := ReasonAdaptiveShadowOnly
	fact := FactShadowSuggestion
	apply := false
	if analyzer.config.Mode == AdaptiveAuto {
		apply = true
		if capped {
			reason = ReasonAdaptiveChangeCapped
			fact = FactAutoClamped
		} else {
			reason = ReasonGCRALimitApplied
			fact = FactStaticAllow
		}
	}
	return Suggestion{RatePerSecond: candidate, Burst: burst, ConfidencePermille: confidence, Reason: reason, Apply: apply, Fact: fact}
}

func (analyzer *Analyzer) boundChange(state *modelState, rate, burst uint64, now int64, alreadyCapped bool) (uint64, uint64, bool) {
	if state.currentRate == 0 {
		state.currentRate = rate
		state.currentBurst = burst
	}
	if rate > state.currentRate {
		rate = state.currentRate
		alreadyCapped = true
	}
	if burst > state.currentBurst {
		burst = state.currentBurst
		alreadyCapped = true
	}
	if state.lastChange != 0 && now-state.lastChange < analyzer.config.CooldownMicros {
		return state.currentRate, state.currentBurst, alreadyCapped
	}
	difference := absoluteDifference(rate, state.currentRate)
	if difference*1000 <= state.currentRate*uint64(analyzer.config.HysteresisPermille) {
		return state.currentRate, state.currentBurst, alreadyCapped
	}
	step := state.currentRate * uint64(analyzer.config.MaxStepPermille) / 1000
	if step < 1 {
		step = 1
	}
	capped := alreadyCapped
	if rate+step < state.currentRate {
		rate = state.currentRate - step
		capped = true
	} else if rate > state.currentRate+step {
		rate = state.currentRate + step
		capped = true
	}
	burstStep := state.currentBurst * uint64(analyzer.config.MaxStepPermille) / 1000
	if burstStep < 1 {
		burstStep = 1
	}
	if burst+burstStep < state.currentBurst {
		burst = state.currentBurst - burstStep
		capped = true
	} else if burst > state.currentBurst+burstStep {
		burst = state.currentBurst + burstStep
		capped = true
	}
	state.lastChange = now
	return rate, burst, capped
}

func sampleRate(sample Sample, maximum uint64) (uint64, bool) {
	maximumRequests := maximum * sample.WindowMicros / microsPerSecond
	if sample.Requests > maximumRequests {
		return maximum, true
	}
	rate := ceilDivide(sample.Requests*microsPerSecond, sample.WindowMicros)
	if rate < 1 {
		rate = 1
	}
	if rate > maximum {
		return maximum, true
	}
	return rate, false
}

func (analyzer *Analyzer) touchExpiryLocked(state *modelState) {
	ttlSeconds := (uint64(analyzer.config.SampleFreshnessMicros) + microsPerSecond - 1) / microsPerSecond
	ttlMicros := int64(ttlSeconds * 4 * microsPerSecond)
	state.expiresAt = cappedTimestampAdd(state.lastSample, ttlMicros)
	if state.heapIndex < 0 {
		heap.Push(&analyzer.expiry, state)
		return
	}
	heap.Fix(&analyzer.expiry, state.heapIndex)
}

func (analyzer *Analyzer) reclaimExpiredLocked(nowMicros int64) {
	for analyzer.expiry.Len() > 0 && stateExpiredAt(nowMicros, analyzer.expiry[0].lastSample, analyzer.expiry[0].expiresAt) {
		state := heap.Pop(&analyzer.expiry).(*modelState)
		if analyzer.groups[state.key] == state {
			delete(analyzer.groups, state.key)
		}
	}
}

func median(values []uint64) uint64 {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	middle := len(values) / 2
	if len(values)%2 == 1 {
		return values[middle]
	}
	return values[middle-1] + (values[middle]-values[middle-1])/2
}

func clamp(value, minimum, maximum uint64) (uint64, bool) {
	if value < minimum {
		return minimum, true
	}
	if value > maximum {
		return maximum, true
	}
	return value, false
}

func absoluteDifference(left, right uint64) uint64 {
	if left > right {
		return left - right
	}
	return right - left
}

func fallbackSuggestion(baseline Limit, reason ReasonCode) Suggestion {
	return Suggestion{RatePerSecond: baseline.RatePerSecond, Burst: baseline.Burst, Reason: reason, Fact: FactFallback}
}
