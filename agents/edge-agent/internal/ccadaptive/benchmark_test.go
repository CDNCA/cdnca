package ccadaptive

import (
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"
	"unsafe"
)

type benchmarkLimiter interface {
	allow(nowMicros int64) bool
}

type fixedWindowReference struct {
	requests uint64
	window   int64
	bucket   int64
	count    uint64
}

func (limiter *fixedWindowReference) allow(nowMicros int64) bool {
	bucket := nowMicros / limiter.window
	if bucket != limiter.bucket {
		limiter.bucket = bucket
		limiter.count = 0
	}
	limiter.count++
	return limiter.count <= limiter.requests
}

type tokenBucketReference struct {
	rate       uint64
	capacity   uint64
	tokens     uint64
	lastMicros int64
}

func (limiter *tokenBucketReference) allow(nowMicros int64) bool {
	if limiter.lastMicros == 0 {
		limiter.tokens = limiter.capacity * microsPerSecond
		limiter.lastMicros = nowMicros
	}
	if nowMicros > limiter.lastMicros {
		refill := uint64(nowMicros-limiter.lastMicros) * limiter.rate
		limiter.tokens = min(limiter.capacity*microsPerSecond, limiter.tokens+refill)
		limiter.lastMicros = nowMicros
	}
	if limiter.tokens < microsPerSecond {
		return false
	}
	limiter.tokens -= microsPerSecond
	return true
}

type gcraBenchmark struct {
	store *Store
	key   Key
	limit Limit
}

func (limiter *gcraBenchmark) allow(nowMicros int64) bool {
	return limiter.store.Decide(Request{Key: limiter.key, Limit: limiter.limit, Cost: 1, NowMicros: nowMicros}).Outcome == OutcomeAllow
}

func TestLimiterComparisonMetrics(t *testing.T) {
	type scenario struct {
		name   string
		events []int64
		want   []bool
	}
	boundary := scenario{name: "window-boundary"}
	for index := 0; index < 100; index++ {
		boundary.events = append(boundary.events, 999_999)
		boundary.want = append(boundary.want, true)
	}
	for index := 0; index < 100; index++ {
		boundary.events = append(boundary.events, 1_000_000)
		boundary.want = append(boundary.want, false)
	}
	steady := scenario{name: "steady"}
	for index := 0; index < 1000; index++ {
		steady.events = append(steady.events, 1_000_000+int64(index)*10_000)
		steady.want = append(steady.want, true)
	}
	attack := scenario{name: "instant-attack"}
	for index := 0; index < 1000; index++ {
		attack.events = append(attack.events, 1_000_000)
		attack.want = append(attack.want, index < 100)
	}

	constructors := []struct {
		name           string
		new            func() benchmarkLimiter
		wantCorrect    int
		wantFalseBurst int
	}{
		{name: "fixed-window-test-reference", new: func() benchmarkLimiter {
			return &fixedWindowReference{requests: 100, window: 1_000_000, bucket: -1}
		}, wantCorrect: 2100, wantFalseBurst: 100},
		{name: "token-bucket-test-reference", new: func() benchmarkLimiter {
			return &tokenBucketReference{rate: 100, capacity: 100}
		}, wantCorrect: 2200, wantFalseBurst: 0},
		{name: "production-gcra", new: newGCRABenchmark, wantCorrect: 2200, wantFalseBurst: 0},
	}
	for _, constructor := range constructors {
		correct := 0
		total := 0
		falseBurst := 0
		for _, workload := range []scenario{boundary, steady, attack} {
			limiter := constructor.new()
			for index, at := range workload.events {
				got := limiter.allow(at)
				if got == workload.want[index] {
					correct++
				}
				if workload.name == "window-boundary" && index >= 100 && got {
					falseBurst++
				}
				total++
			}
		}
		t.Logf("%s correct=%d/%d false_burst=%d", constructor.name, correct, total, falseBurst)
		if correct != constructor.wantCorrect || falseBurst != constructor.wantFalseBurst {
			t.Fatalf("%s metrics correct=%d false_burst=%d, want %d/%d",
				constructor.name, correct, falseBurst, constructor.wantCorrect, constructor.wantFalseBurst)
		}
	}

	for _, constructor := range constructors {
		var samples []int64
		var sink bool
		for trial := 0; trial < 5; trial++ {
			limiter := constructor.new()
			for batch := 0; batch < 200; batch++ {
				started := time.Now()
				for index := 0; index < 100; index++ {
					sink = sink != limiter.allow(1_000_000+int64(batch*100+index)*10_000)
				}
				samples = append(samples, time.Since(started).Nanoseconds()/100)
			}
		}
		benchmarkBooleanSink = sink
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		t.Logf("%s latency_ns p50=%d p95=%d p99=%d trials=5 operations_per_trial=20000",
			constructor.name, percentile(samples, 50), percentile(samples, 95), percentile(samples, 99))
	}
}

var benchmarkBooleanSink bool

func TestAdaptiveScenarioMetrics(t *testing.T) {
	type profile struct {
		name         string
		rates        []uint64
		wantUsable   int
		wantFinal    uint64
		wantReason   ReasonCode
		wantJitter   uint64
		wantRecovery int
	}
	profiles := []profile{
		{name: "normal", rates: repeat(50, 20), wantUsable: 16, wantFinal: 50, wantReason: ReasonAdaptiveShadowOnly, wantRecovery: -1},
		{name: "periodic", rates: []uint64{30, 70, 30, 70, 30, 70, 30, 70, 30, 70, 30, 70}, wantUsable: 8, wantFinal: 100, wantReason: ReasonAdaptiveShadowOnly, wantJitter: 58, wantRecovery: -1},
		{name: "spike", rates: append(append(repeat(50, 8), 500), repeat(50, 20)...), wantUsable: 25, wantFinal: 52, wantReason: ReasonAdaptiveShadowOnly, wantJitter: 50, wantRecovery: 11},
		{name: "attack", rates: repeat(10_000, 12), wantUsable: 8, wantFinal: 100, wantReason: ReasonAdaptiveShadowOnly, wantRecovery: -1},
		{name: "low-sample", rates: []uint64{50, 50}, wantFinal: 100, wantReason: ReasonAdaptiveInsufficientSamples, wantRecovery: -1},
	}
	for _, profile := range profiles {
		config := testAdaptiveConfig()
		config.Mode = AdaptiveShadow
		analyzer, err := NewAnalyzer(config)
		if err != nil {
			t.Fatal(err)
		}
		key := ModelKey{TenantID: "tenant-a", SiteID: "site-a", RuleID: "profile-" + profile.name, Revision: 7}
		baseline := Limit{RatePerSecond: 100, Burst: 20}
		var suggestions []uint64
		var final Suggestion
		for index, rate := range profile.rates {
			final = analyzer.Observe(key, Sample{AtMicros: int64(index) * 1_000_000, Requests: rate, WindowMicros: 1_000_000}, baseline)
			if final.Reason != ReasonAdaptiveInsufficientSamples {
				suggestions = append(suggestions, final.RatePerSecond)
			}
			if final.Apply {
				t.Fatalf("%s shadow suggestion applied: %+v", profile.name, final)
			}
		}
		jitter := uint64(0)
		for index := 1; index < len(suggestions); index++ {
			jitter = max(jitter, absoluteDifference(suggestions[index], suggestions[index-1]))
		}
		recovery := -1
		if profile.name == "spike" {
			for index, value := range suggestions {
				if index >= 4 && value <= 55 {
					recovery = index - 4
					break
				}
			}
		}
		t.Logf("%s samples=%d usable=%d final_rate_requests_per_second=%d reason=%s max_suggestion_jitter_requests_per_second=%d recovery_samples=%d",
			profile.name, len(profile.rates), len(suggestions), final.RatePerSecond, final.Reason, jitter, recovery)
		if len(suggestions) != profile.wantUsable || final.RatePerSecond != profile.wantFinal ||
			final.Reason != profile.wantReason || jitter != profile.wantJitter || recovery != profile.wantRecovery {
			t.Fatalf("%s metrics usable=%d final=%d reason=%s jitter=%d recovery=%d",
				profile.name, len(suggestions), final.RatePerSecond, final.Reason, jitter, recovery)
		}
	}
}

func TestStateMemoryMetrics(t *testing.T) {
	const keys = 100_000
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	store := NewStore()
	for index := 0; index < keys; index++ {
		key := NewKey("tenant-a", "site-a", "rule-a", "client_ip", 7, []byte(strconv.Itoa(index)))
		store.Decide(Request{Key: key, Limit: Limit{RatePerSecond: 100, Burst: 100}, Cost: 1, NowMicros: 1})
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(store)
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	perKey := delta / keys
	t.Logf("state_bytes fixed_window_reference=%d token_bucket_reference=%d gcra_heap_per_active_key=%d keys=%d",
		unsafe.Sizeof(fixedWindowReference{}), unsafe.Sizeof(tokenBucketReference{}),
		perKey, keys)
	if len(store.states) != keys || perKey < 64 || perKey > 512 {
		t.Fatalf("state metrics count=%d bytes_per_key=%d", len(store.states), perKey)
	}
}

func BenchmarkLimiters(b *testing.B) {
	benchmarks := []struct {
		name string
		new  func() benchmarkLimiter
	}{
		{name: "fixed-window-test-reference", new: func() benchmarkLimiter {
			return &fixedWindowReference{requests: 100, window: 1_000_000, bucket: -1}
		}},
		{name: "token-bucket-test-reference", new: func() benchmarkLimiter {
			return &tokenBucketReference{rate: 100, capacity: 100}
		}},
		{name: "production-gcra", new: newGCRABenchmark},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			limiter := benchmark.new()
			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				limiter.allow(1_000_000 + int64(index)*10_000)
			}
		})
	}
}

func newGCRABenchmark() benchmarkLimiter {
	return &gcraBenchmark{
		store: NewStore(), key: NewKey("tenant-a", "site-a", "rule-a", "site", 7, nil),
		limit: Limit{RatePerSecond: 100, Burst: 100},
	}
}

func percentile(values []int64, percent int) int64 {
	index := (len(values)*percent + 99) / 100
	if index < 1 {
		index = 1
	}
	return values[index-1]
}

func repeat(value uint64, count int) []uint64 {
	values := make([]uint64, count)
	for index := range values {
		values[index] = value
	}
	return values
}
