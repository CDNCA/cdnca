package ccadaptive

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestGCRABurstBoundaryWeightedCostAndIdleRecovery(t *testing.T) {
	store := NewStore()
	key := NewKey("tenant-a", "site-a", "rule-a", "client_ip", 7, []byte("192.0.2.10"))
	limit := Limit{RatePerSecond: 10, Burst: 3}
	now := int64(1_000_000)

	for index, remaining := range []uint64{2, 1, 0} {
		decision := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: now})
		if decision.Outcome != OutcomeAllow || decision.Remaining != remaining || decision.Reason != ReasonGCRALimitApplied {
			t.Fatalf("request %d decision = %+v", index+1, decision)
		}
	}
	for _, delta := range []int64{0, 99_999} {
		decision := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: now + delta})
		if decision.Outcome != OutcomeDeny || decision.RetryAfterMicros != 100_000-delta {
			t.Fatalf("boundary delta %d decision = %+v", delta, decision)
		}
	}
	decision := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: now + 100_000})
	if decision.Outcome != OutcomeAllow || decision.Remaining != 0 {
		t.Fatalf("exact boundary decision = %+v", decision)
	}

	weighted := NewStore()
	decision = weighted.Decide(Request{Key: key, Limit: limit, Cost: 2, NowMicros: now})
	if decision.Outcome != OutcomeAllow || decision.Remaining != 1 {
		t.Fatalf("weighted first decision = %+v", decision)
	}
	decision = weighted.Decide(Request{Key: key, Limit: limit, Cost: 2, NowMicros: now})
	if decision.Outcome != OutcomeDeny || decision.RetryAfterMicros != 100_000 {
		t.Fatalf("weighted deny decision = %+v", decision)
	}
	decision = weighted.Decide(Request{Key: key, Limit: limit, Cost: 3, NowMicros: now + 1_000_000})
	if decision.Outcome != OutcomeAllow || decision.Remaining != 0 {
		t.Fatalf("idle recovery decision = %+v", decision)
	}
}

func TestGCRAFallbackDoesNotMutateState(t *testing.T) {
	store := NewStore()
	key := NewKey("tenant-a", "site-a", "rule-a", "path", 7, []byte("/private-value"))
	limit := Limit{RatePerSecond: 1, Burst: 1}

	first := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 10})
	if first.Outcome != OutcomeAllow {
		t.Fatalf("first decision = %+v", first)
	}
	regressed := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 9})
	if regressed.Outcome != OutcomeFallback || regressed.Reason != ReasonClockRegression {
		t.Fatalf("clock regression = %+v", regressed)
	}
	denied := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 10})
	if denied.Outcome != OutcomeDeny || denied.RetryAfterMicros != 1_000_000 {
		t.Fatalf("state changed after regression: %+v", denied)
	}

	store.SetUnavailable(true)
	unavailable := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 20})
	if unavailable.Outcome != OutcomeFallback || unavailable.Reason != ReasonLimiterStateUnavailable {
		t.Fatalf("unavailable decision = %+v", unavailable)
	}
	store.SetUnavailable(false)
	if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 20}); got.RetryAfterMicros != 999_990 {
		t.Fatalf("unavailable path mutated state: %+v", got)
	}

	extremeKey := NewKey("tenant-a", "site-a", "rule-b", "site", 7, nil)
	extreme := store.Decide(Request{Key: extremeKey, Limit: limit, Cost: 1, NowMicros: MaxTimestampMicros})
	if extreme.Outcome != OutcomeAllow || extreme.NextEligibleMicros != MaxTimestampMicros {
		t.Fatalf("extreme decision = %+v", extreme)
	}
}

func TestGCRAConcurrentRequestsHaveSingleBoundedWinnerSet(t *testing.T) {
	store := NewStore()
	key := NewKey("tenant-a", "site-a", "rule-a", "client_ip", 7, []byte("198.51.100.4"))
	request := Request{Key: key, Limit: Limit{RatePerSecond: 100, Burst: 10}, Cost: 1, NowMicros: 1_000_000}
	var allowed atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if store.Decide(request).Outcome == OutcomeAllow {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if got := allowed.Load(); got != 10 {
		t.Fatalf("allowed = %d, want 10", got)
	}
}

func TestGCRAKeyCapacityFailsBackWithoutEviction(t *testing.T) {
	store, err := NewStoreWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	limit := Limit{RatePerSecond: 1, Burst: 1}
	first := NewKey("tenant-a", "site-a", "rule-a", "site", 7, []byte("first"))
	second := NewKey("tenant-a", "site-a", "rule-a", "site", 7, []byte("second"))
	if got := store.Decide(Request{Key: first, Limit: limit, Cost: 1, NowMicros: 1}); got.Outcome != OutcomeAllow {
		t.Fatalf("first key = %+v", got)
	}
	if got := store.Decide(Request{Key: second, Limit: limit, Cost: 1, NowMicros: 1}); got.Outcome != OutcomeFallback || got.Reason != ReasonLimiterStateUnavailable {
		t.Fatalf("capacity fallback = %+v", got)
	}
	if got := store.Decide(Request{Key: first, Limit: limit, Cost: 1, NowMicros: 1}); got.Outcome != OutcomeDeny {
		t.Fatalf("existing key was evicted: %+v", got)
	}
	if got := store.Decide(Request{Key: second, Limit: limit, Cost: 1, NowMicros: 86_400_000_002}); got.Outcome != OutcomeAllow {
		t.Fatalf("expired key did not release capacity: %+v", got)
	}
}

func TestGCRARevisionAndColonIdentifiersAreDistinct(t *testing.T) {
	store, err := NewStoreWithCapacity(4)
	if err != nil {
		t.Fatal(err)
	}
	limit := Limit{RatePerSecond: 1, Burst: 1}
	raw := []byte("same-client")
	keys := []Key{
		NewKey("a:b", "c", "rule", "site", 7, raw),
		NewKey("a", "b:c", "rule", "site", 7, raw),
		NewKey("a:b", "c", "rule", "site", 8, raw),
	}
	for index, key := range keys {
		if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 1}); got.Outcome != OutcomeAllow {
			t.Fatalf("key %d collided: %+v", index, got)
		}
	}
	if keys[0].storageKey() == keys[1].storageKey() || keys[0].storageKey() == keys[2].storageKey() {
		t.Fatal("canonical storage keys collided")
	}
}

func TestGCRADenialAdvancesClockWithoutChargingDeniedCost(t *testing.T) {
	store := NewStore()
	key := NewKey("tenant-a", "site-a", "rule-a", "site", 7, nil)
	limit := Limit{RatePerSecond: 10, Burst: 1}
	if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 0}); got.Outcome != OutcomeAllow {
		t.Fatalf("initial allow = %+v", got)
	}
	if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 50_000}); got.Outcome != OutcomeDeny {
		t.Fatalf("deny = %+v", got)
	}
	if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 49_999}); got.Outcome != OutcomeFallback || got.Reason != ReasonClockRegression {
		t.Fatalf("deny clock was not retained: %+v", got)
	}
	if got := store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: 100_000}); got.Outcome != OutcomeAllow {
		t.Fatalf("denied cost was charged: %+v", got)
	}
}

func TestGCRAFailedRequestDoesNotConsumeCapacity(t *testing.T) {
	store, err := NewStoreWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	invalid := NewKey("tenant-a", "site-a", "rule-invalid", "site", 7, nil)
	if got := store.Decide(Request{Key: invalid, Limit: Limit{RatePerSecond: 1, Burst: 1}, Cost: 2, NowMicros: 1}); got.Outcome != OutcomeFallback {
		t.Fatalf("invalid request = %+v", got)
	}
	if len(store.states) != 0 {
		t.Fatalf("failed request left %d states", len(store.states))
	}
	valid := NewKey("tenant-a", "site-a", "rule-valid", "site", 7, nil)
	if got := store.Decide(Request{Key: valid, Limit: Limit{RatePerSecond: 1, Burst: 1}, Cost: 1, NowMicros: 1}); got.Outcome != OutcomeAllow {
		t.Fatalf("failed request consumed capacity: %+v", got)
	}
}

func TestGCRAHighRateDoesNotLoseHalfCapacityToRoundedIntervals(t *testing.T) {
	store := NewStore()
	key := NewKey("tenant-a", "site-a", "rule-fast", "site", 7, nil)
	limit := Limit{RatePerSecond: 999_999, Burst: 100}
	allowed := 0
	for now := int64(0); now < 1_000_000; now++ {
		if store.Decide(Request{Key: key, Limit: limit, Cost: 1, NowMicros: now}).Outcome == OutcomeAllow {
			allowed++
		}
	}
	if allowed < 999_999 {
		t.Fatalf("allowed = %d requests/s, want at least 999999", allowed)
	}
	t.Logf("configured_rate_requests_per_second=999999 allowed_requests_in_first_second=%d burst=100", allowed)
}

func TestDecisionFactNeverContainsRawIdentity(t *testing.T) {
	raw := []byte("secret-client-token")
	key := NewKey("tenant-a", "site-a", "rule-a", "token", 7, raw)
	decision := NewStore().Decide(Request{Key: key, Limit: Limit{RatePerSecond: 1, Burst: 1}, Cost: 1, NowMicros: 1})
	if decision.Fact.KeyDigest == "" || decision.Fact.TenantID != "tenant-a" || decision.Fact.SiteID != "site-a" ||
		decision.Fact.RuleID != "rule-a" || decision.Fact.KeyScope != "token" || decision.Fact.PolicyRevision != 7 {
		t.Fatalf("fact identity = %+v", decision.Fact)
	}
	if decision.Fact.Contains(string(raw)) {
		t.Fatalf("fact leaked raw identity: %+v", decision.Fact)
	}
}

func TestGCRASaturatedExpiryReleasesCapacityAtMaximumTimestamp(t *testing.T) {
	store, err := NewStoreWithCapacity(1)
	if err != nil {
		t.Fatal(err)
	}
	limit := Limit{RatePerSecond: 1, Burst: 1}
	ttlMicros := stateTTLMicros(limit)
	oldKey := NewKey("tenant-a", "site-a", "rule-a", "site", 7, []byte("old-max"))
	newKey := NewKey("tenant-a", "site-a", "rule-a", "site", 7, []byte("new-max"))
	if got := store.Decide(Request{Key: oldKey, Limit: limit, Cost: 1, NowMicros: MaxTimestampMicros - ttlMicros + 1}); got.Outcome != OutcomeAllow {
		t.Fatalf("old key first decision = %+v", got)
	}
	if got := store.Decide(Request{Key: newKey, Limit: limit, Cost: 1, NowMicros: MaxTimestampMicros - 1}); got.Outcome != OutcomeFallback || got.Reason != ReasonLimiterStateUnavailable {
		t.Fatalf("state expired before saturated boundary: %+v", got)
	}
	if got := store.Decide(Request{Key: newKey, Limit: limit, Cost: 1, NowMicros: MaxTimestampMicros}); got.Outcome != OutcomeAllow {
		t.Fatalf("saturated expiry did not release capacity: %+v", got)
	}
	if got := store.Decide(Request{Key: newKey, Limit: limit, Cost: 1, NowMicros: MaxTimestampMicros}); got.Outcome != OutcomeDeny || len(store.states) != 1 {
		t.Fatalf("active maximum-timestamp state was removed: decision=%+v states=%v", got, store.states)
	}
}
