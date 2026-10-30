package ccadaptive

import (
	"errors"
	"sync"
	"sync/atomic"
)

const microsPerSecond uint64 = 1_000_000

const (
	DefaultMaxKeys        = 100_000
	minimumStateTTLMicros = int64(60_000_000)
	maximumStateTTLMicros = int64(14 * 24 * 60 * 60 * 1_000_000)
)

type keyState struct {
	mu        sync.Mutex
	debt      uint64
	lastNow   int64
	expiresAt int64
}

type Store struct {
	mu          sync.Mutex
	states      map[string]*keyState
	maxKeys     int
	unavailable atomic.Bool
}

func NewStore() *Store { return &Store{states: make(map[string]*keyState), maxKeys: DefaultMaxKeys} }

func NewStoreWithCapacity(maxKeys int) (*Store, error) {
	if maxKeys < 1 || maxKeys > 10_000_000 {
		return nil, errors.New("GCRA max keys must be between 1 and 10000000")
	}
	return &Store{states: make(map[string]*keyState), maxKeys: maxKeys}, nil
}

func (store *Store) SetUnavailable(unavailable bool) { store.unavailable.Store(unavailable) }

func (store *Store) Decide(request Request) Decision {
	fact := factFor(request.Key)
	if store == nil || store.unavailable.Load() {
		return fallback(fact, ReasonLimiterStateUnavailable)
	}
	if !request.Key.valid() || !request.Limit.valid() || request.Cost < 1 ||
		request.Cost > request.Limit.Burst || request.NowMicros < 0 || request.NowMicros > MaxTimestampMicros {
		return fallback(fact, ReasonInvalidInput)
	}

	capacityDebt := request.Limit.Burst * microsPerSecond
	costDebt := request.Cost * microsPerSecond
	state, ok := store.lockedState(request.Key.storageKey(), request.NowMicros)
	if !ok {
		return fallback(fact, ReasonLimiterStateUnavailable)
	}
	defer state.mu.Unlock()

	if request.NowMicros < state.lastNow {
		return fallback(fact, ReasonClockRegression)
	}
	debt := state.debt
	if elapsed := uint64(request.NowMicros - state.lastNow); debt > 0 && elapsed > 0 {
		if elapsed >= ceilDivide(debt, request.Limit.RatePerSecond) {
			debt = 0
		} else {
			debt -= elapsed * request.Limit.RatePerSecond
		}
	}
	candidate := debt + costDebt
	state.debt = debt
	state.lastNow = request.NowMicros
	state.expiresAt = cappedTimestampAdd(request.NowMicros, stateTTLMicros(request.Limit))

	if candidate > capacityDebt {
		retry := ceilDivide(candidate-capacityDebt, request.Limit.RatePerSecond)
		fact.Kind = FactStaticDeny
		fact.Reason = ReasonGCRALimitApplied
		return Decision{
			Outcome: OutcomeDeny, Reason: ReasonGCRALimitApplied,
			RetryAfterMicros: int64(retry), NextEligibleMicros: cappedTimestampAdd(request.NowMicros, int64(retry)),
			Fact: fact,
		}
	}

	state.debt = candidate
	remaining := (capacityDebt - candidate) / microsPerSecond
	nextWait := uint64(0)
	if candidate+microsPerSecond > capacityDebt {
		nextWait = ceilDivide(candidate+microsPerSecond-capacityDebt, request.Limit.RatePerSecond)
	}
	fact.Kind = FactStaticAllow
	fact.Reason = ReasonGCRALimitApplied
	fact.Allowed = true
	return Decision{
		Outcome: OutcomeAllow, Reason: ReasonGCRALimitApplied, Remaining: remaining,
		NextEligibleMicros: cappedTimestampAdd(request.NowMicros, int64(nextWait)), Fact: fact,
	}
}

// lockedState returns a state with its mutex held. Every path locks Store.mu
// before keyState.mu so expiry cleanup and capacity admission cannot deadlock.
func (store *Store) lockedState(key string, now int64) (*keyState, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if state := store.states[key]; state != nil {
		state.mu.Lock()
		if !stateExpiredAt(now, state.lastNow, state.expiresAt) {
			return state, true
		}
		delete(store.states, key)
		state.mu.Unlock()
	}
	if len(store.states) >= store.maxKeys {
		store.removeExpiredLocked(now)
	}
	if len(store.states) >= store.maxKeys {
		return nil, false
	}
	state := &keyState{}
	state.mu.Lock()
	store.states[key] = state
	return state, true
}

func (store *Store) removeExpiredLocked(now int64) {
	for key, state := range store.states {
		state.mu.Lock()
		if stateExpiredAt(now, state.lastNow, state.expiresAt) {
			delete(store.states, key)
		}
		state.mu.Unlock()
	}
}

func stateExpiredAt(now, lastActivity, expiresAt int64) bool {
	return now >= expiresAt && now > lastActivity
}

func stateTTLMicros(limit Limit) int64 {
	drain := int64(ceilDivide(limit.Burst*microsPerSecond, limit.RatePerSecond))
	ttl := drain + minimumStateTTLMicros
	if ttl < minimumStateTTLMicros {
		return minimumStateTTLMicros
	}
	if ttl > maximumStateTTLMicros {
		return maximumStateTTLMicros
	}
	return ttl
}

func ceilDivide(numerator, denominator uint64) uint64 {
	return numerator/denominator + boolUint64(numerator%denominator != 0)
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func cappedTimestampAdd(timestamp, delta int64) int64 {
	if delta > MaxTimestampMicros-timestamp {
		return MaxTimestampMicros
	}
	return timestamp + delta
}

func factFor(key Key) DecisionFact {
	return DecisionFact{
		TenantID: key.tenantID, SiteID: key.siteID, RuleID: key.ruleID,
		KeyScope: key.scope, KeyDigest: key.Digest(), PolicyRevision: key.revision,
	}
}

func fallback(fact DecisionFact, reason ReasonCode) Decision {
	fact.Kind = FactFallback
	fact.Reason = reason
	return Decision{Outcome: OutcomeFallback, Reason: reason, Fact: fact}
}
