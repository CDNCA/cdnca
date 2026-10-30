package cachefreshness

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecideRejectsPrivateRangeAndConditionalRequests(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	for _, test := range []struct {
		name    string
		request RequestFacts
		reason  ReasonCode
	}{
		{"authorization", RequestFacts{Method: "GET", Authorization: true}, ReasonPrivateBypass},
		{"cookie", RequestFacts{Method: "GET", Cookie: true}, ReasonPrivateBypass},
		{"request no-store", RequestFacts{Method: "GET", CacheControlNoStore: true}, ReasonPrivateBypass},
		{"request no-cache", RequestFacts{Method: "GET", CacheControlNoCache: true}, ReasonRequestBypass},
		{"range", RequestFacts{Method: "GET", Range: true}, ReasonRequestBypass},
		{"if-none-match", RequestFacts{Method: "GET", Conditional: true}, ReasonRequestBypass},
		{"post", RequestFacts{Method: "POST"}, ReasonRequestBypass},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision, err := Decide(validPolicy(), test.request, ObjectFacts{}, now)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if decision.Reason != test.reason || !decision.Bypass {
				t.Fatalf("decision = %#v, want bypass reason %q", decision, test.reason)
			}
		})
	}
}

func TestDecideFreshStaleAndHardBoundary(t *testing.T) {
	policy := validPolicy()
	stored := time.Unix(1_750_000_000, 0)
	request := RequestFacts{Method: "GET"}
	tests := []struct {
		name   string
		now    time.Time
		state  ObjectFacts
		reason ReasonCode
	}{
		{"fresh minus one", stored.Add(30*time.Second - time.Nanosecond), ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored}, ReasonFreshHit},
		{"stale starts", stored.Add(30 * time.Second), ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating}, ReasonStaleRevalidate},
		{"hard minus one", stored.Add(90*time.Second - time.Nanosecond), ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating}, ReasonStaleRevalidate},
		{"hard exact", stored.Add(90 * time.Second), ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating}, ReasonStaleHardLimit},
		{"hard plus one", stored.Add(90*time.Second + time.Nanosecond), ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating}, ReasonStaleHardLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := Decide(policy, request, test.state, test.now)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if decision.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", decision.Reason, test.reason)
			}
			if decision.PolicyVersion != policy.PolicyVersion || decision.SiteID != "site-a" || decision.TenantID != "tenant-a" {
				t.Fatalf("decision facts lost policy identity: %#v", decision)
			}
		})
	}
}

func TestDecideCoalescingAndFailureReasons(t *testing.T) {
	now := time.Unix(1_750_000_000, 0)
	tests := []struct {
		name       string
		state      ObjectFacts
		reason     ReasonCode
		cacheState FreshnessState
	}{
		{"cold miss", ObjectFacts{}, ReasonMiss, StateExpired},
		{"follower", ObjectFacts{Coalesced: true}, ReasonCoalescedFollower, StateFresh},
		{"lock timeout", ObjectFacts{Coalesced: true, LockTimedOut: true}, ReasonCoalesceTimeout, StateExpired},
		{"origin error", ObjectFacts{FailureClass: FailureError}, ReasonOriginError, StateExpired},
		{"unsafe response", ObjectFacts{Exists: true, Cacheable: false, StoredAt: now}, ReasonPrivateBypass, StateExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := Decide(validPolicy(), RequestFacts{Method: "GET"}, test.state, now)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if decision.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", decision.Reason, test.reason)
			}
			if decision.State != test.cacheState {
				t.Fatalf("state = %q, want %q", decision.State, test.cacheState)
			}
		})
	}
}

func TestDecideOnlyServesConfiguredFailureClasses(t *testing.T) {
	policy := validPolicy()
	policy.Enhancement.Expert.BackgroundUpdate = boolPointer(false)
	policy.Enhancement.Expert.FailureClasses = []FailureClass{FailureHTTP503}
	artifact, err := Compile(policy, testPaths())
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	if !strings.Contains(string(artifact.Nginx), "proxy_cache_use_stale http_503;") {
		t.Fatal("compiled nginx does not contain the configured failure class")
	}
	stored := time.Unix(1_750_000_000, 0)
	for _, failure := range []FailureClass{
		FailureUpdating, FailureError, FailureTimeout, FailureInvalidHeader,
		FailureHTTP500, FailureHTTP502, FailureHTTP503, FailureHTTP504,
	} {
		decision, err := Decide(policy, RequestFacts{Method: "GET"}, ObjectFacts{
			Exists: true, Cacheable: true, StoredAt: stored, FailureClass: failure,
		}, stored.Add(31*time.Second))
		if err != nil {
			t.Fatalf("Decide failure %q: %v", failure, err)
		}
		want := ReasonOriginError
		if failure == FailureHTTP503 {
			want = ReasonStaleRevalidate
		}
		if decision.Reason != want {
			t.Errorf("failure %q reason = %q, want %q", failure, decision.Reason, want)
		}
		wantState := StateExpired
		if failure == FailureHTTP503 {
			wantState = StateStale
		}
		if decision.State != wantState {
			t.Errorf("failure %q state = %q, want %q", failure, decision.State, wantState)
		}
	}
}

func TestDecideReportsStableFreshStaleAndExpiredStates(t *testing.T) {
	stored := time.Unix(1_750_000_000, 0)
	baseline := validPolicy()
	baseline.Mode = ModeBaseline
	baseline.Enhancement = EnhancementPolicy{Enabled: false}

	tests := []struct {
		name   string
		policy Policy
		now    time.Time
		object ObjectFacts
		want   string
	}{
		{
			name:   "fresh",
			policy: validPolicy(),
			now:    stored.Add(30*time.Second - time.Nanosecond),
			object: ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored},
			want:   "fresh",
		},
		{
			name:   "stale",
			policy: validPolicy(),
			now:    stored.Add(30 * time.Second),
			object: ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating},
			want:   "stale",
		},
		{
			name:   "hard expired",
			policy: validPolicy(),
			now:    stored.Add(90 * time.Second),
			object: ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored, FailureClass: FailureUpdating},
			want:   "expired",
		},
		{
			name:   "enhancement disabled",
			policy: baseline,
			now:    stored.Add(30 * time.Second),
			object: ObjectFacts{Exists: true, Cacheable: true, StoredAt: stored},
			want:   "expired",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := Decide(test.policy, RequestFacts{Method: "GET"}, test.object, test.now)
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			raw, err := json.Marshal(decision)
			if err != nil {
				t.Fatalf("marshal decision: %v", err)
			}
			var observed struct {
				State string `json:"state"`
			}
			if err := json.Unmarshal(raw, &observed); err != nil {
				t.Fatalf("decode decision state: %v", err)
			}
			if observed.State != test.want {
				t.Fatalf("state = %q, want %q; decision=%s", observed.State, test.want, raw)
			}
		})
	}
}
