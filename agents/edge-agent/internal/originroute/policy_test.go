package originroute

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testPolicy() Policy {
	return Policy{
		Schema:    SchemaV1,
		Revision:  1,
		TenantID:  "tenant-a",
		SiteID:    "site-a",
		VersionID: "route-v1",
		Node:      Node{ID: "l1-east-1", Region: "cn-east", Tier: TierL1},
		Listeners: []Listener{{ID: "http", Address: "127.0.0.1", Port: 18080}},
		Pools: []Pool{
			{
				ID: "origin-a", Kind: PoolOrigin,
				Endpoints: []Endpoint{
					{ID: "origin-a-v4", Host: "192.0.2.10", Port: 8080, Weight: 3},
					{ID: "origin-a-v6", Host: "2001:db8::10", Port: 8080, Weight: 1},
				},
			},
			{
				ID: "origin-b", Kind: PoolOrigin,
				Endpoints: []Endpoint{{ID: "origin-b-v4", Host: "198.51.100.30", Port: 8081, Weight: 1}},
			},
			{
				ID: "l2-east", Kind: PoolL2,
				Endpoints: []Endpoint{{ID: "l2-east-1", Host: "198.51.100.20", Port: 8080, NodeID: "l2-east-1", Weight: 1}},
			},
		},
		DefaultPoolID:         "origin-a",
		DefaultFallbackPoolID: "",
		Routes: []Route{
			{ID: "api", Priority: 10, PathPrefix: "/api", PoolID: "origin-b"},
			{
				ID: "private-api", Priority: 10, PathPrefix: "/api/private",
				NodeRegions: []string{"cn-east"}, ClientCIDRs: []string{"203.0.113.0/24"},
				PoolID: "l2-east", FallbackPoolID: "origin-a",
			},
		},
		Retry: RetryPolicy{
			Methods: []string{"HEAD", "GET"}, MaxAttempts: 3,
			ConnectTimeoutMS: 100, ReadTimeoutMS: 250, TotalBudgetMS: 900,
		},
		L2: L2Policy{
			FailureThreshold: 3, RecoveryThreshold: 2,
			ProbeIntervalMS: 10000, MaxHops: 2,
		},
	}
}

func TestParseStrictAndCanonical(t *testing.T) {
	policy := testPolicy()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Routes[0].ID != "private-api" || parsed.Retry.Methods[0] != "GET" {
		t.Fatalf("policy was not normalized deterministically: %+v", parsed)
	}

	shuffled := testPolicy()
	shuffled.Node.Region = "CN-EAST"
	shuffled.Pools[0].Endpoints[0], shuffled.Pools[0].Endpoints[1] = shuffled.Pools[0].Endpoints[1], shuffled.Pools[0].Endpoints[0]
	shuffled.Pools[0], shuffled.Pools[2] = shuffled.Pools[2], shuffled.Pools[0]
	shuffled.Routes[0], shuffled.Routes[1] = shuffled.Routes[1], shuffled.Routes[0]
	shuffled.Retry.Methods[0], shuffled.Retry.Methods[1] = shuffled.Retry.Methods[1], shuffled.Retry.Methods[0]
	left, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Canonical(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != string(right) {
		t.Fatalf("canonical output changed after input reordering:\n%s\n%s", left, right)
	}

	unknown := append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	if _, err := Parse(unknown); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown field error=%v, expected %v", err, ErrInvalidPolicy)
	}
	if _, err := Parse(append(raw, []byte(" true")...)); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("trailing value error=%v, expected %v", err, ErrInvalidPolicy)
	}
	policy.Schema = "cdnca.edge.origin-route/v2"
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown schema error=%v, expected %v", err, ErrInvalidPolicy)
	}
}

func TestValidationRejectsUnsafeAndAmbiguousPolicy(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Policy)
		want   error
	}{
		{
			name: "route conflict",
			mutate: func(policy *Policy) {
				duplicate := policy.Routes[0]
				duplicate.ID = "duplicate-route"
				policy.Routes = append(policy.Routes, duplicate)
			},
			want: ErrConflict,
		},
		{
			name: "path injection",
			mutate: func(policy *Policy) {
				policy.Routes[0].PathPrefix = "/api\nreturn 200"
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "endpoint injection",
			mutate: func(policy *Policy) {
				policy.Pools[0].Endpoints[0].Host = "origin.test;return"
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "unsafe link local",
			mutate: func(policy *Policy) {
				policy.Pools[0].Endpoints[0].Host = "169.254.1.2"
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "non canonical cidr",
			mutate: func(policy *Policy) {
				policy.Routes[1].ClientCIDRs = []string{"203.0.113.7/24"}
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "l2 without fallback",
			mutate: func(policy *Policy) {
				policy.Routes[1].FallbackPoolID = ""
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "l2 self route",
			mutate: func(policy *Policy) {
				policy.Pools[2].Endpoints[0].NodeID = policy.Node.ID
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "l2 to l2",
			mutate: func(policy *Policy) {
				policy.Node.Tier = TierL2
			},
			want: ErrInvalidPolicy,
		},
		{
			name: "unsafe retry method",
			mutate: func(policy *Policy) {
				policy.Retry.Methods = []string{"POST"}
			},
			want: ErrInvalidPolicy,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy()
			test.mutate(&policy)
			if _, err := Normalize(policy); !errors.Is(err, test.want) {
				t.Fatalf("Normalize() error=%v, expected %v", err, test.want)
			}
		})
	}
}

func TestMatchUsesPrioritySpecificityConditionsAndHopGuard(t *testing.T) {
	policy := testPolicy()
	decision, err := Match(policy, RequestFacts{
		Path: "/api/private/orders", ClientIP: "203.0.113.9",
		NodeRegion: "CN-EAST", ListenerID: "http",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RouteID != "private-api" || decision.PoolID != "l2-east" || !strings.Contains(decision.Explanation, "cidr_bits=24") {
		t.Fatalf("specific conditional route decision=%+v", decision)
	}

	decision, err = Match(policy, RequestFacts{
		Path: "/api/private/orders", ClientIP: "198.51.100.9",
		NodeRegion: "cn-east", ListenerID: "http",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RouteID != "api" || decision.PoolID != "origin-b" {
		t.Fatalf("CIDR miss should use less-specific route: %+v", decision)
	}

	decision, err = Match(policy, RequestFacts{
		Path: "/other", ClientIP: "2001:db8::9", ListenerID: "http",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Defaulted || decision.PoolID != "origin-a" {
		t.Fatalf("default route decision=%+v", decision)
	}

	decision, err = Match(policy, RequestFacts{
		Path: "/api/private", ClientIP: "203.0.113.9",
		ListenerID: "http", HopCount: policy.L2.MaxHops,
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.PoolID != "origin-a" || decision.FallbackPoolID != "" || !strings.Contains(decision.Explanation, "loop_guard") {
		t.Fatalf("hop guard decision=%+v", decision)
	}

	if _, err := Match(policy, RequestFacts{Path: "/api", ClientIP: "bad", ListenerID: "http"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid client IP error=%v", err)
	}
}

func TestRetryPlanIsReplaySafeAndBounded(t *testing.T) {
	policy := testPolicy().Retry
	retryable := []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"}
	for _, failure := range retryable {
		decision := PlanRetry(policy, AttemptState{Method: "get", Attempt: 1, Elapsed: 100 * time.Millisecond, Failure: failure})
		if !decision.Retry || decision.Remaining != 800*time.Millisecond {
			t.Fatalf("failure=%s decision=%+v", failure, decision)
		}
	}

	tests := []struct {
		name  string
		state AttemptState
		want  string
	}{
		{"post", AttemptState{Method: "POST", Attempt: 1, Failure: "connect_error"}, "method_not_retryable"},
		{"body", AttemptState{Method: "GET", Attempt: 1, HasRequestBody: true, Failure: "connect_error"}, "request_body_not_replayable"},
		{"stream", AttemptState{Method: "GET", Attempt: 1, StreamingBody: true, Failure: "connect_error"}, "request_body_not_replayable"},
		{"started", AttemptState{Method: "GET", Attempt: 1, ResponseStarted: true, Failure: "read_timeout"}, "response_already_started"},
		{"attempts", AttemptState{Method: "GET", Attempt: 3, Failure: "http_503"}, "attempt_limit_reached"},
		{"budget", AttemptState{Method: "GET", Attempt: 1, Elapsed: 900 * time.Millisecond, Failure: "connect_error"}, "total_budget_exhausted"},
		{"status", AttemptState{Method: "GET", Attempt: 1, Failure: "http_500"}, "failure_not_retryable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := PlanRetry(policy, test.state)
			if decision.Retry || decision.Reason != test.want {
				t.Fatalf("decision=%+v, expected reason %s", decision, test.want)
			}
		})
	}
}

func TestL2CircuitOpensProbesAndRecovers(t *testing.T) {
	policy := testPolicy().L2
	now := time.Unix(1700000000, 0)
	state := CircuitState{}
	for index := 0; index < int(policy.FailureThreshold); index++ {
		var allowed bool
		state, allowed = AllowL2(policy, state, now)
		if !allowed {
			t.Fatalf("closed circuit rejected attempt %d", index)
		}
		state = ObserveL2(policy, state, false, now)
	}
	if state.Phase != CircuitOpen || !state.ProbeAfter.Equal(now.Add(10*time.Second)) {
		t.Fatalf("open state=%+v", state)
	}
	if next, allowed := AllowL2(policy, state, now.Add(9*time.Second)); allowed || next.Phase != CircuitOpen {
		t.Fatalf("open circuit admitted early probe: %+v allowed=%t", next, allowed)
	}
	state, allowed := AllowL2(policy, state, now.Add(10*time.Second))
	if !allowed || state.Phase != CircuitHalfOpen {
		t.Fatalf("probe state=%+v allowed=%t", state, allowed)
	}
	state = ObserveL2(policy, state, true, now.Add(10*time.Second))
	if state.Phase != CircuitHalfOpen || state.ConsecutiveSuccesses != 1 {
		t.Fatalf("first recovery state=%+v", state)
	}
	state = ObserveL2(policy, state, true, now.Add(11*time.Second))
	if state.Phase != CircuitClosed {
		t.Fatalf("recovered state=%+v", state)
	}
}

type testAddressInspector struct {
	addresses map[netip.Addr]bool
	err       error
}

func (inspector testAddressInspector) HasAddress(_ context.Context, address netip.Addr) (bool, error) {
	return inspector.addresses[address], inspector.err
}

func TestValidateLocalBindingsChecksIPv4AndIPv6(t *testing.T) {
	policy := testPolicy()
	policy.Pools[1].Endpoints[0].Host = "198.51.100.30"
	policy.Listeners[0].IngressSourceIPv4 = "127.0.0.1"
	policy.Listeners[0].IngressSourceIPv6 = "::1"
	inspector := testAddressInspector{addresses: map[netip.Addr]bool{
		netip.MustParseAddr("127.0.0.1"): true,
		netip.MustParseAddr("::1"):       true,
	}}
	if err := ValidateLocalBindings(context.Background(), policy, inspector); err != nil {
		t.Fatal(err)
	}
	delete(inspector.addresses, netip.MustParseAddr("::1"))
	if err := ValidateLocalBindings(context.Background(), policy, inspector); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("missing IPv6 source error=%v", err)
	}
	inspector.err = errors.New("inspection failed")
	if err := ValidateLocalBindings(context.Background(), policy, inspector); err == nil || !strings.Contains(err.Error(), "inspection failed") {
		t.Fatalf("inspection error=%v", err)
	}
}
