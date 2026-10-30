package originroute

import (
	"testing"
	"time"
)

func TestEffectiveRetryPublishesStableResultAndReasonCodes(t *testing.T) {
	policy := testPolicy().Retry
	for _, failure := range []string{
		"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504",
	} {
		decision := PlanRetry(policy, AttemptState{
			Method: "GET", Attempt: 1, Elapsed: 100 * time.Millisecond, Failure: failure,
		})
		if !decision.Retry || decision.ResultCode != "retry" ||
			decision.Reason != "retryable_upstream_failure" || decision.Remaining != 800*time.Millisecond {
			t.Fatalf("failure %q decision = %+v", failure, decision)
		}
	}

	for _, test := range []struct {
		name  string
		state AttemptState
		want  string
	}{
		{name: "body", state: AttemptState{Method: "GET", Attempt: 1, HasRequestBody: true, Failure: "connect_error"}, want: "request_body_not_replayable"},
		{name: "streaming body", state: AttemptState{Method: "GET", Attempt: 1, StreamingBody: true, Failure: "connect_error"}, want: "request_body_not_replayable"},
		{name: "response started", state: AttemptState{Method: "GET", Attempt: 1, ResponseStarted: true, Failure: "read_timeout"}, want: "response_already_started"},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := PlanRetry(policy, test.state)
			if decision.Retry || decision.ResultCode != "stop" || decision.Reason != test.want {
				t.Fatalf("decision = %+v, want stop/%s", decision, test.want)
			}
		})
	}
}

func TestEffectiveL2FallbackIsDirectSingleAndWithinTotalBudget(t *testing.T) {
	policy := testPolicy()
	decision := Decision{PoolID: "l2-east", FallbackPoolID: "origin-a"}
	state := L2FallbackState{Attempt: AttemptState{
		Method: "GET", Attempt: 1, Elapsed: 850 * time.Millisecond, Failure: "http_503",
	}}

	fallback := PlanL2Fallback(policy, decision, state)
	if !fallback.Fallback || fallback.PoolID != "origin-a" ||
		fallback.Remaining != 50*time.Millisecond || fallback.ResultCode != "direct_origin_fallback" ||
		fallback.ReasonCode != "l2_retryable_failure" {
		t.Fatalf("fallback = %+v", fallback)
	}

	state.DirectOriginAttempted = true
	repeated := PlanL2Fallback(policy, decision, state)
	if repeated.Fallback || repeated.ResultCode != "stop" || repeated.ReasonCode != "direct_origin_attempt_limit_reached" {
		t.Fatalf("repeated fallback = %+v", repeated)
	}

	for _, test := range []struct {
		name  string
		state AttemptState
		want  string
	}{
		{name: "body", state: AttemptState{Method: "GET", Attempt: 1, HasRequestBody: true, Failure: "connect_error"}, want: "request_body_not_replayable"},
		{name: "response", state: AttemptState{Method: "GET", Attempt: 1, ResponseStarted: true, Failure: "http_502"}, want: "response_already_started"},
		{name: "budget", state: AttemptState{Method: "GET", Attempt: 1, Elapsed: 900 * time.Millisecond, Failure: "connect_timeout"}, want: "total_budget_exhausted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := PlanL2Fallback(policy, decision, L2FallbackState{Attempt: test.state})
			if result.Fallback || result.ResultCode != "stop" || result.ReasonCode != test.want {
				t.Fatalf("result = %+v, want stop/%s", result, test.want)
			}
		})
	}
}

func TestEffectiveL2FallbackDoesNotLoopOrAmplify(t *testing.T) {
	policy := testPolicy()
	decision, err := Match(policy, RequestFacts{
		Path: "/api/private", ClientIP: "203.0.113.9", ListenerID: "http", HopCount: policy.L2.MaxHops,
	})
	if err != nil {
		t.Fatal(err)
	}
	result := PlanL2Fallback(policy, decision, L2FallbackState{Attempt: AttemptState{
		Method: "GET", Attempt: 1, Failure: "connect_error",
	}})
	if result.Fallback || result.ResultCode != "stop" || result.ReasonCode != "l2_not_selected" {
		t.Fatalf("loop-guarded fallback = %+v", result)
	}

	invalid := PlanL2Fallback(policy, Decision{PoolID: "l2-east", FallbackPoolID: "l2-east"}, L2FallbackState{
		Attempt: AttemptState{Method: "GET", Attempt: 1, Failure: "connect_error"},
	})
	if invalid.Fallback || invalid.ReasonCode != "direct_origin_required" {
		t.Fatalf("non-origin fallback = %+v", invalid)
	}
}

func TestEffectiveL2CircuitAdmitsOneHalfOpenProbe(t *testing.T) {
	policy := testPolicy().L2
	now := time.Unix(1700000000, 0)
	state := CircuitState{Phase: CircuitOpen, ProbeAfter: now}

	first := PlanL2Attempt(policy, state, now)
	if !first.Allowed || !first.Probe || first.ResultCode != "l2_attempt" ||
		first.ReasonCode != "half_open_probe" || !first.State.ProbeInFlight {
		t.Fatalf("first probe = %+v", first)
	}
	second := PlanL2Attempt(policy, first.State, now)
	if second.Allowed || second.ResultCode != "direct_origin_fallback" ||
		second.ReasonCode != "half_open_probe_in_flight" {
		t.Fatalf("concurrent probe = %+v", second)
	}

	observed := ObserveL2(policy, first.State, true, now)
	if observed.ProbeInFlight {
		t.Fatalf("observed probe retained lease: %+v", observed)
	}
	next := PlanL2Attempt(policy, observed, now.Add(time.Millisecond))
	if !next.Allowed || !next.Probe {
		t.Fatalf("next recovery probe = %+v", next)
	}
}
