package drainruntime

import (
	"errors"
	"strings"
	"testing"
)

func TestCompileIsDeterministicAndKeepsOldOnlyListenerUntilDrain(t *testing.T) {
	plan := validPlan(7)
	compiled, err := Compile(plan)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	reordered := plan
	reordered.Old.Listeners[0], reordered.Old.Listeners[1] = reordered.Old.Listeners[1], reordered.Old.Listeners[0]
	reordered.New.Listeners[0], reordered.New.Listeners[1] = reordered.New.Listeners[1], reordered.New.Listeners[0]
	reordered.HealthChecks[0], reordered.HealthChecks[1] = reordered.HealthChecks[1], reordered.HealthChecks[0]
	again, err := Compile(reordered)
	if err != nil {
		t.Fatalf("Compile(reordered) error = %v", err)
	}
	if compiled.Digest != again.Digest || string(compiled.CanonicalJSON) != string(again.CanonicalJSON) ||
		string(compiled.CandidateNginx) != string(again.CandidateNginx) || string(compiled.DrainingNginx) != string(again.DrainingNginx) {
		t.Fatal("equivalent plan order produced different artifacts")
	}
	candidate := string(compiled.CandidateNginx)
	draining := string(compiled.DrainingNginx)
	rollback := string(compiled.RollbackNginx)
	for _, expected := range []string{"127.0.0.1:18080", "127.0.0.1:18081", "127.0.0.1:18082", "127.0.0.1:19082"} {
		if !strings.Contains(candidate, expected) {
			t.Fatalf("candidate fixture missing %q\n%s", expected, candidate)
		}
	}
	if strings.Contains(candidate, "127.0.0.1:19080") {
		t.Fatal("candidate fixture retained replaced shared-bind upstream")
	}
	if strings.Contains(draining, "127.0.0.1:18081") {
		t.Fatal("draining fixture still accepts the old-only listener")
	}
	if !strings.Contains(rollback, "127.0.0.1:19080") || strings.Contains(rollback, "127.0.0.1:19082") {
		t.Fatal("rollback fixture does not contain only the old generation")
	}
}

func TestCompileAllowsRetiringTheLastListener(t *testing.T) {
	plan := validPlan(8)
	plan.New = Version{VersionID: "retired", Listeners: []Listener{}}
	plan.HealthChecks = []HealthCheck{}
	compiled, err := Compile(plan)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled.DrainingNginx), "listen ") || len(compiled.Plan.New.Listeners) != 0 ||
		len(compiled.Plan.HealthChecks) != 0 {
		t.Fatalf("last-listener retirement retained listeners or checks: %s", compiled.DrainingNginx)
	}
	if !strings.Contains(string(compiled.CanonicalJSON), `"listeners":[]`) {
		t.Fatalf("empty listener set must remain a JSON array: %s", compiled.CanonicalJSON)
	}
}

func TestCompileRejectsInstructionInjectionAndImplicitForce(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{"plan ID", func(plan *Plan) { plan.PlanID = "x; include /tmp/pwn;" }},
		{"listener ID", func(plan *Plan) { plan.New.Listeners[0].ID = "x\nserver{}" }},
		{"hostname", func(plan *Plan) { plan.New.Listeners[0].UpstreamAddress = "origin.internal" }},
		{"wildcard overlap", func(plan *Plan) {
			plan.New.Listeners[1].Address = "0.0.0.0"
			plan.New.Listeners[1].Port = plan.New.Listeners[0].Port
		}},
		{"HTTP CRLF", func(plan *Plan) { plan.HealthChecks[0].Path = "/health\r\nHost: injected" }},
		{"TCP newline", func(plan *Plan) { plan.HealthChecks[1].Payload = "ping\nquit" }},
		{"force without reason", func(plan *Plan) { plan.Drain.Force = ForceAfterDeadline }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan(1)
			test.mutate(&plan)
			if _, err := Compile(plan); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("Compile() error = %v, want ErrInvalidPlan", err)
			}
		})
	}
}

func validPlan(revision uint64) Plan {
	return Plan{
		SchemaVersion: SchemaVersionV1, PlanID: "drain-plan", Revision: revision,
		Old: Version{VersionID: "v1", Listeners: []Listener{
			{ID: "http", Protocol: ProtocolHTTP, Address: "127.0.0.1", Port: 18080, UpstreamAddress: "127.0.0.1", UpstreamPort: 19080},
			{ID: "tcp", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: 18081, UpstreamAddress: "127.0.0.1", UpstreamPort: 19081},
		}},
		New: Version{VersionID: "v2", Listeners: []Listener{
			{ID: "http", Protocol: ProtocolHTTP, Address: "127.0.0.1", Port: 18080, UpstreamAddress: "127.0.0.1", UpstreamPort: 19082},
			{ID: "tcp", Protocol: ProtocolTCP, Address: "127.0.0.1", Port: 18082, UpstreamAddress: "127.0.0.1", UpstreamPort: 19082},
		}},
		HealthTimeoutSeconds: 2,
		HealthChecks: []HealthCheck{
			{ListenerID: "http", Path: "/health", ExpectedStatus: 200, ExpectedBodyPrefix: "v2"},
			{ListenerID: "tcp", Payload: "health", ExpectedBodyPrefix: "v2:"},
		},
		Drain: DrainPolicy{MaxDrainSeconds: 3, Force: ForceNever},
	}
}
