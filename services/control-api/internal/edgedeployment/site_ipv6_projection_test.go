package edgedeployment

import "testing"

func TestSITE03IPv6ProjectionRequiresAuthoritativeAggregateTerminalState(t *testing.T) {
	for _, test := range []struct {
		name                       string
		total, succeeded, terminal int
		forceFailure               bool
		wantSuccess, wantReady     bool
	}{
		{name: "running", total: 3, succeeded: 2, terminal: 2},
		{name: "all healthy", total: 3, succeeded: 3, terminal: 3, wantSuccess: true, wantReady: true},
		{name: "partial failure", total: 3, succeeded: 2, terminal: 3, wantReady: true},
		{name: "all failed", total: 3, terminal: 3, wantReady: true},
		{name: "cancelled", total: 3, succeeded: 2, terminal: 2, forceFailure: true, wantReady: true},
		{name: "empty", forceFailure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotSuccess, gotReady := siteIPv6RolloutTerminal(
				test.total, test.succeeded, test.terminal, test.forceFailure,
			)
			if gotSuccess != test.wantSuccess || gotReady != test.wantReady {
				t.Fatalf("terminal=(%t,%t) want=(%t,%t)", gotSuccess, gotReady, test.wantSuccess, test.wantReady)
			}
		})
	}
}
