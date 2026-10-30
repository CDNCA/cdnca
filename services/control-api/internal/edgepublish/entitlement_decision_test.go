package edgepublish

import (
	"testing"
	"time"
)

// Grace publishes like valid; expired, revoked and
// incoherent decisions are rejected.
func TestValidEntitlementDecisionAllowsGrace(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	base := EntitlementDecision{Allowed: true, LocallyVerified: true, LeaseSerial: 1, EvaluatedAt: now}
	for _, test := range []struct {
		name    string
		status  string
		inGrace bool
		want    bool
	}{
		{name: "valid", status: EntitlementStatusValid, want: true},
		{name: "grace", status: EntitlementStatusGrace, inGrace: true, want: true},
		{name: "grace without flag", status: EntitlementStatusGrace},
		{name: "valid flagged grace", status: EntitlementStatusValid, inGrace: true},
		{name: "expired", status: "expired"},
		{name: "revoked", status: "revoked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			decision := base
			decision.Status, decision.InGrace = test.status, test.inGrace
			if got := validEntitlementDecision(decision, now); got != test.want {
				t.Fatalf("validEntitlementDecision(%s) = %v, want %v", test.name, got, test.want)
			}
		})
	}
}
