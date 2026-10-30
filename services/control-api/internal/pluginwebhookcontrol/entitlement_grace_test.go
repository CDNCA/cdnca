package pluginwebhookcontrol

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
)

// Plugin webhook writes follow the publish rule: usable through the lease grace
// window even after the revocation list's 15-minute window has passed.
func TestEntitlementDecisionUsableThroughGrace(t *testing.T) {
	now := time.Date(2026, 10, 21, 3, 10, 0, 0, time.UTC)
	decision := entitlementguard.FeatureDecision{
		NotBefore:           now.Add(-2 * time.Hour),
		ExpiresAt:           now.Add(-30 * time.Minute),
		GraceUntil:          now.Add(30 * time.Minute), // 1-hour grace window
		RevocationIssuedAt:  now.Add(-time.Hour),
		RevocationExpiresAt: now.Add(-45 * time.Minute),
	}
	for _, check := range []struct {
		name     string
		boundary time.Time
		want     bool
	}{
		{"inside grace with stale revocation list", now, true},
		{"last instant of grace", decision.GraceUntil.Add(-time.Nanosecond), true},
		{"grace ended", decision.GraceUntil, false},
		{"after grace", decision.GraceUntil.Add(time.Minute), false},
		{"before lease not_before", decision.NotBefore.Add(-time.Second), false},
		{"before revocation issued", decision.RevocationIssuedAt.Add(-time.Second), false},
	} {
		if got := entitlementDecisionUsable(decision, check.boundary); got != check.want {
			t.Errorf("%s: usable = %t, want %t", check.name, got, check.want)
		}
	}
}
