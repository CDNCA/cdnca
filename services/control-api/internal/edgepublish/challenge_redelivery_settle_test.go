package edgepublish

import "testing"

// fix-tails1028 §1: a redelivery whose deployment the node ignored as an old
// release (it already runs a newer revision of the scope) is skipped — the
// row goes and the sweep decides afresh — never a failed attempt.
func TestChallengeRedeliverySettlementSkipsIgnoredOldRelease(t *testing.T) {
	cases := []struct {
		name       string
		state      string
		superseded bool
		expired    bool
		want       challengeRedeliveryOutcome
	}{
		{"healthy receipt", "healthy", false, false, redeliveryDelivered},
		{"ignored old release", "failed", true, false, redeliverySkipped},
		{"ignored old release past its deadline", "failed", true, true, redeliverySkipped},
		{"real failure", "failed", false, false, redeliveryFailedAttempt},
		{"reverted", "reverted", false, false, redeliveryFailedAttempt},
		{"rollback failed", "rollback_failed", false, false, redeliveryFailedAttempt},
		{"missing deployment", "missing", false, false, redeliveryFailedAttempt},
		{"applying past its deadline", "applying", false, true, redeliveryExpired},
		{"still applying", "applying", false, false, redeliveryWaiting},
	}
	for _, tc := range cases {
		if got := challengeRedeliverySettlement(tc.state, tc.superseded, tc.expired); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
