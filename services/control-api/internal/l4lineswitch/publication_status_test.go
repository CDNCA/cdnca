package l4lineswitch

import "testing"

// fix-cfgflow3: a node that ignored the switch publication as an old release
// (it already runs a newer revision) ends without failing the rollout.
func TestWorkloadRolloutStateCountsIgnoredOldReleaseApart(t *testing.T) {
	for _, test := range []struct {
		name                                            string
		total, succeeded, superseded, failed, cancelled int
		want                                            string
	}{
		{name: "healthy and ignored", total: 3, succeeded: 2, superseded: 1, want: RolloutSucceeded},
		{name: "all ignored", total: 2, superseded: 2, want: RolloutSucceeded},
		{name: "one failed", total: 3, succeeded: 1, superseded: 1, failed: 1, want: RolloutFailed},
		{name: "still applying", total: 3, succeeded: 1, superseded: 1, want: RolloutPending},
		{name: "cancelled", total: 2, succeeded: 1, cancelled: 1, want: RolloutFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := workloadRolloutState(test.total, test.succeeded, test.superseded, test.failed, test.cancelled); got != test.want {
				t.Fatalf("workloadRolloutState() = %q, want %q", got, test.want)
			}
		})
	}
}
