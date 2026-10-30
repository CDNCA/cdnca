package nodeserving

import (
	"testing"
	"time"
)

func TestDeploymentTimesOutOnlyBeforeActivation(t *testing.T) {
	for state, want := range map[string]bool{
		"queued": true, "delivered": true, "agent_queued": true, "started": true, "staged": true, "prechecked": true,
		// The node may already run an activated or reverting deployment.
		"activated": false, "reverting": false,
		"healthy": false, "failed": false, "reverted": false, "rollback_failed": false, "cancelled": false, "": false,
	} {
		if got := DeploymentTimesOut(state); got != want {
			t.Errorf("DeploymentTimesOut(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestDeploymentTimeoutDueOneMinuteAfterDeadline(t *testing.T) {
	deadline := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		now  time.Time
		want bool
	}{
		{deadline.Add(-time.Hour), false},
		{deadline, false},
		{deadline.Add(DeploymentTimeoutGrace - time.Microsecond), false},
		{deadline.Add(DeploymentTimeoutGrace), true},
		{deadline.Add(time.Hour), true},
	} {
		if got := DeploymentTimeoutDue(deadline, test.now); got != test.want {
			t.Errorf("DeploymentTimeoutDue(deadline, deadline%+v) = %v, want %v", test.now.Sub(deadline), got, test.want)
		}
	}
	if DeploymentTimeoutGrace != time.Minute {
		t.Fatalf("grace = %v; migration 348 checks timed_out_at >= deadline_at + 1 minute", DeploymentTimeoutGrace)
	}
}
