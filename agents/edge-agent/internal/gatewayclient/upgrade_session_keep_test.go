package gatewayclient

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// Every upgrade Recover error used to end the gateway session, the next session
// recovered the same command and failed the same way, about every 0.5 s. An upgrade
// error now keeps the session and the recovery is retried with a backoff.
func TestRunSessionKeepsSessionWhenUpgradeRecoveryFails(t *testing.T) {
	previous := upgradeRetryInitialDelay
	upgradeRetryInitialDelay = 20 * time.Millisecond
	t.Cleanup(func() { upgradeRetryInitialDelay = previous })

	runtime := &upgradeNegotiationProbeRuntime{}
	client := newUpgradeCapabilityClient(t, runtime, true)
	enabled := []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_EDGE_UPGRADE, ApiVersion: 1}}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	established, runErr, _ := runUpgradeNegotiationSession(t, ctx, client, enabled, nil)
	if !established || !sessionEndedByDeadline(ctx, runErr) {
		t.Fatalf("session = (established=%t, err=%v), want kept until the context ended", established, runErr)
	}
	if recoveries := runtime.recoveryCount(); recoveries < 2 {
		t.Fatalf("recoveries = %d, want the failed recovery retried", recoveries)
	}
}
