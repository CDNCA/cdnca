package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestHeartbeatMarketProbeRoleValidation(t *testing.T) {
	gateway := newHeartbeatGateway(t, &fakeHeartbeatSink{}, nil)
	for _, test := range []struct {
		role  agentv1.MarketProbeRole
		valid bool
	}{
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED, true}, // older Agents
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, true},
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, true},
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED, true},
		{agentv1.MarketProbeRole(4), false},
		{agentv1.MarketProbeRole(-1), false},
	} {
		heartbeat := validHeartbeatRequest(1, 1, 2, uuid.NewString(), uuid.NewString()).GetHeartbeat()
		heartbeat.Runtime = &agentv1.EdgeRuntimeStatus{MarketProbe: test.role}
		err := gateway.validateHeartbeat(heartbeat, 1, 0, false, "")
		if (err == nil) != test.valid {
			t.Fatalf("role %d: err = %v, want valid=%v", test.role, err, test.valid)
		}
	}
}
