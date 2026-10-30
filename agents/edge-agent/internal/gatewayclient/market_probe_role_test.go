package gatewayclient

import (
	"context"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestRuntimeStatusReportsMarketProbeRole(t *testing.T) {
	for _, role := range []agentv1.MarketProbeRole{
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED,
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY,
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET,
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED,
	} {
		client := &Client{}
		if err := WithRuntimeStatusProbe(RuntimeStatusProbe{
			OpenResty:       func(context.Context, string) error { return nil },
			MarketProbeRole: role,
		})(client); err != nil {
			t.Fatal(err)
		}
		if got := client.runtimeStatus(context.Background(), nil).GetMarketProbe(); got != role {
			t.Fatalf("heartbeat market_probe = %v, want %v", got, role)
		}
	}
}
