package nodepresence

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestMarketProbeRoleProjection(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	validator := newTestValidator(t, now)
	for role, want := range map[agentv1.MarketProbeRole]string{
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED: "",
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY:  MarketProbeRoleProbeOnly,
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET: MarketProbeRoleJoinMarket,
		agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED:    MarketProbeRoleDisabled,
	} {
		heartbeat := validPresenceHeartbeat(1, 1, now)
		heartbeat.Runtime.MarketProbe = role
		if _, err := validator.Decode("cdnca.agent.heartbeats."+uuid.NewString(), marshalHeartbeat(t, heartbeat)); err != nil {
			t.Fatalf("role %v rejected: %v", role, err)
		}
		got := MarketProbeRole(role)
		if want == "" && got != nil || want != "" && (got == nil || *got != want) {
			t.Fatalf("role %v stored as %v, want %q", role, got, want)
		}
	}
}
