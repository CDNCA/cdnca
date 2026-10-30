//go:build integration

package nodepresence

import (
	"context"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
)

// TestMarketProbeRoleFollowsHeartbeats: each projected heartbeat records its
// market probe role (UNSPECIFIED clears it) and the inventory shows it.
func TestMarketProbeRoleFollowsHeartbeats(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is required")
	}
	ctx := context.Background()
	nodeID := seedPresenceNode(t, pool)
	store, err := NewStore(pool, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Microsecond)
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: "cdnca.role.heartbeats", MaxHeartbeatBytes: 1 << 20,
		MaxActiveDeployments: 128, MaxFutureSkew: time.Minute, MaxPastAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return base }
	inventory := NewInventory(pool, nil, time.Hour, time.Now, slog.Default())
	var scopeID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT scope_id FROM nodes WHERE id=$1`, nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	for sequence, test := range []struct {
		role agentv1.MarketProbeRole
		want string
	}{
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, MarketProbeRoleProbeOnly},
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, MarketProbeRoleJoinMarket},
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED, MarketProbeRoleDisabled},
		{agentv1.MarketProbeRole_MARKET_PROBE_ROLE_UNSPECIFIED, ""},
	} {
		heartbeat := validPresenceHeartbeat(1, uint64(sequence+1), base)
		heartbeat.Runtime.MarketProbe = test.role
		envelope, err := validator.Decode("cdnca.role.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
		if err != nil {
			t.Fatal(err)
		}
		projection, err := store.Project(ctx, envelope)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.ConfirmOnline(ctx, projection); err != nil {
			t.Fatal(err)
		}
		var stored *string
		if err := pool.QueryRow(ctx, `SELECT market_probe_role FROM node_presence WHERE node_id=$1`, nodeID).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		item, err := inventory.Get(ctx, scopeID, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		for label, got := range map[string]*string{"stored": stored, "inventory": item.Presence.MarketProbeRole} {
			if test.want == "" && got != nil || test.want != "" && (got == nil || *got != test.want) {
				t.Fatalf("%v: %s role = %v, want %q", test.role, label, got, test.want)
			}
		}
	}
}
