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
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestTelemetryHealthFollowsHeartbeats (migration 592): each
// projected heartbeat records the telemetry pipeline's error code with its
// first/last seen time and count; a healthy heartbeat clears it, and the
// inventory (node API) returns it.
func TestTelemetryHealthFollowsHeartbeats(t *testing.T) {
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
		SubjectPrefix: "cdnca.telemetry.heartbeats", MaxHeartbeatBytes: 1 << 20,
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
	first := base.Add(-2 * time.Minute)
	for sequence, test := range []struct {
		health *agentv1.TelemetryHealth
		code   string
		count  int64
	}{
		{&agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first),
			LastSeenTime: timestamppb.New(first), Count: 1}, "L4_USAGE_LEDGER_FULL", 1},
		{&agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_LEDGER_FULL", FirstSeenTime: timestamppb.New(first),
			LastSeenTime: timestamppb.New(base), Count: 5}, "L4_USAGE_LEDGER_FULL", 5},
		{&agentv1.TelemetryHealth{ErrorCode: "L4_USAGE_ATTRIBUTION_PENDING", FirstSeenTime: timestamppb.New(base),
			LastSeenTime: timestamppb.New(base), Count: 1}, "L4_USAGE_ATTRIBUTION_PENDING", 1},
		{nil, "", 0},
	} {
		heartbeat := validPresenceHeartbeat(1, uint64(sequence+1), base)
		heartbeat.Runtime.Telemetry = test.health
		envelope, err := validator.Decode("cdnca.telemetry.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
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
		item, err := inventory.Get(ctx, scopeID, nodeID)
		if err != nil {
			t.Fatal(err)
		}
		presence := item.Presence
		if test.code == "" {
			if presence.TelemetryErrorCode != nil || presence.TelemetryFirstSeenAt != nil || presence.TelemetryLastSeenAt != nil ||
				presence.TelemetryCount != nil {
				t.Fatalf("heartbeat %d: healthy heartbeat left %+v", sequence+1, presence)
			}
			continue
		}
		if presence.TelemetryErrorCode == nil || *presence.TelemetryErrorCode != test.code || presence.TelemetryCount == nil ||
			*presence.TelemetryCount != test.count || presence.TelemetryFirstSeenAt == nil ||
			!presence.TelemetryFirstSeenAt.Equal(test.health.FirstSeenTime.AsTime()) || presence.TelemetryLastSeenAt == nil ||
			!presence.TelemetryLastSeenAt.Equal(test.health.LastSeenTime.AsTime()) {
			t.Fatalf("heartbeat %d: presence = %+v, want %s x%d", sequence+1, presence, test.code, test.count)
		}
	}
}
