//go:build integration

package nodepresence

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestPackagingToolsetFollowsHeartbeats (migration 647): each
// projected heartbeat records the packaging toolset report; an Agent that
// does not report it (older than capability 83) clears it.
func TestPackagingToolsetFollowsHeartbeats(t *testing.T) {
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
	base := time.Now().UTC().Truncate(time.Second)
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: "cdnca.toolset.heartbeats", MaxHeartbeatBytes: 1 << 20,
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
	scripts, helper := strings.Repeat("a", 64), strings.Repeat("b", 64)
	refreshed := base.Add(-time.Minute)
	for sequence, status := range []*agentv1.PackagingToolsetStatus{
		{RefreshStatus: "none", ScriptsSha256: scripts, HelperSha256: helper},
		{RefreshStatus: "ok", RefreshVersion: "1.0.36", RefreshTime: timestamppb.New(refreshed), HelperStatus: "failed",
			HelperReason: "transient unit could not replace the packaging helper", ScriptsSha256: scripts, HelperSha256: helper},
		nil,
	} {
		heartbeat := validPresenceHeartbeat(1, uint64(sequence+1), base)
		heartbeat.Runtime.PackagingToolset = status
		envelope, err := validator.Decode("cdnca.toolset.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
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
		switch sequence {
		case 0:
			if *presence.ToolsetRefreshStatus != "none" || presence.ToolsetRefreshVersion != nil || presence.ToolsetRefreshedAt != nil ||
				*presence.ToolsetScriptsSHA256 != scripts || *presence.ToolsetHelperSHA256 != helper {
				t.Fatalf("never refreshed: %+v", presence)
			}
		case 1:
			if *presence.ToolsetRefreshStatus != "ok" || *presence.ToolsetRefreshVersion != "1.0.36" ||
				!presence.ToolsetRefreshedAt.Equal(refreshed) || *presence.ToolsetHelperStatus != "failed" ||
				!strings.HasPrefix(*presence.ToolsetHelperReason, "transient unit") || presence.ToolsetRefreshReason != nil {
				t.Fatalf("refreshed: %+v", presence)
			}
		default:
			if presence.ToolsetRefreshStatus != nil || presence.ToolsetScriptsSHA256 != nil || presence.ToolsetHelperStatus != nil {
				t.Fatalf("not reported: %+v", presence)
			}
		}
	}
	// The table refuses a shape the contract does not allow.
	if _, err := pool.Exec(ctx, `UPDATE node_presence SET toolset_refresh_status='ok' WHERE node_id=$1`, nodeID); err == nil {
		t.Fatal("ok without version and time accepted")
	}
}
