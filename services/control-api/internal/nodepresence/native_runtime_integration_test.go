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
)

// TestNativeRuntimeFollowsHeartbeats (migration 468): each projected
// heartbeat records its native runtime outcome (absent clears it) and the
// inventory shows it per node.
func TestNativeRuntimeFollowsHeartbeats(t *testing.T) {
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
		SubjectPrefix: "cdnca.native.heartbeats", MaxHeartbeatBytes: 1 << 20,
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
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for sequence, test := range []struct {
		status *agentv1.NativeRuntimeStatus
		want   [4]string // state, release, previous_release, error_code
	}{
		{&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_SWITCHED, Release: b, PreviousRelease: a},
			[4]string{NativeRuntimeSwitched, b, a, ""}},
		{&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_UNCHANGED, Release: b},
			[4]string{NativeRuntimeUnchanged, b, "", ""}},
		{&agentv1.NativeRuntimeStatus{State: agentv1.NativeRuntimeState_NATIVE_RUNTIME_STATE_ROLLED_BACK, Release: b, PreviousRelease: a,
			ErrorCode: "RUNTIME_PRECHECK_FAILED"}, [4]string{NativeRuntimeRolledBack, b, a, "RUNTIME_PRECHECK_FAILED"}},
		{nil, [4]string{}},
	} {
		heartbeat := validPresenceHeartbeat(1, uint64(sequence+1), base)
		heartbeat.Runtime.NativeRuntime = test.status
		envelope, err := validator.Decode("cdnca.native.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
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
		for index, got := range []*string{presence.NativeRuntimeState, presence.NativeRuntimeRelease,
			presence.NativeRuntimePreviousRelease, presence.NativeRuntimeErrorCode} {
			if want := test.want[index]; want == "" && got != nil || want != "" && (got == nil || *got != want) {
				t.Fatalf("heartbeat %d field %d = %v, want %q", sequence+1, index, got, want)
			}
		}
	}
}
