//go:build integration

package marketsupply

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/libs/marketproto/spec"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupplyguard"
	"github.com/cdnca/cdnca/services/control-api/internal/node"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type staticSlotStates struct {
	items []marketclient.SlotState
	err   error
}

func (s *staticSlotStates) SlotStates(context.Context) ([]marketclient.SlotState, time.Time, error) {
	return s.items, time.Now(), s.err
}

// TestKeepOneOnlineNodeWhileNormalSubscribers: a
// two-node supply with a normal market subscriber. Disabling the offline
// node is allowed; disabling or removing the last online node is refused
// with the counts (node update, batch, group change, empty selection); with
// every subscription stopped for lack of payment it is allowed; a stale
// cache (market unreachable) refuses again; a supply already at zero online
// nodes is not blocked.
func TestKeepOneOnlineNodeWhileNormalSubscribers(t *testing.T) {
	pool := marketSupplyPool(t)
	ctx := t.Context()
	platform := platformScope(t, pool)
	seller := seedSeller(t, pool, platform)
	caps := capabilitySnapshot(t, map[agentv1.CapabilityName]uint32{agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE: 1})
	online := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.1", "CN", "电信", caps, false)
	offline := seedSupplyNode(t, pool, platform, seller.UserID, "8.8.5.2", "CN", "联通", caps, false)
	// The node write path re-checks the whole management settings object.
	exec(t, pool, `UPDATE nodes SET management_settings = management_settings || jsonb_build_object('auto_disable', jsonb_build_object(
		'bandwidth_limit', 0, 'bandwidth_unit', 'Mbps', 'traffic_enabled', true, 'traffic_from_day', 1,
		'traffic_from_time', '00:00:00', 'traffic_total_gb', 500, 'traffic_types', jsonb_build_array('outbound'),
		'excluded_interfaces', '', 'disabled_periods', '')) WHERE id = ANY($1::uuid[])`, []uuid.UUID{online, offline})
	exec(t, pool, `UPDATE node_presence SET status='offline', offline_since=now(), online_since=NULL WHERE node_id=$1`, offline)
	scheduler := nodescheduler.NewService(pool, time.Now)
	groups := NewSupplyGroups(pool, scheduler, staticFeatures{})
	group, err := groups.Put(ctx, seller, SupplyGroupWrite{Name: "ML18b", NodeIDs: []uuid.UUID{online, offline},
		IdempotencyKey: "ml18b-group", RequestID: "ml18b-group"})
	if err != nil {
		t.Fatal(err)
	}

	// One normal local market subscription on the group.
	svc := newTestService(t, pool, time.Now)
	path := []uuid.UUID{uuid.New()}
	g := grant.Grant{Schema: grant.SchemaV2, GrantID: uuid.New(), LeafMemberID: uuid.New(), SubscriptionPath: path,
		NodePoolRef: group.ID.String(), LoadThresholds: spec.DefaultLoadFloor,
		IssuedAt: time.Now().Add(-time.Hour).Unix(), NotBefore: time.Now().Add(-time.Hour).Unix(),
		NotAfter: time.Now().Add(24 * time.Hour).Unix()}
	if out := mustSync(t, svc, g); out[0].Action != "opened" {
		t.Fatalf("sync %+v", out)
	}

	nodes := node.NewService(node.NewStoreWithClock(pool, time.Now, nil))
	actor := node.Actor{UserID: seller.UserID, ScopeID: platform}
	revision := func(id uuid.UUID) int64 {
		t.Helper()
		var r int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM nodes WHERE id=$1`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	setState := func(id uuid.UUID, state, key string) error {
		_, err := nodes.UpdateNode(ctx, actor, node.UpdateRequest{ID: id, ExpectedRevision: revision(id),
			Fields: node.UpdateFields{AdminState: &state}, IdempotencyKey: key, RequestID: key})
		return err
	}
	wantInUse := func(err error, what string) {
		t.Helper()
		var inUse *marketsupplyguard.InUseError
		if !errors.As(err, &inUse) || inUse.OnlineAvailable != 0 || inUse.NormalSubscriptions != 1 || inUse.GroupID != group.ID {
			t.Fatalf("%s: want supply in use (0 online, 1 normal), got %v", what, err)
		}
	}

	// The last online node cannot be removed from the group (only the offline node left), nor the selection emptied.
	_, err = groups.Put(ctx, seller, SupplyGroupWrite{GroupID: group.ID, ExpectedRevision: group.Revision, Name: "ML18b",
		NodeIDs: []uuid.UUID{offline}, IdempotencyKey: "ml18b-remove", RequestID: "ml18b-remove"})
	if !errors.Is(err, nodescheduler.ErrMarketSupplyInUse) {
		t.Fatalf("remove the last online node: %v", err)
	}
	wantInUse(err, "remove")
	wantInUse(func() error {
		_, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: group.ID, ExpectedRevision: group.Revision, Name: "ML18b",
			IdempotencyKey: "ml18b-empty", RequestID: "ml18b-empty"})
		return err
	}(), "empty selection")

	// The offline node can be disabled (it is not what keeps the supply online).
	if err := setState(offline, node.StateDisabled, "ml18b-off-disable"); err != nil {
		t.Fatalf("disable the offline node: %v", err)
	}
	// The last online node cannot be disabled or drained.
	err = setState(online, node.StateDisabled, "ml18b-on-disable")
	if !errors.Is(err, node.ErrSupplyInUse) {
		t.Fatalf("disable the last online node: %v", err)
	}
	wantInUse(err, "disable")
	wantInUse(setState(online, node.StateDraining, "ml18b-on-drain"), "drain")
	batch, err := nodes.BatchAdminState(ctx, actor, node.BatchAdminStateRequest{AdminState: node.StateDisabled,
		Items: []node.BatchAdminStateItem{{ID: online, ExpectedRevision: revision(online)}}, IdempotencyKey: "ml18b-batch", RequestID: "ml18b-batch"})
	if err != nil || batch.Items[0].Status != "failed" || batch.Items[0].Error.Code != "supply_in_use" ||
		*batch.Items[0].Error.OnlineAvailable != 0 || *batch.Items[0].Error.NormalSubscriptions != 1 {
		t.Fatalf("batch disable: %+v %v", batch, err)
	}
	// Every subscription stopped for lack of payment: the seller may stop.
	sync := NewSlotStateSync(pool, &staticSlotStates{items: []marketclient.SlotState{
		{SubscriptionPath: path, NodePoolRef: group.ID.String(), State: "stopped"}}}, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := sync.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := setState(online, node.StateDisabled, "ml18b-on-disable-stopped"); err != nil {
		t.Fatalf("disable with every subscription stopped: %v", err)
	}
	exec(t, pool, `UPDATE nodes SET admin_state='active', revision=revision+1 WHERE id=$1`, online)

	// Market unreachable: the cache goes stale and counts the subscription as normal again.
	exec(t, pool, `UPDATE market_supply_slot_state_sync SET fetched_at=now() - interval '11 minutes'`)
	wantInUse(setState(online, node.StateDisabled, "ml18b-on-disable-stale"), "stale cache")
	failing := NewSlotStateSync(pool, &staticSlotStates{err: errors.New("market unreachable")}, time.Now,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := failing.Refresh(ctx); err == nil {
		t.Fatal("refresh against an unreachable market must fail")
	}
	wantInUse(setState(online, node.StateDisabled, "ml18b-on-disable-unreachable"), "unreachable market")

	// A cancelled subscription does not count either.
	cancelled := NewSlotStateSync(pool, &staticSlotStates{items: []marketclient.SlotState{
		{SubscriptionPath: path, NodePoolRef: group.ID.String(), State: "cancelled"}}}, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := cancelled.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM market_supply_slot_states WHERE state='cancelled'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cache replaced: %d %v", count, err)
	}
	// Normal again (fresh): the node going offline by itself is not blocked,
	// and a supply already at zero online nodes may be changed.
	normal := NewSlotStateSync(pool, &staticSlotStates{items: []marketclient.SlotState{
		{SubscriptionPath: path, NodePoolRef: group.ID.String(), State: "normal"}}}, time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := normal.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	exec(t, pool, `UPDATE node_presence SET status='offline', offline_since=now(), online_since=NULL WHERE node_id=$1`, online)
	if err := setState(online, node.StateDisabled, "ml18b-on-disable-offline"); err != nil {
		t.Fatalf("disable a node that is already offline: %v", err)
	}
	exec(t, pool, `UPDATE nodes SET admin_state='active', revision=revision+1 WHERE id=$1`, offline)
	if _, err := groups.Put(ctx, seller, SupplyGroupWrite{GroupID: group.ID, ExpectedRevision: group.Revision, Name: "ML18b",
		NodeIDs: []uuid.UUID{offline}, IdempotencyKey: "ml18b-remove-zero", RequestID: "ml18b-remove-zero"}); err != nil {
		t.Fatalf("change a supply already at zero online nodes: %v", err)
	}
}
