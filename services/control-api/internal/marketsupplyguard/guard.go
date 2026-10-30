// Package marketsupplyguard keeps a seller from taking an in-use market
// supply to zero online nodes (ADR 0012 §18.4):
// while the supply still has a normal subscriber, a seller action (disable a
// node, change the supply group's members) must leave at least one online
// available node. A node failing on its own is not a seller action, so a
// supply already at zero is not blocked.
//
// Online available: an enabled endpoint of the group's current revision on
// a node that is admin_state active, presence online (the offline worker
// flips it after NODE_PRESENCE_OFFLINE_AFTER), not isolated after failed
// config syncs and not taken out of resolution by a system serving hold.
//
// Normal subscriber: an active, unexpired local market subscription on the
// group, unless the cached market slot state (migration 429, refreshed by
// marketsupply.SlotStateSync) is fresh and says stopped (unpaid or a
// platform ticket) or cancelled. A missing or stale cache counts every
// subscription as normal: refuse while the market is unreachable.
package marketsupplyguard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxStateAge is how old the cached slot states may be and still let a
// stopped or cancelled subscription not count.
const MaxStateAge = 10 * time.Minute

// ErrInUse matches every *InUseError.
var ErrInUse = errors.New("market supply in use: keep at least one online node")

// InUseError says why the write was refused: after it, OnlineAvailable
// (always 0) nodes would serve NormalSubscriptions normal subscribers.
type InUseError struct {
	GroupID             uuid.UUID
	OnlineAvailable     int
	NormalSubscriptions int
}

func (e *InUseError) Error() string {
	return fmt.Sprintf("market supply %s in use by %d normal subscription(s): %d online available node(s) would remain",
		e.GroupID, e.NormalSubscriptions, e.OnlineAvailable)
}

func (e *InUseError) Is(target error) bool { return target == ErrInUse }

// Snapshot is the online available count of the guarded supply groups
// before a write.
type Snapshot map[uuid.UUID]int

const lockKey = "cdnca.market-supply-guard/v1"

// Lock serialises guarded writes, so two writes cannot each leave one node
// and together leave none. Take it first in the transaction, before any node
// or line group lock: every guarded write does, so it cannot close a cycle.
// Snapshots take it again (advisory locks stack within a session).
func Lock(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
		return fmt.Errorf("lock market supply guard: %w", err)
	}
	return nil
}

// onlineAvailable counts the online available nodes of the group's current
// revision. Its aliases are its own: GROUP_ID may name a column of the
// enclosing query (NodeSnapshot), which an inner line_group would shadow.
const onlineAvailable = `(SELECT count(DISTINCT guard_endpoint.node_id) FROM node_line_groups guard_group
	JOIN node_line_endpoints guard_endpoint ON guard_endpoint.tenant_scope_id=guard_group.tenant_scope_id
	 AND guard_endpoint.line_group_id=guard_group.id AND guard_endpoint.config_revision=guard_group.current_revision AND guard_endpoint.enabled
	JOIN nodes guard_node ON guard_node.id=guard_endpoint.node_id AND guard_node.admin_state='active'
	JOIN node_presence guard_presence ON guard_presence.node_id=guard_node.id AND guard_presence.status='online'
	WHERE guard_group.id=GROUP_ID AND guard_group.deleted_at IS NULL
	  AND NOT EXISTS (SELECT 1 FROM node_isolation_states isolation WHERE isolation.node_id=guard_node.id AND isolation.status='isolated')
	  AND NOT EXISTS (SELECT 1 FROM node_serving_holds hold WHERE hold.node_id=guard_node.id AND hold.held))`

// GroupSnapshot is the snapshot of one market supply group before its
// members change.
func GroupSnapshot(ctx context.Context, tx pgx.Tx, groupID uuid.UUID) (Snapshot, error) {
	if err := Lock(ctx, tx); err != nil {
		return nil, err
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT `+groupOnline("$1"), groupID).Scan(&count); err != nil {
		return nil, fmt.Errorf("count market supply online nodes: %w", err)
	}
	return Snapshot{groupID: count}, nil
}

// NodeSnapshot is the snapshot of every market supply group the node is an
// enabled member of, before the node changes.
func NodeSnapshot(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) (Snapshot, error) {
	if err := Lock(ctx, tx); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT line_group.id, `+groupOnline("line_group.id")+`
		FROM node_line_groups line_group
		WHERE line_group.purpose='market_supply' AND line_group.deleted_at IS NULL AND EXISTS (
			SELECT 1 FROM node_line_endpoints endpoint WHERE endpoint.tenant_scope_id=line_group.tenant_scope_id
			 AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
			 AND endpoint.enabled AND endpoint.node_id=$1)`, nodeID)
	if err != nil {
		return nil, fmt.Errorf("read market supply groups of node: %w", err)
	}
	defer rows.Close()
	snapshot := Snapshot{}
	for rows.Next() {
		var id uuid.UUID
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		snapshot[id] = count
	}
	return snapshot, rows.Err()
}

// OnlineAvailable counts the online available nodes of a supply group
// (reported to the market with the inventory, ADR 0012 §24).
func OnlineAvailable(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, groupID uuid.UUID) (int, error) {
	var count int
	if err := q.QueryRow(ctx, `SELECT `+groupOnline("$1"), groupID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count market supply online nodes: %w", err)
	}
	return count, nil
}

func groupOnline(group string) string {
	return strings.ReplaceAll(onlineAvailable, "GROUP_ID", group)
}

// Verify recounts after the write (in the same transaction) and returns an
// *InUseError when a group went from online nodes to none while it has a
// normal subscriber.
func (s Snapshot) Verify(ctx context.Context, tx pgx.Tx) error {
	for groupID, before := range s {
		if err := check(ctx, tx, groupID, before, -1); err != nil {
			return err
		}
	}
	return nil
}

// CheckEmptying refuses removing every node of the group (a selection
// rejected before it reaches a write) as Verify would.
func CheckEmptying(ctx context.Context, tx pgx.Tx, groupID uuid.UUID) error {
	snapshot, err := GroupSnapshot(ctx, tx, groupID)
	if err != nil {
		return err
	}
	return check(ctx, tx, groupID, snapshot[groupID], 0)
}

// check: after < 0 recounts the group now.
func check(ctx context.Context, tx pgx.Tx, groupID uuid.UUID, before, after int) error {
	if before == 0 {
		return nil // already at zero: node failures, not this write
	}
	var online, normal int
	if err := tx.QueryRow(ctx, `SELECT `+groupOnline("$1")+`, `+normalSubscriptions, groupID, MaxStateAge.Seconds()).
		Scan(&online, &normal); err != nil {
		return fmt.Errorf("verify market supply group: %w", err)
	}
	if after >= 0 {
		online = after
	}
	if online == 0 && normal > 0 {
		return &InUseError{GroupID: groupID, OnlineAvailable: online, NormalSubscriptions: normal}
	}
	return nil
}

// normalSubscriptions counts the group's normal local market subscriptions
// ($1 group, $2 MaxStateAge in seconds). The local
// product name is "market:" + marketsupply.Key, the cache key.
const normalSubscriptions = `(SELECT count(*) FROM package_subscriptions subscription
	JOIN package_products product ON product.id=subscription.product_id
	WHERE product.deleted_at IS NULL AND product.spec ? 'market' AND product.spec->>'node_group_id'=$1::text
	  AND subscription.lifecycle_status='active' AND subscription.deleted_at IS NULL AND subscription.ends_at > now()
	  AND NOT (EXISTS (SELECT 1 FROM market_supply_slot_state_sync sync WHERE sync.fetched_at >= now() - make_interval(secs => $2))
	       AND EXISTS (SELECT 1 FROM market_supply_slot_states slot
	           WHERE 'market:' || slot.market_key = product.name AND slot.state IN ('stopped', 'cancelled'))))`
