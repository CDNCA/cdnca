package marketsupply

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/marketproto/grant"
	mspec "github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Market supply limits on the leaf's nodes (ADR 0012 §6.2, §6.3; control
// migration 429 market_supply_limits). A grant's realtime caps are the supply
// total; every serving node of the pool gets ceil(total / serving nodes) (Q1).
// The market's supply.hold for the slot (HoldsForLeaf snapshot) adds stop
// (every request 503) or a monthly traffic throttle (bandwidth throttle_bps
// split the same way); pause is DNS only, nodes keep serving (§7.4). The row
// changes only when a value does, and every change republishes the tenant.

// Hold is the market's current hold on one supply slot (supply.hold).
type Hold struct {
	Action      string // stop, pause or throttle
	ThrottleBPS int64  // throttle only: the monthly traffic throttle, supply total
	Revision    int64
}

// LimitTotals are a grant's supply totals; 0 = not selected (unlimited).
type LimitTotals struct {
	BandwidthBPS, Connections, Requests, NewPerSecond, QPS int64
}

func grantTotals(g grant.Grant) LimitTotals {
	value := func(m mspec.Metric) int64 {
		v, _ := g.Limits.Cap(m)
		return v
	}
	return LimitTotals{BandwidthBPS: value(mspec.MetricBandwidthPeakBPS),
		Connections: value(mspec.MetricConcurrentConnections), Requests: value(mspec.MetricConcurrentRequests),
		NewPerSecond: value(mspec.MetricNewConnectionsPerSecond), QPS: value(mspec.MetricQPS)}
}

// ceilShare is ceil(total / nodes); 0 stays 0 (unlimited).
func ceilShare(total int64, nodes int) int64 {
	if total <= 0 {
		return 0
	}
	n := int64(nodes)
	return total/n + min(total%n, 1)
}

// NodeShare is one node's limits for totals split over nodes (≥ 1) under hold.
// concurrent_requests is the node's in-flight request budget, bounded by the
// node format (65535): a larger share is clamped there, which is stricter.
func NodeShare(subscriptionID uuid.UUID, totals LimitTotals, hold Hold, nodes int) edgeconfig.PackageConnectionLimit {
	share := edgeconfig.PackageConnectionLimit{SubscriptionID: subscriptionID.String(), Connections: -1,
		BandwidthBPS: ceilShare(totals.BandwidthBPS, nodes), MaxConnections: ceilShare(totals.Connections, nodes),
		NewPerSecond: ceilShare(totals.NewPerSecond, nodes), QPS: ceilShare(totals.QPS, nodes)}
	if totals.Requests > 0 {
		share.Connections = min(ceilShare(totals.Requests, nodes), 65535)
	}
	share.MaxConnections = min(share.MaxConnections, edgeconfig.MaxSubscriptionConnections)
	share.NewPerSecond = min(share.NewPerSecond, edgeconfig.MaxSubscriptionNewPerSecond)
	share.QPS = min(share.QPS, edgeconfig.MaxSubscriptionQPS)
	switch hold.Action {
	case string(mspec.ActionStop):
		share.Stopped = true
	case string(mspec.ActionThrottle):
		if throttled := ceilShare(hold.ThrottleBPS, nodes); throttled > 0 &&
			(share.BandwidthBPS == 0 || throttled < share.BandwidthBPS) {
			share.BandwidthBPS = throttled
		}
	}
	share.BandwidthBPS = min(share.BandwidthBPS, edgeconfig.MaxPackageBandwidthBPS)
	return share
}

// servingNodes counts the pool's serving nodes (node_line_endpoint_serving,
// the set delivery publishes to; nodes held out by availability are not).
func servingNodes(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, platform, poolID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(DISTINCT serving.node_id)
		FROM node_line_groups line_group
		JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=line_group.tenant_scope_id
		  AND serving.line_group_id=line_group.id AND serving.config_revision=line_group.current_revision
		  AND serving.serving
		JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
		WHERE line_group.id=$1 AND line_group.tenant_scope_id=$2 AND line_group.deleted_at IS NULL`,
		poolID, platform).Scan(&n)
	return n, err
}

type limitRow struct {
	totals LimitTotals
	hold   Hold
	nodes  int
	share  edgeconfig.PackageConnectionLimit
}

// applyLimits writes the subscription's market limits and republishes the
// tenant when its node share changed. totals nil keeps the stored totals (a
// hold or node count change); hold nil keeps the stored hold. A pool without
// a serving node keeps the row as it is. Returns whether it republished.
func (s *Service) applyLimits(ctx context.Context, platform, tenantScope, subscriptionID, poolID uuid.UUID,
	key, poolRef string, totals *LimitTotals, hold *Hold,
) (bool, error) {
	changed := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		nodes, err := servingNodes(ctx, tx, platform, poolID)
		if err != nil {
			return err
		}
		var current limitRow
		var holdAction *string
		found := true
		err = tx.QueryRow(ctx, `SELECT total_bandwidth_bps,total_connections,total_requests,total_new_per_second,total_qps,
				hold_action,hold_throttle_bps,hold_revision,serving_nodes,node_requests,node_bandwidth_bps,node_connections,
				node_new_per_second,node_qps,node_stopped
			FROM market_supply_limits WHERE package_subscription_id=$1 FOR UPDATE`, subscriptionID).Scan(
			&current.totals.BandwidthBPS, &current.totals.Connections, &current.totals.Requests,
			&current.totals.NewPerSecond, &current.totals.QPS, &holdAction, &current.hold.ThrottleBPS,
			&current.hold.Revision, &current.nodes, &current.share.Connections, &current.share.BandwidthBPS,
			&current.share.MaxConnections, &current.share.NewPerSecond, &current.share.QPS, &current.share.Stopped)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
		} else if err != nil {
			return err
		}
		if holdAction != nil {
			current.hold.Action = *holdAction
		}
		current.share.SubscriptionID = subscriptionID.String()
		next := current
		if totals != nil {
			next.totals = *totals
		}
		if hold != nil {
			next.hold = *hold
		}
		if nodes == 0 {
			if !found {
				return nil // nothing to split by yet; the next round retries
			}
			nodes = current.nodes
		}
		next.nodes = nodes
		next.share = NodeShare(subscriptionID, next.totals, next.hold, nodes)
		if found && next == current {
			return nil
		}
		var action *string
		if next.hold.Action != "" {
			action = &next.hold.Action
		}
		throttle := next.hold.ThrottleBPS
		if next.hold.Action != string(mspec.ActionThrottle) {
			throttle = 0
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO market_supply_limits (package_subscription_id,tenant_scope_id,market_key,
				node_pool_ref,total_bandwidth_bps,total_connections,total_requests,total_new_per_second,total_qps,hold_action,
				hold_throttle_bps,hold_revision,serving_nodes,node_requests,node_bandwidth_bps,node_connections,
				node_new_per_second,node_qps,node_stopped,updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
			ON CONFLICT (package_subscription_id) DO UPDATE SET total_bandwidth_bps=EXCLUDED.total_bandwidth_bps,
				total_connections=EXCLUDED.total_connections,total_requests=EXCLUDED.total_requests,
				total_new_per_second=EXCLUDED.total_new_per_second,total_qps=EXCLUDED.total_qps,
				hold_action=EXCLUDED.hold_action,hold_throttle_bps=EXCLUDED.hold_throttle_bps,
				hold_revision=EXCLUDED.hold_revision,serving_nodes=EXCLUDED.serving_nodes,
				node_requests=EXCLUDED.node_requests,node_bandwidth_bps=EXCLUDED.node_bandwidth_bps,
				node_connections=EXCLUDED.node_connections,node_new_per_second=EXCLUDED.node_new_per_second,
				node_qps=EXCLUDED.node_qps,node_stopped=EXCLUDED.node_stopped,updated_at=EXCLUDED.updated_at`,
			subscriptionID, tenantScope, key, poolRef, next.totals.BandwidthBPS, next.totals.Connections,
			next.totals.Requests, next.totals.NewPerSecond, next.totals.QPS, action, throttle, next.hold.Revision,
			next.nodes, next.share.Connections, next.share.BandwidthBPS, next.share.MaxConnections,
			next.share.NewPerSecond, next.share.QPS, next.share.Stopped, now); err != nil {
			return err
		}
		if found && next.share == current.share {
			return nil // totals, hold or node count moved, the node values did not
		}
		changed = true
		return s.republishLimits(ctx, tx, tenantScope, subscriptionID, next, now)
	})
	return changed, err
}

// republishLimits moves the subscription's sites (the site objects carry the
// limits) and asks the system channel for one immediate publication.
func (s *Service) republishLimits(ctx context.Context, tx pgx.Tx, tenantScope, subscriptionID uuid.UUID, row limitRow,
	now time.Time,
) error {
	var sites int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sites WHERE scope_id=$1 AND package_subscription_id=$2
		AND deleted_at IS NULL`, tenantScope, subscriptionID).Scan(&sites); err != nil || sites == 0 {
		return err // no site yet: its first publication reads the row
	}
	// Publication lock order: the scope's configuration row first.
	if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
		VALUES($1,1,clock_timestamp()) ON CONFLICT(scope_id) DO NOTHING`, tenantScope); err != nil {
		return err
	}
	var fromRevision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`,
		tenantScope).Scan(&fromRevision); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1, updated_at=$3
		WHERE scope_id=$1 AND package_subscription_id=$2 AND deleted_at IS NULL`, tenantScope, subscriptionID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	var siteID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM sites WHERE scope_id=$1 AND package_subscription_id=$2 AND deleted_at IS NULL
		ORDER BY id LIMIT 1`, tenantScope, subscriptionID).Scan(&siteID); err != nil {
		return err
	}
	requestID := fmt.Sprintf("market-limits:%s:%d:%d:%d", subscriptionID, row.hold.Revision, row.nodes, now.UnixNano())
	_, err = edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
		ScopeID: tenantScope, Trigger: edgepublish.SystemTriggerMarketLimits, SourceResourceID: siteID,
		SourceRequestID: requestID, FromRevision: fromRevision, Immediate: true,
	})
	return err
}

// applyGrantLimits writes the grant's totals (the stored hold is kept).
func (s *Service) applyGrantLimits(ctx context.Context, actor serviceActor, tenant tenantRef, subscriptionID,
	poolID uuid.UUID, key string, g grant.Grant,
) error {
	totals := grantTotals(g)
	_, err := s.applyLimits(ctx, actor.scopeID, tenant.scopeID, subscriptionID, poolID, key, g.NodePoolRef, &totals, nil)
	return err
}

// HoldKey is the market key (Key) of the slot a hold applies to.
func HoldKey(path []uuid.UUID, poolRef string) string {
	return Key(grant.Grant{SubscriptionPath: path, NodePoolRef: poolRef})
}

// RefreshLimits re-splits every market subscription over its pool's serving
// nodes now and, when holds is not nil (a fresh market snapshot keyed by
// HoldKey; a slot missing from it has no hold), applies the holds. With nil
// holds (market unreachable) the last hold stays in force (§6.3). Returns
// how many tenants were republished.
func (s *Service) RefreshLimits(ctx context.Context, holds map[string]Hold) (int, error) {
	actor, err := s.ensureActor(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := s.pool.Query(ctx, `SELECT package_subscription_id,tenant_scope_id,market_key,node_pool_ref
		FROM market_supply_limits ORDER BY package_subscription_id`)
	if err != nil {
		return 0, err
	}
	type slot struct {
		subscription, tenant uuid.UUID
		key, pool            string
	}
	slots, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (slot, error) {
		var v slot
		return v, row.Scan(&v.subscription, &v.tenant, &v.key, &v.pool)
	})
	if err != nil {
		return 0, err
	}
	republished := 0
	var errs []error
	for _, v := range slots {
		poolID, err := uuid.Parse(v.pool)
		if err != nil {
			continue
		}
		var hold *Hold
		if holds != nil {
			value := holds[v.key]
			hold = &value
		}
		changed, err := s.applyLimits(ctx, actor.scopeID, v.tenant, v.subscription, poolID, v.key, v.pool, nil, hold)
		if err != nil {
			errs = append(errs, fmt.Errorf("market limits %s: %w", v.key, err))
			continue
		}
		if changed {
			republished++
		}
	}
	return republished, errors.Join(errs...)
}
