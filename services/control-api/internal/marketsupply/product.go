package marketsupply

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	mspec "github.com/cdnca/cdnca/libs/marketproto/spec"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ensureProduct returns the hidden product for key. A purchase freezes its
// allocation, and a new purchase yields a new key, so the product never
// changes once written. It is never published, so no tenant can buy it.
func (s *Service) ensureProduct(ctx context.Context, actor serviceActor, key string, poolID uuid.UUID,
	g grant.Grant,
) (uuid.UUID, int64, error) {
	name := productPrefix + key
	var id uuid.UUID
	var revision int64
	err := s.pool.QueryRow(ctx, `SELECT id, revision FROM package_products
		WHERE lower(name)=lower($1) AND deleted_at IS NULL AND owner_scope_id=$2`, name, actor.scopeID).Scan(&id, &revision)
	if err == nil {
		return id, revision, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, 0, err
	}
	spec, err := productSpec(name, poolID, s.cfg.CNAMEDomain, g)
	if err != nil {
		return uuid.Nil, 0, err
	}
	id, revision = uuid.New(), 1
	now := s.now().UTC().Truncate(time.Microsecond)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{actor.scopeID}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO package_products (
				id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES ($1,$2,true,1000000,$3,1,$4,$4,$5,$5)`, id, name, spec, actor.userID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO package_product_versions (
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES ($1,1,$2,true,1000000,$3,false,$4,$5)`, id, name, spec, actor.userID, now); err != nil {
			return err
		}
		return audit.NewWithClock(s.pool, func() time.Time { return now }).Append(ctx, tx, audit.Event{
			ScopeID: actor.scopeID, ActorUserID: &actor.userID,
			Action: "package.product.create", ResourceType: "package_product", ResourceID: id.String(),
			RequestID: "market-" + key, Result: "success",
			// The catalog audit link trigger requires exactly this payload; the
			// market origin is recorded in the product spec instead.
			Payload: map[string]any{"revision": 1, "enabled": true},
		})
	})
	if err != nil {
		return uuid.Nil, 0, err
	}
	return id, revision, nil
}

func productSpec(name string, poolID uuid.UUID, cnameDomain string, g grant.Grant) ([]byte, error) {
	a := g.Allocation
	// An unselected limit is unlimited (-1). Realtime caps are the supply
	// total (display and package monitoring); nodes run the per node share
	// of market_supply_limits instead (limits.go). connections is the
	// package's concurrent request budget, bounded by the catalog (65535).
	capOrUnlimited := func(m mspec.Metric) int64 {
		if v, ok := g.Limits.Cap(m); ok {
			return v
		}
		return -1
	}
	connections := capOrUnlimited(mspec.MetricConcurrentRequests)
	if connections > 65535 {
		connections = 65535
	}
	spec := map[string]any{
		"name":          name,
		"description":   "节点市场订阅（自动生成，不上架）",
		"group_ids":     []uuid.UUID{},
		"node_group_id": poolID,
		"limits": map[string]any{
			"domains": capOrUnlimited(mspec.MetricDomains), "root_domains": -1, "connections": connections,
			"monthly_traffic_bytes": capOrUnlimited(mspec.MetricMonthlyTrafficBytes),
			"bandwidth_bps":         capOrUnlimited(mspec.MetricBandwidthPeakBPS),
			"http_ports":            a.HTTPPorts, "stream_ports": a.StreamPorts,
			"websocket": a.WebSocket, "http3": a.HTTP3,
			// The subscriber's rate limit becomes a local CC policy of this
			// tenant; the leaf checks what it may express (rateLimitFields).
			"custom_cc": true,
		},
		"prices": map[string]any{"currency": "CNY", "monthly_minor": 0, "quarterly_minor": 0, "yearly_minor": 0},
		"market": map[string]any{
			"subscription_path": g.SubscriptionPath, "node_pool_ref": g.NodePoolRef,
			"require_icp": g.Compliance.RequireICP, "require_kyc": g.Compliance.RequireKYC,
		},
		"enabled": true,
	}
	if cnameDomain != "" {
		spec["cname"] = map[string]any{"mode": "per_site", "domain": cnameDomain, "hostname": ""}
	}
	return json.Marshal(spec)
}

// grantSiteLimit is the hidden subscription's site limit: the domains limit,
// or -1 (unlimited) when the seller did not select it.
func grantSiteLimit(g grant.Grant) int64 {
	if v, ok := g.Limits.Cap(mspec.MetricDomains); ok {
		return v
	}
	return -1
}
