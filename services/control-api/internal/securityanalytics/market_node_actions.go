package securityanalytics

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Whole-node actions on market supply nodes (ADR 0012 §19.3, ML-23,
// migration 432): a node_event of a node in a hidden market supply line group
// (purpose='market_supply'), and an automatic defence L4/L5 verdict on such a
// node, are queued in the ingest transaction for internal/marketprobe to
// report to the market. A verdict on a market tenant's site also carries the
// tenant's market key and the site, so the market can count same-site
// actions (§19.4, U8). The client address is never queued.

// MarketNodeActionLevel is the lowest verdict level that acts on the whole
// node (L4 kernel ban, L5 XDP).
const MarketNodeActionLevel = 4

// EnableMarketNodeActions makes Ingest queue whole-node actions on market
// supply nodes. Call before the consumer starts.
func (ingestor *Ingestor) EnableMarketNodeActions() { ingestor.marketActions = true }

// queueMarketNodeAction queues one action of node in every market supply
// pool the node serves. It runs under a savepoint: a failure is logged and
// never undoes the ingest.
func (ingestor *Ingestor) queueMarketNodeAction(ctx context.Context, tx pgx.Tx, node uuid.UUID, at time.Time,
	source, kind string, level, count int64, tenant, site *uuid.UUID) {
	if !ingestor.marketActions {
		return
	}
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		slog.Warn("market node action not queued", "node_id", node, "error", err)
		return
	}
	if err := queueMarketNodeActionTx(ctx, savepoint, node, at, source, kind, level, count, tenant, site, ingestor.now()); err != nil {
		_ = savepoint.Rollback(ctx)
		slog.Warn("market node action not queued", "node_id", node, "kind", kind, "error", err)
		return
	}
	if err := savepoint.Commit(ctx); err != nil {
		slog.Warn("market node action not queued", "node_id", node, "error", err)
	}
}

func queueMarketNodeActionTx(ctx context.Context, tx pgx.Tx, node uuid.UUID, at time.Time, source, kind string, level, count int64,
	tenant, site *uuid.UUID, now time.Time) error {
	// The market key and pool of a market tenant's site (marketsupply keeps
	// one market_supply_limits row per market tenant subscription); such a
	// row goes only to that pool, where its grant is.
	var key, pool *string
	if tenant != nil && site != nil {
		err := tx.QueryRow(ctx, `SELECT market_key, node_pool_ref FROM market_supply_limits WHERE tenant_scope_id=$1
			ORDER BY updated_at DESC LIMIT 1`, *tenant).Scan(&key, &pool)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
	}
	var siteID *uuid.UUID
	if key != nil {
		siteID = site
	}
	_, err := tx.Exec(ctx, `INSERT INTO market_node_action_queue(node_id,node_pool_ref,occurred_at,source,kind,level,count,market_key,
			site_id,created_at)
		SELECT DISTINCT $1::uuid, line_group.id::text, $2::timestamptz, $3::text, $4::text, $5::smallint, $6::bigint, $7::text,
			$8::uuid, $9::timestamptz
		FROM node_line_groups line_group
		JOIN node_line_endpoints endpoint ON endpoint.tenant_scope_id=line_group.tenant_scope_id
		  AND endpoint.line_group_id=line_group.id AND endpoint.config_revision=line_group.current_revision
		WHERE line_group.purpose='market_supply' AND line_group.deleted_at IS NULL AND endpoint.node_id=$1
		  AND ($10::text IS NULL OR line_group.id::text=$10)`,
		node, at, source, kind, min(max(level, 0), 5), min(max(count, 1), 1_000_000), key, siteID, now, pool)
	return err
}
