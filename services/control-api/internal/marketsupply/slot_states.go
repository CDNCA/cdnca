package marketsupply

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/grant"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SlotStateSource is the market's slot state list (marketclient.Client.SlotStates).
type SlotStateSource interface {
	SlotStates(ctx context.Context) ([]marketclient.SlotState, time.Time, error)
}

// SlotStateSync keeps the leaf's cache of market slot states (migration
// 429) that marketsupplyguard reads (ADR 0012 §18.4, ML-18): which local
// market subscriptions are stopped (unpaid, a platform ticket) or cancelled
// and so no longer oblige the seller to keep an online node. A failed fetch
// leaves the cache to go stale, and a stale cache counts every subscription
// as normal.
type SlotStateSync struct {
	pool   *pgxpool.Pool
	source SlotStateSource
	now    func() time.Time
	log    *slog.Logger
}

func NewSlotStateSync(pool *pgxpool.Pool, source SlotStateSource, now func() time.Time, log *slog.Logger) *SlotStateSync {
	return &SlotStateSync{pool: pool, source: source, now: now, log: log}
}

var errSlotState = errors.New("market slot state: invalid row")

// Refresh fetches the list once and replaces the cache with it.
func (s *SlotStateSync) Refresh(ctx context.Context) error {
	items, asOf, err := s.source.SlotStates(ctx)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(items))
	states := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		if len(item.SubscriptionPath) == 0 || item.NodePoolRef == "" ||
			item.State != "normal" && item.State != "stopped" && item.State != "cancelled" {
			return errSlotState
		}
		key := Key(grant.Grant{SubscriptionPath: item.SubscriptionPath, NodePoolRef: item.NodePoolRef})
		if seen[key] {
			continue
		}
		seen[key] = true
		keys, states = append(keys, key), append(states, item.State)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM market_supply_slot_states`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO market_supply_slot_states (market_key, state)
			SELECT * FROM unnest($1::text[], $2::text[])`, keys, states); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO market_supply_slot_state_sync (singleton, fetched_at, market_as_of)
			VALUES (true, $1, $2) ON CONFLICT (singleton) DO UPDATE SET fetched_at = EXCLUDED.fetched_at,
			market_as_of = EXCLUDED.market_as_of`, s.now().UTC(), asOf.UTC())
		return err
	})
}

// Run refreshes every interval until ctx ends.
func (s *SlotStateSync) Run(ctx context.Context, every time.Duration) error {
	for {
		if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("market slot state refresh failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(every):
		}
	}
}
