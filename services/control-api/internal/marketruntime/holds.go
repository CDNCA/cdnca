package marketruntime

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/marketsupply"
	"github.com/google/uuid"
)

// Supply holds on the leaf (ADR 0012 §6.2 supply.hold, §6.3). The market is
// not a relay member, so the leaf pulls its hold snapshot over mTLS and
// applies it with marketsupply.RefreshLimits, which also re-splits the
// realtime caps over each pool's serving nodes now. Unreachable: the node
// counts are still refreshed, the last applied holds stay (no auto release).

// HoldSource is marketclient.Client.SupplyHolds.
type HoldSource interface {
	SupplyHolds(ctx context.Context) (marketclient.SupplyHolds, error)
}

// LimitApplier is marketsupply.Service.RefreshLimits.
type LimitApplier interface {
	RefreshLimits(ctx context.Context, holds map[string]marketsupply.Hold) (int, error)
}

// WithHolds turns on the hold and node share loop every interval.
func (r *Runtime) WithHolds(source HoldSource, applier LimitApplier, every time.Duration) *Runtime {
	if every <= 0 {
		every = 10 * time.Second
	}
	r.holdSource, r.limitApplier, r.holdEvery = source, applier, every
	return r
}

func (r *Runtime) holdLoop(ctx context.Context) {
	for {
		if err := r.refreshHolds(ctx); err != nil && ctx.Err() == nil {
			r.log.Warn("market supply limits refresh failed", "err", err)
		}
		if !sleep(ctx, r.holdEvery) {
			return
		}
	}
}

func (r *Runtime) refreshHolds(ctx context.Context) error {
	if r.identity().MemberID == uuid.Nil {
		return nil
	}
	var holds map[string]marketsupply.Hold
	if snapshot, err := r.holdSource.SupplyHolds(ctx); err != nil {
		r.log.Warn("market supply holds unavailable, keeping the last ones", "err", err)
	} else {
		holds = HoldMap(snapshot)
	}
	republished, err := r.limitApplier.RefreshLimits(ctx, holds)
	if republished > 0 {
		r.log.Info("market supply limits republished", "tenants", republished)
	}
	return err
}

// HoldMap keys a hold snapshot by marketsupply.HoldKey.
func HoldMap(snapshot marketclient.SupplyHolds) map[string]marketsupply.Hold {
	holds := make(map[string]marketsupply.Hold, len(snapshot.Items))
	for _, h := range snapshot.Items {
		holds[marketsupply.HoldKey(h.SubscriptionPath, h.NodePoolRef)] = marketsupply.Hold{Action: h.Action,
			ThrottleBPS: h.ThrottleBPS, Revision: h.Revision}
	}
	return holds
}
