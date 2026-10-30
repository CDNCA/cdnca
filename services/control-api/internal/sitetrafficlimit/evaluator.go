package sitetrafficlimit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsageReader is the site's traffic in [from, to) (ClickHouse
// access_metering_facts_v1).
type UsageReader interface {
	SiteTraffic(ctx context.Context, tenantScopeID, siteID uuid.UUID, from, to time.Time) (uint64, error)
}

// Evaluator decides, for the enabled limits due for evaluation, whether a cap
// is reached, records the decision and republishes the scope when it changed.
type Evaluator struct {
	pool     *pgxpool.Pool
	usage    UsageReader
	auditor  *audit.Log
	now      func() time.Time
	interval time.Duration
	batch    int
}

func NewEvaluator(pool *pgxpool.Pool, usage UsageReader, interval time.Duration, batch int, now func() time.Time) (*Evaluator, error) {
	if pool == nil || usage == nil || interval <= 0 || batch < 1 || batch > 1000 {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &Evaluator{pool: pool, usage: usage, auditor: audit.New(pool), now: now, interval: interval, batch: batch}, nil
}

type dueLimit struct {
	scopeID, siteID uuid.UUID
	setting         Setting
	totalSince      *time.Time
	exceededPeriod  *string
	exceededStart   *time.Time
}

// RunOnce evaluates up to batch due limits; it reports whether any decision
// changed.
func (evaluator *Evaluator) RunOnce(ctx context.Context) (bool, error) {
	now := evaluator.now().UTC()
	rows, err := evaluator.pool.Query(ctx, `SELECT scope_id,site_id,daily_bytes,monthly_bytes,total_bytes,total_since,
		time_zone,exceeded_period,exceeded_period_start FROM site_traffic_limits
		WHERE enabled AND (evaluated_at IS NULL OR evaluated_at < $1) ORDER BY evaluated_at NULLS FIRST, site_id LIMIT $2`,
		now.Add(-evaluator.interval), evaluator.batch)
	if err != nil {
		return false, err
	}
	due, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (dueLimit, error) {
		var item dueLimit
		return item, row.Scan(&item.scopeID, &item.siteID, &item.setting.DailyBytes, &item.setting.MonthlyBytes,
			&item.setting.TotalBytes, &item.totalSince, &item.setting.TimeZone, &item.exceededPeriod, &item.exceededStart)
	})
	if err != nil {
		return false, err
	}
	changed := false
	var errs []error
	for _, item := range due {
		decided, err := evaluator.evaluate(ctx, item, now)
		if err != nil {
			errs = append(errs, fmt.Errorf("site %s: %w", item.siteID, err))
			continue
		}
		changed = changed || decided
	}
	return changed, errors.Join(errs...)
}

// Decide is the reached cap at now ("" none) and the start of its period,
// given the usage of each capped period.
func Decide(setting Setting, daily, monthly, total uint64, dayStart, monthStart time.Time, totalSince *time.Time) (string, time.Time) {
	switch {
	case setting.TotalBytes != nil && total >= uint64(*setting.TotalBytes) && totalSince != nil:
		return edgeconfig.SiteTrafficLimitTotal, *totalSince
	case setting.MonthlyBytes != nil && monthly >= uint64(*setting.MonthlyBytes):
		return edgeconfig.SiteTrafficLimitMonthly, monthStart
	case setting.DailyBytes != nil && daily >= uint64(*setting.DailyBytes):
		return edgeconfig.SiteTrafficLimitDaily, dayStart
	}
	return "", time.Time{}
}

func (evaluator *Evaluator) evaluate(ctx context.Context, item dueLimit, now time.Time) (bool, error) {
	location, err := time.LoadLocation(item.setting.TimeZone)
	if err != nil {
		return false, err
	}
	dayStart, monthStart := PeriodStarts(now, location)
	read := func(cap *int64, from time.Time) (uint64, error) {
		if cap == nil || !from.Before(now) {
			return 0, nil
		}
		return evaluator.usage.SiteTraffic(ctx, item.scopeID, item.siteID, from, now)
	}
	daily, err := read(item.setting.DailyBytes, dayStart)
	if err != nil {
		return false, err
	}
	monthly, err := read(item.setting.MonthlyBytes, monthStart)
	if err != nil {
		return false, err
	}
	var total uint64
	if item.totalSince != nil {
		if total, err = read(item.setting.TotalBytes, *item.totalSince); err != nil {
			return false, err
		}
	}
	period, start := Decide(item.setting, daily, monthly, total, dayStart, monthStart, item.totalSince)
	changed := false
	err = pgx.BeginFunc(ctx, evaluator.pool, func(tx pgx.Tx) error {
		if err := lockEdgeConfigurationScope(ctx, tx, item.scopeID); err != nil {
			return err
		}
		var fromRevision int64
		if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`, item.scopeID).Scan(&fromRevision); err != nil {
			return err
		}
		// The setting may have changed since the read: only decide on the
		// row as read (same caps, still enabled, same exceeded state).
		var current dueLimit
		var enabled bool
		err := tx.QueryRow(ctx, `SELECT enabled,daily_bytes,monthly_bytes,total_bytes,total_since,exceeded_period,exceeded_period_start
			FROM site_traffic_limits WHERE site_id=$1 FOR UPDATE`, item.siteID).Scan(&enabled, &current.setting.DailyBytes,
			&current.setting.MonthlyBytes, &current.setting.TotalBytes, &current.totalSince, &current.exceededPeriod, &current.exceededStart)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if !enabled || !sameCaps(current, item) {
			return nil
		}
		previous := ""
		if current.exceededPeriod != nil {
			previous = *current.exceededPeriod
		}
		samePeriod := previous == period && (period == "" || current.exceededStart != nil && current.exceededStart.Equal(start))
		if samePeriod {
			_, err := tx.Exec(ctx, `UPDATE site_traffic_limits SET evaluated_at=$2 WHERE site_id=$1`, item.siteID, now)
			return err
		}
		var periodValue, startValue, atValue any
		if period != "" {
			periodValue, startValue, atValue = period, start, now
		}
		if _, err := tx.Exec(ctx, `UPDATE site_traffic_limits SET evaluated_at=$2,exceeded_period=$3,
			exceeded_period_start=$4,exceeded_at=$5 WHERE site_id=$1`, item.siteID, now, periodValue, startValue, atValue); err != nil {
			return err
		}
		// The release reads the decision from site_traffic_limits; advance
		// the site so the scope's source revision moves (one system segment).
		if _, err := tx.Exec(ctx, `UPDATE sites SET revision=revision+1,updated_at=$2 WHERE id=$1 AND deleted_at IS NULL`,
			item.siteID, now); err != nil {
			return err
		}
		operation := "site.batch.enable"
		action := AuditRestored
		if period != "" {
			operation, action = "site.batch.disable", AuditExceeded
		}
		mode, err := edgeautopublish.RequestRepublicationTx(ctx, tx, edgeautopublish.RepublishRequest{
			ScopeID: item.scopeID, Trigger: edgepublish.SystemTriggerTrafficEnforcement, Operation: operation,
			SourceResourceID: item.siteID, SourceRequestID: "site-traffic-limit:" + item.siteID.String() + ":" + now.Format(time.RFC3339),
			FromRevision: fromRevision,
		})
		if err != nil {
			return fmt.Errorf("republish site traffic limit: %w", err)
		}
		changed = true
		return evaluator.auditor.Append(ctx, tx, audit.Event{
			ScopeID: item.scopeID, Action: action, ResourceType: "site", ResourceID: item.siteID.String(),
			RequestID: "site-traffic-limit-" + uuid.NewString(), Result: "success",
			Payload: map[string]any{
				"site_id": item.siteID.String(), "period": period, "previous_period": previous,
				"daily_bytes": daily, "monthly_bytes": monthly, "total_bytes": total,
				"changes":          map[string]any{"exceeded_period": map[string]any{"from": previous, "to": period}},
				"publication_mode": mode.Mode,
			},
		})
	})
	return changed, err
}

func sameCaps(left, right dueLimit) bool {
	equal := func(a, b *int64) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
	sameSince := left.totalSince == nil && right.totalSince == nil ||
		left.totalSince != nil && right.totalSince != nil && left.totalSince.Equal(*right.totalSince)
	return equal(left.setting.DailyBytes, right.setting.DailyBytes) && equal(left.setting.MonthlyBytes, right.setting.MonthlyBytes) &&
		equal(left.setting.TotalBytes, right.setting.TotalBytes) && sameSince
}
