package packageaddon

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EffectiveCounts never mutates the immutable base subscription. The additive
// projection is evaluated at the same clock as the consuming quota decision.
func EffectiveCounts(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time, domains, traffic int64) (int64, int64, error) {
	var installed bool
	if err := tx.QueryRow(ctx, `SELECT to_regprocedure('package_addon_effective_limits(uuid,timestamp with time zone)') IS NOT NULL`).Scan(&installed); err != nil {
		return 0, 0, err
	}
	if !installed {
		return domains, traffic, nil
	}
	var count, bytes int64
	err := tx.QueryRow(ctx, `SELECT (limits->>'domains')::bigint,(limits->>'monthly_traffic_bytes')::bigint FROM (SELECT package_addon_effective_limits($1,$2) AS limits) effective`, id, at).Scan(&count, &bytes)
	return count, bytes, err
}

func RenewalAddition(ctx context.Context, tx pgx.Tx, id uuid.UUID, period string) (int64, error) {
	months := int64(1)
	switch period {
	case "month":
	case "quarter":
		months = 3
	case "year":
		months = 12
	default:
		return 0, ErrInvalid
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('package_addon_assignments') IS NOT NULL`).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var value int64
	err := tx.QueryRow(ctx, `SELECT coalesce(sum((snapshot->>'monthly_price_minor')::numeric*amount*$2),0)::bigint FROM package_addon_assignments WHERE subscription_id=$1 AND revoked_at IS NULL`, id, months).Scan(&value)
	if value < 0 || value > 1000000000000000 {
		return 0, ErrInvalid
	}
	return value, err
}
