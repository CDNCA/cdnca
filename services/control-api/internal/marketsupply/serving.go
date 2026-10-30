package marketsupply

import (
	"context"

	"github.com/google/uuid"
)

// PoolSubscribers counts the normal subscribers of a supply group (ADR 0012
// §18.4): active, unexpired hidden market subscriptions on
// products of the group. A subscription the market stopped for unpaid usage
// or a platform ticket still counts until the market ends its grant (the
// leaf keeps no hold state yet): stricter, never looser.
func (s *SupplyGroups) PoolSubscribers(ctx context.Context, group uuid.UUID) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM package_subscriptions sub
		JOIN package_products product ON product.id = sub.product_id
		WHERE product.deleted_at IS NULL AND product.spec ? 'market' AND product.spec->>'node_group_id' = $1::text
		AND sub.deleted_at IS NULL AND sub.lifecycle_status = 'active' AND sub.ends_at > now()`, group).Scan(&n)
	return n, err
}

// PoolServing reports whether a pool still has normal subscribers
// (marketprobe: such a pool stays reported after its offers are delisted,
// since delisting stops new sales only).
func (s *SupplyGroups) PoolServing(ctx context.Context, ref string) (bool, error) {
	id, err := uuid.Parse(ref)
	if err != nil {
		return false, nil
	}
	n, err := s.PoolSubscribers(ctx, id)
	return n > 0, err
}
