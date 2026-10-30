package entitlementguard

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ActiveDomainCount is the domains.count value the site guard compares with
// the lease limit, for the usage report (fix-usagereport).
func ActiveDomainCount(ctx context.Context, tx pgx.Tx) (int64, error) {
	return activeDomainCount(ctx, tx)
}

// AllocatedNodeCount is the nodes.count value the node guard compares with
// the lease limit, for the usage report (fix-usagereport).
func AllocatedNodeCount(ctx context.Context, tx pgx.Tx) (int64, error) {
	return allocatedNodeCount(ctx, tx)
}
