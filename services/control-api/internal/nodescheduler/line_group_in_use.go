package nodescheduler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Other kinds of LineGroupInUseError: escalation package policies (B/C
// line), escalated site routes (current/next line) and the fallback chain's
// last-resort line group.
const (
	LineGroupUseEscalatePolicy     = "escalate_package_policy"
	LineGroupUseEscalateSiteRoute  = "escalate_site_route"
	LineGroupUseFallbackLastResort = "fallback_last_resort"
)

// LineGroupInUseError refuses deleting a line group live configuration still
// routes to: packages (spec node_group_id / backup_node_group_id, by name),
// active subscription snapshots (an expired one may still be renewed; a
// cancelled one serves nothing), sites, streams, and the Other kinds. It is an
// ErrReferenceConflict.
type LineGroupInUseError struct {
	Products      []string
	Subscriptions int
	Sites         int
	Streams       int
	Other         []string
}

func (e *LineGroupInUseError) Error() string {
	return fmt.Sprintf("%v: %d package(s), %d subscription(s), %d site(s), %d stream(s), other %v",
		ErrReferenceConflict, len(e.Products), e.Subscriptions, e.Sites, e.Streams, e.Other)
}

func (e *LineGroupInUseError) Is(target error) bool { return target == ErrReferenceConflict }

// ensureLineGroupUnused returns a *LineGroupInUseError when anything live
// still points at the scope's line group groupID.
func ensureLineGroupUnused(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID) error {
	inUse := &LineGroupInUseError{Products: []string{}, Other: []string{}}
	var policies, routes, lastResort bool
	if err := tx.QueryRow(ctx, `SELECT
		COALESCE((SELECT array_agg(product.name ORDER BY product.name, product.id) FROM package_products product
			WHERE product.deleted_at IS NULL AND $3 IN (product.spec->>'node_group_id', product.spec->>'backup_node_group_id')),
			'{}'::text[]),
		(SELECT count(*) FROM package_subscriptions subscription WHERE subscription.deleted_at IS NULL
			AND subscription.lifecycle_status='active'
			AND $3 IN (subscription.product_snapshot->'spec'->>'node_group_id',
				subscription.product_snapshot->'spec'->>'backup_node_group_id')),
		(SELECT count(*) FROM sites site WHERE site.deleted_at IS NULL AND site.node_group_id=$2),
		(SELECT count(*) FROM l4_forwards forward WHERE forward.deleted_at IS NULL
			AND $2 IN (forward.node_group_id, forward.backup_node_group_id)),
		EXISTS (SELECT 1 FROM escalate_package_policies policy
			WHERE (policy.b_owner_scope_id=$1 AND policy.b_line_group_id=$2)
			   OR (policy.c_owner_scope_id=$1 AND policy.c_line_group_id=$2)),
		EXISTS (SELECT 1 FROM escalate_site_routes route
			JOIN sites site ON site.scope_id=route.tenant_scope_id AND site.id=route.site_id AND site.deleted_at IS NULL
			WHERE (route.line_owner_scope_id=$1 AND route.line_group_id=$2)
			   OR (route.next_owner_scope_id=$1 AND route.next_group_id=$2)),
		EXISTS (SELECT 1 FROM fallback_chain_settings settings
			WHERE settings.last_resort_owner_scope_id=$1 AND settings.last_resort_line_group_id=$2)`,
		scopeID, groupID, groupID.String()).Scan(&inUse.Products, &inUse.Subscriptions, &inUse.Sites, &inUse.Streams,
		&policies, &routes, &lastResort); err != nil {
		return fmt.Errorf("check node line group references: %w", err)
	}
	for _, other := range []struct {
		used bool
		kind string
	}{{policies, LineGroupUseEscalatePolicy}, {routes, LineGroupUseEscalateSiteRoute}, {lastResort, LineGroupUseFallbackLastResort}} {
		if other.used {
			inUse.Other = append(inUse.Other, other.kind)
		}
	}
	if len(inUse.Products) == 0 && inUse.Subscriptions == 0 && inUse.Sites == 0 && inUse.Streams == 0 && len(inUse.Other) == 0 {
		return nil
	}
	return inUse
}
