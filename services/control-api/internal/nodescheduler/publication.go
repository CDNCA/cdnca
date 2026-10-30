package nodescheduler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// lockLineGroupUsingScopes locks, in scope order, the configuration row of
// every tenant scope with a live site on the group directly or through its
// package's primary or backup group, or its attack escalation line override
// (the carriage rule of migrations 287/460).
func lockLineGroupUsingScopes(ctx context.Context, tx pgx.Tx, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT edge_scope.scope_id FROM edge_configuration_scopes edge_scope
		WHERE edge_scope.scope_id IN (
			SELECT site.scope_id FROM sites site
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=site.scope_id
			 AND subscription.id=site.package_subscription_id AND subscription.deleted_at IS NULL
			LEFT JOIN escalate_site_routes route ON route.tenant_scope_id=site.scope_id AND route.site_id=site.id
			WHERE site.deleted_at IS NULL AND $1 IN (
			    site.node_group_id,
			    (subscription.product_snapshot->'spec'->>'node_group_id')::uuid,
			    (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid,
			    route.line_group_id, route.next_group_id,
			    -- community edition: no package, no own group -> the platform default
			    (SELECT platform_default.id FROM node_line_groups platform_default
			     WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL
			       AND site.node_group_id IS NULL AND site.package_subscription_id IS NULL))
			UNION
			-- Streams on the group by their own line (migration 499), else their package's.
			SELECT forward.scope_id FROM l4_forwards forward
			LEFT JOIN package_subscriptions subscription ON subscription.tenant_scope_id=forward.scope_id
			 AND subscription.id=forward.package_subscription_id AND subscription.deleted_at IS NULL
			WHERE forward.deleted_at IS NULL AND $1 IN (
			    COALESCE(forward.node_group_id, (subscription.product_snapshot->'spec'->>'node_group_id')::uuid),
			    COALESCE(forward.backup_node_group_id, (subscription.product_snapshot->'spec'->>'backup_node_group_id')::uuid),
			    (SELECT platform_default.id FROM node_line_groups platform_default
			     WHERE platform_default.is_platform_default AND platform_default.deleted_at IS NULL
			       AND forward.node_group_id IS NULL AND forward.package_subscription_id IS NULL)))
		ORDER BY edge_scope.scope_id FOR UPDATE OF edge_scope`, groupID)
	if err != nil {
		return nil, fmt.Errorf("lock line group publication scopes: %w", err)
	}
	scopes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("lock line group publication scopes: %w", err)
	}
	return scopes, nil
}

// enabledLineGroupNodes is the sorted set of nodes a revision sends traffic to.
func enabledLineGroupNodes(ctx context.Context, tx pgx.Tx, scopeID, groupID uuid.UUID, revision int64) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_line_endpoints
		WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 AND enabled AND node_id IS NOT NULL
		ORDER BY node_id`, scopeID, groupID, revision)
	if err != nil {
		return nil, fmt.Errorf("read line group nodes: %w", err)
	}
	nodes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("read line group nodes: %w", err)
	}
	return nodes, nil
}

// republishUsingScopes advances each using scope's source revision (one
// publication per revision) and queues its republication: through its
// automatic policy, or the system channel for any other scope. A
// burst of group edits leaves one live request per scope.
func (s *Service) republishUsingScopes(ctx context.Context, tx pgx.Tx, scopes []uuid.UUID, groupID uuid.UUID, requestID string) (int, error) {
	queued := 0
	for _, scopeID := range scopes {
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
			return 0, fmt.Errorf("advance line group scope revision: %w", err)
		}
		if s.publications == nil {
			continue
		}
		enqueued, err := s.publications.EnqueueLineGroupChangeTx(ctx, tx, scopeID, groupID, requestID)
		if err != nil {
			return 0, fmt.Errorf("enqueue line group publication: %w", err)
		}
		if enqueued {
			queued++
		}
	}
	return queued, nil
}
