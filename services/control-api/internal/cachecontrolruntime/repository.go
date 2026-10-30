package cachecontrolruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type queuedNode struct {
	ScopeID      uuid.UUID
	NodeID       uuid.UUID
	FirstCreated time.Time
}

type postgresRepository struct {
	pool *pgxpool.Pool
}

func (repository *postgresRepository) activeScopes(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT scope_id,min(created_at) AS first_created
		FROM cache_operations WHERE state IN ('queued','running')
		GROUP BY scope_id ORDER BY first_created,scope_id`)
	if err != nil {
		return nil, fmt.Errorf("list active cache operation scopes: %w", err)
	}
	defer rows.Close()
	var result []uuid.UUID
	for rows.Next() {
		var scopeID uuid.UUID
		var ignored time.Time
		if err := rows.Scan(&scopeID, &ignored); err != nil {
			return nil, fmt.Errorf("scan active cache operation scope: %w", err)
		}
		result = append(result, scopeID)
	}
	return result, rows.Err()
}

// automaticScopes are the scopes with an automatic (carrying-node) cache
// operation created within the follow-up window.
func (repository *postgresRepository) automaticScopes(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	rows, err := repository.pool.Query(ctx, `
		SELECT DISTINCT scope_id FROM cache_operations
		WHERE auto_nodes AND parent_operation_id IS NULL AND created_at >= $1
		ORDER BY scope_id`, now.Add(-24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("list automatic cache operation scopes: %w", err)
	}
	defer rows.Close()
	var result []uuid.UUID
	for rows.Next() {
		var scopeID uuid.UUID
		if err := rows.Scan(&scopeID); err != nil {
			return nil, fmt.Errorf("scan automatic cache operation scope: %w", err)
		}
		result = append(result, scopeID)
	}
	return result, rows.Err()
}

func (repository *postgresRepository) readyNodes(
	ctx context.Context,
	now time.Time,
	after *queuedNode,
	limit int,
) ([]queuedNode, error) {
	var afterCreated *time.Time
	var afterScope, afterNode *uuid.UUID
	if after != nil {
		afterCreated, afterScope, afterNode = &after.FirstCreated, &after.ScopeID, &after.NodeID
	}
	rows, err := repository.pool.Query(ctx, `
		WITH ready AS MATERIALIZED (
			SELECT node.scope_id,node.node_id,min(operation.created_at) AS first_created
			FROM cache_operation_nodes node
			JOIN cache_operations operation
			  ON operation.scope_id=node.scope_id AND operation.id=node.operation_id
			JOIN node_config_state config
			  ON config.configuration_scope_id=node.scope_id AND config.node_id=node.node_id
			WHERE node.state='queued' AND node.next_attempt_at<=$1
			  AND operation.state IN ('queued','running')
			  AND config.current_config_version_id IS NOT NULL
			  AND NOT config.reconciliation_required
			GROUP BY node.scope_id,node.node_id
		)
		SELECT scope_id,node_id,first_created FROM ready
		WHERE $2::timestamptz IS NULL OR
		      (first_created,scope_id,node_id) > ($2::timestamptz,$3::uuid,$4::uuid)
		ORDER BY first_created,scope_id,node_id LIMIT $5`,
		now, afterCreated, afterScope, afterNode, limit)
	if err != nil {
		return nil, fmt.Errorf("list ready cache operation nodes: %w", err)
	}
	defer rows.Close()
	result := make([]queuedNode, 0, limit)
	for rows.Next() {
		var node queuedNode
		if err := rows.Scan(&node.ScopeID, &node.NodeID, &node.FirstCreated); err != nil {
			return nil, fmt.Errorf("scan ready cache operation node: %w", err)
		}
		result = append(result, node)
	}
	return result, rows.Err()
}
