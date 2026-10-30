package nodescheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type loadRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

type loadQuerier interface {
	Query(context.Context, string, ...any) (loadRows, error)
}

type poolLoadQuerier struct{ pool *pgxpool.Pool }

func (querier poolLoadQuerier) Query(ctx context.Context, query string, args ...any) (loadRows, error) {
	return querier.pool.Query(ctx, query, args...)
}

type PostgresLoadProvider struct{ queries loadQuerier }

func NewPostgresLoadProvider(pool *pgxpool.Pool) *PostgresLoadProvider {
	if pool == nil {
		return nil
	}
	return newPostgresLoadProvider(poolLoadQuerier{pool: pool})
}

func newPostgresLoadProvider(queries loadQuerier) *PostgresLoadProvider {
	return &PostgresLoadProvider{queries: queries}
}

func (provider *PostgresLoadProvider) Loads(
	ctx context.Context,
	tenantScopeID uuid.UUID,
	endpoints []Endpoint,
) (map[uuid.UUID]LoadSample, error) {
	if provider == nil || provider.queries == nil || ctx == nil || tenantScopeID == uuid.Nil ||
		len(endpoints) > maxEndpoints {
		return nil, ErrInvalidInput
	}
	result := make(map[uuid.UUID]LoadSample, len(endpoints))
	nodeIDs := make([]uuid.UUID, 0, len(endpoints))
	seenNodes := make(map[uuid.UUID]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if endpoint.ID == uuid.Nil {
			return nil, ErrInvalidInput
		}
		if endpoint.NodeID == uuid.Nil {
			continue
		}
		if _, exists := seenNodes[endpoint.NodeID]; !exists {
			seenNodes[endpoint.NodeID] = struct{}{}
			nodeIDs = append(nodeIDs, endpoint.NodeID)
		}
	}
	if len(nodeIDs) == 0 {
		return result, nil
	}
	rows, err := provider.queries.Query(ctx, `
		SELECT node.id,metric.active_connections,metric.observed_at
		FROM nodes node
		JOIN node_metric_latest metric ON metric.node_id=node.id
		WHERE node.scope_id=$1 AND node.id = ANY($2::uuid[])
		  AND metric.metrics_known AND metric.active_connections IS NOT NULL`,
		tenantScopeID, nodeIDs)
	if err != nil {
		return nil, fmt.Errorf("load node scheduling metrics: %w", err)
	}
	defer rows.Close()
	byNode := make(map[uuid.UUID]LoadSample, len(nodeIDs))
	for rows.Next() {
		var nodeID uuid.UUID
		var inflight int64
		var observedAt time.Time
		if err := rows.Scan(&nodeID, &inflight, &observedAt); err != nil {
			return nil, fmt.Errorf("scan node scheduling metrics: %w", err)
		}
		if nodeID == uuid.Nil || inflight < 0 || observedAt.IsZero() {
			return nil, ErrInvalidInput
		}
		if _, duplicate := byNode[nodeID]; duplicate {
			return nil, ErrInvalidInput
		}
		byNode[nodeID] = LoadSample{Inflight: inflight, ObservedAt: observedAt}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate node scheduling metrics: %w", err)
	}
	for _, endpoint := range endpoints {
		if sample, ok := byNode[endpoint.NodeID]; ok {
			result[endpoint.ID] = sample
		}
	}
	return result, nil
}
