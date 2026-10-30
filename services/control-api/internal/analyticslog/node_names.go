package analyticslog

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NodeNameLookup names the nodes of one page of platform access rows
// (fix-logfields): ClickHouse keeps node_id only; the page shows the node's
// name. A node that is unknown (deleted) maps to no entry.
type NodeNameLookup interface {
	Lookup(ctx context.Context, ids []string) map[string]string
}

// SetNodeNameLookup makes platform access rows carry node_name.
func (handler *Handler) SetNodeNameLookup(lookup NodeNameLookup) { handler.nodeNames = lookup }

// lookupNodeNames: the canonical distinct node IDs of the rows and their
// names (nil without a lookup).
func (handler *Handler) lookupNodeNames(ctx context.Context, items []AccessLog) map[string]string {
	if handler.nodeNames == nil || len(items) == 0 {
		return nil
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if id, err := uuid.Parse(item.NodeID); err == nil && !seen[id.String()] {
			seen[id.String()] = true
			ids = append(ids, id.String())
		}
	}
	if len(ids) == 0 {
		return map[string]string{}
	}
	return handler.nodeNames.Lookup(ctx, ids)
}

func nodeNameOf(names map[string]string, nodeID string) string {
	id, err := uuid.Parse(nodeID)
	if err != nil {
		return ""
	}
	return names[id.String()]
}

type PostgresNodeNameLookup struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

func NewPostgresNodeNameLookup(pool *pgxpool.Pool, logger *slog.Logger) *PostgresNodeNameLookup {
	if logger == nil {
		logger = slog.Default()
	}
	return &PostgresNodeNameLookup{pool: pool, logger: logger}
}

const nodeNamesSQL = `SELECT id::text, name FROM nodes WHERE id=ANY($1::uuid[])`

func (lookup *PostgresNodeNameLookup) Lookup(ctx context.Context, ids []string) map[string]string {
	names := map[string]string{}
	if lookup == nil || lookup.pool == nil || len(ids) == 0 {
		return names
	}
	rows, err := lookup.pool.Query(ctx, nodeNamesSQL, ids)
	if err != nil {
		lookup.logger.WarnContext(ctx, "access log node names failed", "error", err)
		return names
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if rows.Scan(&id, &name) == nil {
			names[id] = name
		}
	}
	return names
}
