package edgeautopublish

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const capabilityWatcherBatch = 100

// CapabilityWatcher turns a node's new capabilities (a Connect session that
// declares a different set) into republications of the scopes waiting on it:
// a refused publication (capability hold) newer than the scope's last
// publication, or a system republication that refused the node. The node's
// first observed set is recorded as its baseline.
type CapabilityWatcher struct {
	pool     *pgxpool.Pool
	interval time.Duration
	debounce time.Duration
	now      func() time.Time
	last     time.Time
}

func NewCapabilityWatcher(pool *pgxpool.Pool, interval time.Duration) (*CapabilityWatcher, error) {
	if pool == nil || interval < 0 || interval > time.Hour {
		return nil, ErrInvalidInput
	}
	return &CapabilityWatcher{pool: pool, interval: interval, debounce: edgepublish.SystemRepublicationDebounce, now: time.Now}, nil
}

// RunOnce sweeps at most once per interval (the runtime polls faster).
func (watcher *CapabilityWatcher) RunOnce(ctx context.Context) (bool, error) {
	if watcher == nil || ctx == nil {
		return false, ErrInvalidInput
	}
	now := watcher.now()
	if !watcher.last.IsZero() && now.Sub(watcher.last) < watcher.interval {
		return false, nil
	}
	watcher.last = now
	queued, err := watcher.SweepOnce(ctx)
	return queued > 0, err
}

// SweepOnce handles up to one batch of nodes whose latest session declares a
// capability set the watcher has not acted on, and returns the scopes queued.
func (watcher *CapabilityWatcher) SweepOnce(ctx context.Context) (int, error) {
	queued := 0
	err := pgx.BeginFunc(ctx, watcher.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT latest.node_id,latest.session_epoch,latest.capabilities_sha256
			FROM (SELECT DISTINCT ON (node_id) node_id,session_epoch,capabilities_sha256
			      FROM node_session_capabilities ORDER BY node_id,session_epoch DESC) latest
			JOIN nodes node ON node.id=latest.node_id
			LEFT JOIN edge_node_capability_marks mark ON mark.node_id=latest.node_id
			WHERE mark.node_id IS NULL OR mark.capabilities_sha256<>latest.capabilities_sha256
			ORDER BY latest.node_id LIMIT $1`, capabilityWatcherBatch)
		if err != nil {
			return err
		}
		type changed struct {
			nodeID uuid.UUID
			epoch  int64
			digest []byte
		}
		nodes, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (changed, error) {
			var item changed
			return item, row.Scan(&item.nodeID, &item.epoch, &item.digest)
		})
		if err != nil {
			return err
		}
		// Scopes are locked in scope order across the whole batch.
		byScope := map[uuid.UUID]uuid.UUID{}
		for _, node := range nodes {
			scopes, err := waitingScopes(ctx, tx, node.nodeID)
			if err != nil {
				return err
			}
			for _, scopeID := range scopes {
				if _, seen := byScope[scopeID]; !seen {
					byScope[scopeID] = node.nodeID
				}
			}
		}
		ordered := slices.SortedFunc(maps.Keys(byScope), func(left, right uuid.UUID) int { return bytes.Compare(left[:], right[:]) })
		for _, scopeID := range ordered {
			nodeID := byScope[scopeID]
			if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
				ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeCapability, SourceResourceID: nodeID,
				SourceRequestID: "node-capability/" + nodeID.String(), Debounce: watcher.debounce,
			}); err != nil {
				return err
			}
			queued++
		}
		for _, node := range nodes {
			if _, err := tx.Exec(ctx, `INSERT INTO edge_node_capability_marks(node_id,session_epoch,capabilities_sha256,observed_at)
				VALUES($1,$2,$3,clock_timestamp())
				ON CONFLICT (node_id) DO UPDATE SET session_epoch=EXCLUDED.session_epoch,
				  capabilities_sha256=EXCLUDED.capabilities_sha256,observed_at=EXCLUDED.observed_at`,
				node.nodeID, node.epoch, node.digest); err != nil {
				return err
			}
		}
		return nil
	})
	return queued, err
}

// waitingScopes are the scopes, in scope order (the lock order), that a
// capability change of nodeID can complete.
func waitingScopes(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT scope_id FROM (
			SELECT hold.scope_id FROM edge_capability_publication_holds hold
			-- An automatic publication that left the node out holds at its own
			-- revision (>=); a refused manual one at a revision never published.
			WHERE hold.refused_node_ids @> ARRAY[$1::uuid] AND hold.source_revision>=COALESCE((
			  SELECT max(publication.source_revision) FROM edge_config_publications publication
			  WHERE publication.configuration_scope_id=hold.scope_id AND publication.contract_version=1),0)
			UNION
			SELECT head.scope_id FROM edge_system_republication_heads head
			WHERE head.excluded_node_ids @> ARRAY[$1::uuid]) waiting
		ORDER BY scope_id`, nodeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

// RequestNodeReadyRepublicationsTx republishes, through the system channel,
// every scope waiting on nodeID (a capability hold naming it, or a system
// republication that excluded it). The IP library distributor calls it when
// a node first applies a library: declaring IP_INTEL did not complete those
// publications, having the library does. It returns the scopes queued.
func RequestNodeReadyRepublicationsTx(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, sourceRequestID string,
	debounce time.Duration) (int, error) {
	if ctx == nil || tx == nil || nodeID == uuid.Nil || sourceRequestID == "" {
		return 0, ErrInvalidInput
	}
	scopes, err := waitingScopes(ctx, tx, nodeID)
	if err != nil {
		return 0, err
	}
	for _, scopeID := range scopes {
		if _, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
			ScopeID: scopeID, Trigger: edgepublish.SystemTriggerNodeCapability, SourceResourceID: nodeID,
			SourceRequestID: sourceRequestID, Debounce: debounce,
		}); err != nil {
			return 0, err
		}
	}
	return len(scopes), nil
}
