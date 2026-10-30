package nodemonitoringoutbox

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/jackc/pgx/v5"
)

func (store *Store) reconcileActiveNodeMonitoring(ctx context.Context, limit int) error {
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		document, activatedAt, err := systemconfig.LoadActiveNodeMonitoring(ctx, tx)
		if err != nil || document.ActiveRevision == 0 {
			return err
		}
		// Match activation's serving-node target set, so a node first receives
		// monitoring right after its first configuration activation. Gateway
		// still requires the authenticated session's live monitoring capability
		// before delivery. Any existing outbox state is a fact, not a request to
		// retry it.
		rows, err := tx.Query(ctx, `SELECT `+TargetColumns+` FROM nodes node `+TargetJoin+`
			WHERE `+ServingNodePredicate+` AND NOT EXISTS (
				SELECT 1 FROM node_monitoring_command_outbox outbox
				WHERE outbox.node_id=node.id AND outbox.config_revision=`+TargetRevision+`
			)
			ORDER BY node.id LIMIT $2 FOR UPDATE OF node SKIP LOCKED`, document.ActiveRevision, limit)
		if err != nil {
			return fmt.Errorf("load missing node monitoring targets: %w", err)
		}
		targets, err := ScanTargets(rows)
		if err != nil {
			return err
		}
		for _, target := range targets {
			artifact, err := target.Artifact(document, activatedAt)
			if err != nil {
				return err
			}
			if err := store.EnqueueNodeMonitoringArtifact(ctx, tx, artifact); err != nil {
				return err
			}
		}
		return nil
	})
}
