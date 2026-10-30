package nodeserving

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SyncRetrier republishes one scope to a node held for failed sync. It
// returns false when a retry for that node and scope is not yet due.
type SyncRetrier interface {
	RetryNodeSync(ctx context.Context, nodeID, scopeID uuid.UUID, notBefore time.Time) (bool, error)
}

type configSyncCandidate struct {
	nodeID, scopeID uuid.UUID
	active          bool
	held            bool
	reason          string
	revision        int64
	heldSince       *time.Time
	failingScopes   []uuid.UUID
	running         bool
}

// configSyncCandidates reads every node with a deployment or a config-sync
// hold, classifying each scope's newest non-cancelled deployment.
func (store *Store) configSyncCandidates(ctx context.Context) ([]configSyncCandidate, time.Time, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, time.Time{}, err
	}
	rows, err := tx.Query(ctx, `WITH latest AS (
			SELECT DISTINCT ON (deployment.node_id,deployment.configuration_scope_id)
			       deployment.node_id,deployment.configuration_scope_id,deployment.action,deployment.deadline_at,
			       -- A frozen node's refusal (fix-stoppolicy2) is no failed sync: the
			       -- node keeps serving and gets the scope again once it unfreezes.
			       CASE WHEN EXISTS (SELECT 1 FROM node_deployment_frozen_refusals frozen_refusal
			           WHERE frozen_refusal.deployment_id=deployment.id AND frozen_refusal.attempt=deployment.attempt)
			       THEN 'healthy' ELSE deployment.state END AS state
			FROM node_deployments deployment
			-- Node-side artifact deliveries (node artifact set segments and
			-- sets, migration 349) never hold the node's serving when they fail.
			WHERE deployment.state<>'cancelled' AND deployment.configuration_scope_id IS NOT NULL
			  AND NOT EXISTS (SELECT 1 FROM configuration_artifacts node_artifact
			      WHERE node_artifact.config_version_id=deployment.config_version_id
			        AND node_artifact.media_type=ANY($3::text[]))
			ORDER BY deployment.node_id,deployment.configuration_scope_id,deployment.created_at DESC,deployment.attempt DESC
		)
		SELECT node.id,node.scope_id,node.admin_state='active',
		       COALESCE(hold.held,false),COALESCE(hold.reason_code,''),COALESCE(hold.revision,0),hold.held_since,
		       COALESCE(array_agg(latest.configuration_scope_id ORDER BY latest.configuration_scope_id) FILTER (WHERE
		           latest.state IN ('failed','rollback_failed') OR latest.state='reverted' AND latest.action='apply' OR
		           latest.state NOT IN ('healthy','failed','reverted','rollback_failed') AND latest.deadline_at<$2),'{}'),
		       COALESCE(bool_or(latest.state NOT IN ('healthy','failed','reverted','rollback_failed')
		           AND latest.deadline_at>=$2),false)
		FROM nodes node
		LEFT JOIN node_serving_holds hold ON hold.node_id=node.id AND hold.source=$1
		LEFT JOIN latest ON latest.node_id=node.id
		WHERE latest.node_id IS NOT NULL OR hold.held
		GROUP BY node.id,node.scope_id,node.admin_state,hold.held,hold.reason_code,hold.revision,hold.held_since
		ORDER BY node.id`, SourceConfigSync, now, []string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment})
	if err != nil {
		return nil, time.Time{}, err
	}
	candidates, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (configSyncCandidate, error) {
		var item configSyncCandidate
		return item, row.Scan(&item.nodeID, &item.scopeID, &item.active, &item.held, &item.reason, &item.revision,
			&item.heldSince, &item.failingScopes, &item.running)
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return candidates, now, tx.Commit(ctx)
}

// holdWouldExceedLimit: in some current line group of the node, more than
// half of the admin-enabled nodes would be held by any source.
func (store *Store) holdWouldExceedLimit(ctx context.Context, nodeID uuid.UUID) (bool, error) {
	var exceeded bool
	err := store.pool.QueryRow(ctx, `SELECT COALESCE(bool_or(2*(counts.held+1) > counts.enabled),false) FROM (
			SELECT count(DISTINCT serving.node_id) FILTER (WHERE serving.admin_enabled) AS enabled,
			       count(DISTINCT serving.node_id) FILTER (WHERE serving.admin_enabled AND serving.held) AS held
			FROM node_line_groups line_group
			JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=line_group.tenant_scope_id
			 AND serving.line_group_id=line_group.id AND serving.config_revision=line_group.current_revision
			WHERE line_group.deleted_at IS NULL AND EXISTS (
				SELECT 1 FROM node_line_endpoints mine WHERE mine.tenant_scope_id=line_group.tenant_scope_id
				 AND mine.line_group_id=line_group.id AND mine.config_revision=line_group.current_revision
				 AND mine.node_id=$1 AND mine.enabled)
			GROUP BY line_group.tenant_scope_id,line_group.id) counts`, nodeID).Scan(&exceeded)
	return exceeded, err
}

// ConfigSyncEvaluator enforces disable_failed_sync_nodes (NF04).
type ConfigSyncEvaluator struct {
	store   *Store
	retrier SyncRetrier
}

// NewConfigSyncEvaluator: retrier may be nil, then held nodes recover only
// through a publication someone else starts.
func NewConfigSyncEvaluator(store *Store, retrier SyncRetrier) *ConfigSyncEvaluator {
	return &ConfigSyncEvaluator{store: store, retrier: retrier}
}

func (evaluator *ConfigSyncEvaluator) Evaluate(ctx context.Context) error {
	enabled, err := systemothersettings.DisableFailedSyncNodes(ctx, evaluator.store.pool)
	if err != nil {
		return err
	}
	candidates, now, err := evaluator.store.configSyncCandidates(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := evaluator.evaluate(ctx, enabled, candidate, now); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (evaluator *ConfigSyncEvaluator) evaluate(ctx context.Context, enabled bool, candidate configSyncCandidate, now time.Time) error {
	input := ConfigSyncInput{
		Enabled: enabled, NodeActive: candidate.active, Failing: len(candidate.failingScopes) > 0,
		Running: candidate.running, Held: candidate.held, Reason: candidate.reason,
	}
	if enabled && candidate.active && input.Failing && !candidate.held {
		over, err := evaluator.store.holdWouldExceedLimit(ctx, candidate.nodeID)
		if err != nil {
			return err
		}
		input.OverLimit = over
	}
	decision := DecideConfigSync(input)
	decision.Detail = map[string]any{"failing_scopes": len(candidate.failingScopes)}
	if decision.Held != candidate.held {
		_, err := evaluator.store.Apply(ctx, candidate.nodeID, candidate.scopeID, SourceConfigSync, candidate.revision, decision)
		return err
	}
	if !decision.Held || evaluator.retrier == nil || candidate.running || candidate.heldSince == nil ||
		now.Sub(*candidate.heldSince) < ConfigSyncRetryAfter {
		return nil
	}
	var first error
	for _, scopeID := range candidate.failingScopes {
		if _, err := evaluator.retrier.RetryNodeSync(ctx, candidate.nodeID, scopeID,
			now.Add(-ConfigSyncRetryAfter)); err != nil && first == nil {
			first = err
		}
	}
	return first
}
