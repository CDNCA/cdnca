package nodeserving

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// ReinstallRetryWindow is how long after a reinstall (a node's second or
	// later initial enrollment) its failed deployments are republished.
	ReinstallRetryWindow = 6 * time.Hour
	// ReinstallRetryInterval separates two republications of one node and
	// scope (RetryNodeSync's notBefore).
	ReinstallRetryInterval = 10 * time.Minute
)

// ReinstallRedeliveryEvaluator: the
// enrollment of a reinstalled host resets its delivery state and republishes
// its scopes once, in the enrollment transaction (nodeidentity
// resetHostDeliveryStateTx, the same as reset-node-host-delivery). That
// republication can reach the new host before it can take it - no service
// ticket yet (installation_frozen), the node artifact set with the rule pack
// objects not installed yet (object not found) - and fail. For
// ReinstallRetryWindow after the reinstall, a scope whose newest deployment on
// the new host failed, with none in flight, is republished again every
// ReinstallRetryInterval, whatever disable_failed_sync_nodes says (NF04
// retries only nodes it holds).
type ReinstallRedeliveryEvaluator struct {
	store   *Store
	retrier SyncRetrier
}

func NewReinstallRedeliveryEvaluator(store *Store, retrier SyncRetrier) *ReinstallRedeliveryEvaluator {
	return &ReinstallRedeliveryEvaluator{store: store, retrier: retrier}
}

func (evaluator *ReinstallRedeliveryEvaluator) Evaluate(ctx context.Context) error {
	if evaluator == nil || evaluator.store == nil || evaluator.retrier == nil {
		return ErrInvalidInput
	}
	var now time.Time
	if err := evaluator.store.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	rows, err := evaluator.store.pool.Query(ctx, `WITH reinstalled AS (
			SELECT node_id FROM node_certificates WHERE issuance_kind='initial'
			GROUP BY node_id HAVING count(*)>=2 AND max(issued_at)>$1
		), current_host AS (
			SELECT deployment.node_id,deployment.configuration_scope_id,deployment.action,deployment.state,
			       deployment.deadline_at,deployment.created_at,deployment.attempt
			FROM node_deployments deployment
			JOIN reinstalled ON reinstalled.node_id=deployment.node_id
			JOIN nodes node ON node.id=deployment.node_id AND node.admin_state='active'
			WHERE deployment.state<>'cancelled' AND deployment.configuration_scope_id IS NOT NULL
			  AND `+edgedeployment.CurrentHostDeployment("deployment")+`
			  -- node artifact set deliveries have their own retry (artifactsetdist)
			  AND NOT EXISTS (SELECT 1 FROM configuration_artifacts node_artifact
			      WHERE node_artifact.config_version_id=deployment.config_version_id
			        AND node_artifact.media_type=ANY($2::text[]))
		), latest AS (
			SELECT DISTINCT ON (node_id,configuration_scope_id) * FROM current_host
			ORDER BY node_id,configuration_scope_id,created_at DESC,attempt DESC
		)
		SELECT latest.node_id,latest.configuration_scope_id FROM latest
		WHERE (latest.state IN ('failed','rollback_failed') OR latest.state='reverted' AND latest.action='apply')
		  AND NOT EXISTS (SELECT 1 FROM current_host running
		      WHERE running.node_id=latest.node_id AND running.configuration_scope_id=latest.configuration_scope_id
		        AND running.state NOT IN ('healthy','failed','reverted','rollback_failed') AND running.deadline_at>=$3)
		ORDER BY 1,2`, now.Add(-ReinstallRetryWindow), []string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment}, now)
	if err != nil {
		return err
	}
	pairs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]uuid.UUID, error) {
		var pair [2]uuid.UUID
		return pair, row.Scan(&pair[0], &pair[1])
	})
	if err != nil {
		return err
	}
	var first error
	for _, pair := range pairs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := evaluator.retrier.RetryNodeSync(ctx, pair[0], pair[1], now.Add(-ReinstallRetryInterval)); err != nil && first == nil {
			first = err
		}
	}
	return first
}
