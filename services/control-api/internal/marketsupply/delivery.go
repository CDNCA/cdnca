package marketsupply

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Delivery of a leaf tenant's sites: the tenant publishes its own
// configuration to the nodes serving the seller's pool, next to the seller's
// own tenant on the same nodes (docs/architecture/multi-tenant-node-sharing.md
// §8). Its automatic publication policy names those nodes; every site write
// then queues a publication, and the edge publisher only lets the tenant onto
// a node that declares MULTI_TENANT_RUNTIME.
const (
	deliveryActivationTimeoutMS = 60_000
	deliveryObservationWindowMS = 30_000
	deliverySuccesses           = 3
	deliveryMaxAttempts         = 3
	deliveryDeadlineSeconds     = 1800
)

// ensureDelivery points the tenant's automatic publication at the pool's
// serving nodes. Policy facts are append-only, so a revision is added only
// when the node set changed; a pool with no serving node leaves the policy as
// it is rather than publishing nowhere.
func (s *Service) ensureDelivery(ctx context.Context, actor serviceActor, tenant tenantRef, poolID uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var nodes []uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT serving.node_id ORDER BY serving.node_id), '{}')
			FROM node_line_groups line_group
			JOIN node_line_endpoint_serving serving ON serving.tenant_scope_id=line_group.tenant_scope_id
			  AND serving.line_group_id=line_group.id AND serving.config_revision=line_group.current_revision
			  AND serving.serving
			JOIN nodes node ON node.id=serving.node_id AND node.admin_state='active'
			WHERE line_group.id=$1 AND line_group.tenant_scope_id=$2 AND line_group.deleted_at IS NULL`,
			poolID, actor.scopeID).Scan(&nodes); err != nil {
			return err
		}
		if len(nodes) == 0 {
			return nil
		}
		var mode string
		var current []uuid.UUID
		err := tx.QueryRow(ctx, `SELECT mode, node_ids FROM edge_automatic_publication_policy_facts
			WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, tenant.scopeID).Scan(&mode, &current)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil && mode == "automatic" && slices.Equal(current, nodes) {
			return nil
		}
		_, err = tx.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
			target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
			required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
			SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,$3,$4,$5,$6,$7,$8,$9,'market_pool_nodes',$10
			FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
			tenant.scopeID, nodes, deliveryActivationTimeoutMS, deliveryObservationWindowMS, deliverySuccesses,
			deliveryMaxAttempts, deliveryDeadlineSeconds, actor.scopeID, actor.userID, s.now().UTC())
		return err
	})
}
