package edgestatus

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/jackc/pgx/v5"
)

// StatusRefusalAuditAction is written when a refused status ends its
// deployment.
const StatusRefusalAuditAction = "node.deployment.status_refused"

// Refusal reason codes (migration 477 node_deployment_status_refusals).
const (
	RefusalBindingConflict   = "status_binding_conflict"
	RefusalInvalidTransition = "status_invalid_transition"
)

// RefusalFinalizer ends a deployment whose status the controller refused for
// good. Store implements it; the processor calls it before dropping the
// message.
type RefusalFinalizer interface {
	FinalizeRefused(context.Context, Envelope, error) (bool, error)
}

// refusalReason maps the refusals that strand a deployment: the gateway has
// told the node the status is stored, so the node sends nothing again. Other
// permanent errors (malformed, unknown deployment, payload conflict) do not
// name a status this deployment's node could have sent.
func refusalReason(err error) (string, bool) {
	switch {
	case errors.Is(err, ErrBindingConflict):
		return RefusalBindingConflict, true
	case errors.Is(err, ErrInvalidTransition):
		return RefusalInvalidTransition, true
	}
	return "", false
}

// refusalEndsDeployment: only a deployment not yet activated, as for a
// timeout (348). An activated or reverting deployment may already run on the
// node; only its report ends it.
func refusalEndsDeployment(state string) bool {
	switch state {
	case "queued", "delivered", "agent_queued", "started", "staged", "prechecked":
		return true
	}
	return false
}

// FinalizeRefused records the refusal, fails the deployment and advances its
// rollout, as a failed node report would, so the node's per-scope queue moves
// on. It only acts when the status came from the deployment's own
// node and would have moved the deployment forward: a duplicate, stale or
// foreign status leaves it alone. It reports whether the deployment ended.
func (s *Store) FinalizeRefused(ctx context.Context, envelope Envelope, cause error) (bool, error) {
	reason, ok := refusalReason(cause)
	if !ok || ctx == nil || envelope.Status == nil || envelope.Status.Event == nil {
		return false, nil
	}
	ended := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		deployment, err := lockDeployment(ctx, tx, envelope.DeploymentID, envelope.Status.Attempt)
		if errors.Is(err, ErrDeploymentMissing) || errors.Is(err, ErrProjectionConflict) {
			return nil
		}
		if err != nil {
			return err
		}
		if deployment.nodeID != envelope.NodeID || deployment.configID != envelope.ConfigID ||
			!refusalEndsDeployment(deployment.state) {
			return nil
		}
		var maxSequence int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(transition_sequence),0) FROM deployment_status_events
			WHERE deployment_id=$1 AND attempt=$2`, envelope.DeploymentID, envelope.Status.Attempt).Scan(&maxSequence); err != nil {
			return fmt.Errorf("read refused deployment high water: %w", err)
		}
		if envelope.Status.TransitionSequence <= uint64(maxSequence) {
			return nil
		}
		// A skipped step may still be redelivered (a transient error naks
		// it while the next one is processed); only a status right after the
		// stored one is wrong for good. A gap stays bounded by the deadline
		// timeout (348).
		if reason == RefusalInvalidTransition && envelope.Status.TransitionSequence != uint64(maxSequence)+1 {
			return nil
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return fmt.Errorf("read database clock: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_status_refusals(
			deployment_id,attempt,previous_state,reason_code,status_event_id,transition_sequence,refused_at)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, envelope.DeploymentID, envelope.Status.Attempt, deployment.state, reason,
			envelope.EventID, int64(envelope.Status.TransitionSequence), now); err != nil {
			return fmt.Errorf("record deployment status refusal: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE edge_command_outbox SET status='cancelled',updated_at=$3
			WHERE deployment_id=$1 AND deployment_attempt=$2 AND status IN ('held','pending','failed')`,
			envelope.DeploymentID, envelope.Status.Attempt, now); err != nil {
			return fmt.Errorf("cancel refused deployment command: %w", err)
		}
		command, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=$4
			WHERE id=$1 AND attempt=$2 AND state=$3`, envelope.DeploymentID, envelope.Status.Attempt, deployment.state, now)
		if err != nil {
			return fmt.Errorf("fail refused deployment: %w", err)
		}
		if command.RowsAffected() != 1 {
			return ErrProjectionConflict
		}
		if err := edgedeployment.AdvanceRolloutAfterStatusTx(ctx, tx, deployment.rolloutID, now); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: deployment.scopeID, Action: StatusRefusalAuditAction,
			ResourceType: "node_deployment", ResourceID: envelope.DeploymentID.String(),
			RequestID: envelope.RequestID.String(), Result: "failure", ReasonCode: reason,
			ActorKind: audit.ActorSystem, ActorRef: "job:edge-status",
			Payload: map[string]any{"node_id": envelope.NodeID.String(), "attempt": envelope.Status.Attempt,
				"previous_state": deployment.state, "refused_state": envelope.Status.GetState().String(),
				"transition_sequence": envelope.Status.TransitionSequence, "event_id": envelope.EventID.String(),
				"reason_code": reason, "error": cause.Error()},
			OccurredAt: now}); err != nil {
			return fmt.Errorf("audit deployment status refusal: %w", err)
		}
		ended = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("finalize refused deployment status: %w", err)
	}
	return ended, nil
}
