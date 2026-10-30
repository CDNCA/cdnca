package edgestatus

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/domaineventsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// enqueueDeploymentStatusEvent appends io.cdnca.deployment.v1.status_changed
// in the projection transaction. Only tenant-scope configuration rollouts are
// a tenant's deployment; a platform-scope rollout raises no tenant event.
func enqueueDeploymentStatusEvent(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, envelope Envelope,
	rolloutID uuid.UUID, state string) error {
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind FROM access_scopes WHERE id=$1`, scopeID).Scan(&kind); err != nil {
		return fmt.Errorf("load deployment scope kind: %w", err)
	}
	if kind != "tenant" {
		return nil
	}
	fact, err := domaineventsource.NewDeploymentStatusFact(domaineventsource.DeploymentStatus{
		EventID: envelope.EventID, TenantScopeID: scopeID, DeploymentID: envelope.DeploymentID,
		NodeID: envelope.NodeID, RolloutID: rolloutID, Attempt: envelope.Status.Attempt,
		TransitionSequence: envelope.Status.TransitionSequence, State: state,
		OccurredAt: envelope.Status.Event.OccurredTime.AsTime(),
	})
	if err != nil {
		return fmt.Errorf("build deployment source event: %w", err)
	}
	if _, err := domaineventsource.EnqueueTx(ctx, tx, fact); err != nil {
		return err
	}
	return nil
}
