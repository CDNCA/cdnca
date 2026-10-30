package pluginwebhookcontrol

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type webhookAuditInput struct {
	Actor        Actor
	Action       string
	Result       string
	Reason       string
	ResourceType string
	ResourceID   uuid.UUID
	RequestID    string
	OccurredAt   time.Time
}

func appendWebhookAudit(ctx context.Context, tx pgx.Tx, input webhookAuditInput) (uuid.UUID, error) {
	if tx == nil || input.Actor.validate() != nil || input.Action == "" || input.Result == "" || input.Reason == "" ||
		input.ResourceType == "" || input.ResourceID == uuid.Nil || input.RequestID == "" || input.OccurredAt.IsZero() {
		return uuid.Nil, ErrInvalidInput
	}
	actorID := input.Actor.ActorUserID
	return audit.AppendTx(ctx, tx, audit.Event{
		ScopeID: input.Actor.TargetScopeID, ActorUserID: &actorID, Action: input.Action,
		ResourceType: input.ResourceType, ResourceID: input.ResourceID.String(), RequestID: input.RequestID,
		Result: input.Result, OccurredAt: input.OccurredAt,
		Payload: map[string]any{"actor_scope_id": input.Actor.ActorScopeID.String(),
			"target_scope_id": input.Actor.TargetScopeID.String(), "operation": input.Action, "reason": input.Reason},
	})
}
