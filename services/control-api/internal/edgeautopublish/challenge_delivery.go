package edgeautopublish

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ChallengeDeliveryPublisher queues the republication of a scope once a node
// confirmed the JS challenge policy the control plane redelivered to it
// (edgepublish.ChallengeRedeliverer): manual scopes
// through the system channel (debounced, merged with the other deliveries of
// the window), automatic scopes through their policy (source_kind
// challenge_delivery, the node as the source resource).
type ChallengeDeliveryPublisher struct{}

func (ChallengeDeliveryPublisher) RepublishChallengeDeliveryTx(
	ctx context.Context, tx pgx.Tx, scopeID, nodeID, rolloutID uuid.UUID,
) error {
	if ctx == nil || tx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil || rolloutID == uuid.Nil {
		return ErrInvalidInput
	}
	_, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerChallengeDelivery, SourceResourceID: nodeID,
		SourceRequestID: "challenge-delivery." + rolloutID.String(),
	})
	return err
}

var _ edgepublish.ChallengeDeliveryRepublisher = ChallengeDeliveryPublisher{}
