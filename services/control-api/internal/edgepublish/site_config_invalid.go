package edgepublish

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SiteConfigInvalidError is a stored site the publication cannot compile
//.
// Retrying cannot change it; the next save of the site does. It unwraps to
// ErrInvalidInput, so manual publications keep answering validation_error.
type SiteConfigInvalidError struct {
	SiteID uuid.UUID
	// Reason: https_ports_invalid, https_ports_mismatch, no_listen_ports,
	// failover_tries_invalid.
	Reason string
}

func (e *SiteConfigInvalidError) Error() string {
	return "site " + e.SiteID.String() + " configuration is invalid: " + e.Reason
}

func (e *SiteConfigInvalidError) Unwrap() error { return ErrInvalidInput }

// SiteConfigInvalidAction is the audit action of a publication refused for a
// site's stored configuration.
const SiteConfigInvalidAction = "edge_publication.site_config_invalid"

// recordSiteConfigInvalid audits the refusal on its own transaction (the
// publication's rolled back); failing to write it does not hide the refusal.
func (s *Service) recordSiteConfigInvalid(ctx context.Context, request PublishRequest, err error) {
	var invalid *SiteConfigInvalidError
	if !errors.As(err, &invalid) || request.ConfigurationScopeID == uuid.Nil {
		return
	}
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var actorID *uuid.UUID
		if actor := request.Actor.UserID; actor != uuid.Nil {
			actorID = &actor
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.ConfigurationScopeID, ActorUserID: actorID,
			Action: SiteConfigInvalidAction, ResourceType: "site", ResourceID: invalid.SiteID.String(),
			RequestID: request.RequestID, Result: "denied",
			Payload: map[string]any{"reason": invalid.Reason, "site_id": invalid.SiteID.String(),
				"source_revision": request.ExpectedSourceRevision, "idempotency_key": request.IdempotencyKey},
		})
	})
}
