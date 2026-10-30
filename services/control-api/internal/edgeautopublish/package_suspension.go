package edgeautopublish

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RequestPackageSuspensionRepublicationTx makes a package subscription's
// suspension (or its end) effective on the nodes at once (bb03, ADR 0019 §5,
// migration 555). Publication filters suspended subscriptions out; no site row
// changes, so the scope takes a revision of its own (attributed to
// package_suspension on a manual scope) and is republished immediately, as a
// package expiry is. The caller locked the configuration scope and read
// fromRevision before changing the subscription.
func RequestPackageSuspensionRepublicationTx(ctx context.Context, tx pgx.Tx, scopeID, subscriptionID uuid.UUID,
	fromRevision int64, suspend bool, requestID string,
) error {
	if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, scopeID); err != nil {
		return err
	}
	operation := "site.batch.enable"
	if suspend {
		operation = "site.batch.disable"
	}
	_, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: scopeID, Trigger: edgepublish.SystemTriggerPackageSuspension, SourceResourceID: subscriptionID,
		Operation: operation, SourceRequestID: "package-suspension:" + requestID, FromRevision: fromRevision,
		Immediate: true,
	})
	return err
}
