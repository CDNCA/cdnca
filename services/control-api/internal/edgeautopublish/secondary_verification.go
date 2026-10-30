package edgeautopublish

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5"
)

// SecondaryVerificationRepublisher makes the sites an overdue secondary
// identity verification stopped (or its completion restored) effective on the
// nodes at once (FX57): an automatic scope through its policy, any other scope
// through a system republication that is due immediately, in the caller's
// transaction, with the site change attributed to secondary verification.
type SecondaryVerificationRepublisher struct{}

var _ identity.SecondaryVerificationRepublisher = SecondaryVerificationRepublisher{}

func (SecondaryVerificationRepublisher) RepublishNowTx(ctx context.Context, tx pgx.Tx, request identity.SecondaryVerificationRepublish) error {
	_, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: request.ScopeID, Trigger: edgepublish.SystemTriggerSecondaryVerification, SourceResourceID: request.UserID,
		Operation: request.Operation, SourceRequestID: request.RequestID, FromRevision: request.FromRevision, Immediate: true,
	})
	return err
}

// AccountSuspensionRepublisher makes the sites a disabled account stopped (or
// its reactivation restored) effective on the nodes at once.
type AccountSuspensionRepublisher struct{}

var _ identity.AccountSuspensionRepublisher = AccountSuspensionRepublisher{}

func (AccountSuspensionRepublisher) RepublishNowTx(ctx context.Context, tx pgx.Tx, request identity.SecondaryVerificationRepublish) error {
	_, err := RequestRepublicationTx(ctx, tx, RepublishRequest{
		ScopeID: request.ScopeID, Trigger: edgepublish.SystemTriggerAccountSuspension, SourceResourceID: request.UserID,
		Operation: request.Operation, SourceRequestID: request.RequestID, FromRevision: request.FromRevision, Immediate: true,
	})
	return err
}
