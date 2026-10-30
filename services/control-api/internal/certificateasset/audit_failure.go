package certificateasset

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// failureReasons maps store errors to the stable reason codes of a refused or
// failed certificate operation's audit event (result denied or failure).
var failureReasons = []struct {
	err    error
	reason string
	denied bool
}{
	{ErrPermissionDenied, "permission_denied", true},
	{ErrIdempotencyConflict, "idempotency_conflict", true},
	{ErrRevisionConflict, "revision_conflict", true},
	{ErrInvalidTransition, "invalid_transition", true},
	{ErrNotFound, "not_found", true},
	{ErrDeleted, "deleted", true},
	{ErrReferenced, "still_referenced", true},
	{ErrAutoRenewUnsupported, "auto_renew_unsupported", true},
	{ErrAssetDisabled, "asset_disabled", true},
	{ErrDownloadUnavailable, "download_unavailable", true},
	{ErrDomainNotCovered, "domain_not_covered", true},
	{ErrACMEOrderMismatch, "acme_order_mismatch", true},
	{ErrCertificateExpired, "certificate_expired", true},
	{ErrCertificateNotYetValid, "certificate_not_yet_valid", true},
	{ErrKeyMismatch, "private_key_mismatch", true},
	{ErrWeakPublicKey, "weak_public_key", true},
	{ErrWeakSignature, "weak_signature", true},
	{ErrCertificateAuthority, "certificate_is_ca", true},
	{ErrServerAuthRequired, "server_auth_required", true},
	{ErrInvalidSAN, "invalid_san", true},
	{ErrChainOrder, "chain_out_of_order", true},
	{ErrChainIncomplete, "chain_incomplete", true},
	{ErrInvalidCertificatePEM, "invalid_certificate", true},
	{ErrInvalidPrivateKeyPEM, "invalid_private_key", true},
	{ErrInvalidInput, "invalid_input", true},
	{ErrEnvelopeUnavailable, "envelope_unavailable", false},
}

func failureReason(err error) (string, string) {
	for _, candidate := range failureReasons {
		if errors.Is(err, candidate.err) {
			if candidate.denied {
				return "denied", candidate.reason
			}
			return "failure", candidate.reason
		}
	}
	return "failure", "internal_error"
}

// auditFailure records a refused or failed operation (its own transaction
// rolled back). It is written to the actor's own scope, so a request against
// another tenant never writes into that tenant's log. Best effort: an audit
// that cannot be written does not replace the operation's error.
func (s *Store) auditFailure(
	ctx context.Context,
	actor Actor,
	tenantScopeID uuid.UUID,
	requestID, action, resourceType string,
	resourceID uuid.UUID,
	cause error,
) {
	if cause == nil || s == nil || s.pool == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil ||
		!validOpaqueName(requestID, 128) {
		return
	}
	result, reason := failureReason(cause)
	resource := "new"
	if resourceID != uuid.Nil {
		resource = resourceID.String()
	}
	payload := map[string]any{
		"actor_scope_id": actor.ScopeID.String(), "target_scope_id": tenantScopeID.String(),
		"operation": action, "reason_code": reason,
	}
	ctx = context.WithoutCancel(ctx)
	if ip := audit.SourceIPFrom(ctx); ip != "" {
		payload["ip"] = ip
	}
	actorID := actor.UserID
	_ = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actorID, Action: action,
			ResourceType: resourceType, ResourceID: resource, RequestID: requestID,
			Result: result, Payload: payload,
		})
	})
}
