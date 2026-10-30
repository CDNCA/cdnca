package identity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// secondaryVerificationCompletedSQL is true when the user has an approved,
// evidence-settled personal reverification created after the request.
const secondaryVerificationCompletedSQL = `EXISTS (
	SELECT 1 FROM identity_verification_cases c
	JOIN identity_verification_evidence_settlements settlement ON settlement.tenant_scope_id=c.tenant_scope_id
	  AND settlement.case_id=c.id AND settlement.actor_user_id=c.applicant_user_id AND settlement.state='settled'
	WHERE c.tenant_scope_id=v.scope_id AND c.applicant_user_id=v.user_id
	  AND c.kind='personal_reverification' AND c.status='approved' AND c.created_at>=v.requested_at)`

// ReadSecondaryVerificationTx reads the request; a missing row is revision 0, disabled.
func ReadSecondaryVerificationTx(ctx context.Context, tx pgx.Tx, userID, scopeID uuid.UUID) (ManagedUserSecondaryVerification, error) {
	result := ManagedUserSecondaryVerification{UserID: userID, TenantScopeID: scopeID, ExpiryAction: SecondaryExpiryNone}
	err := tx.QueryRow(ctx, `SELECT v.revision,v.enabled,v.deadline,v.expiry_action,v.requested_at,v.enforced_at,
		v.enabled AND `+secondaryVerificationCompletedSQL+`
		FROM identity_user_secondary_verification v WHERE v.scope_id=$1 AND v.user_id=$2`, scopeID, userID).
		Scan(&result.Revision, &result.Enabled, &result.Deadline, &result.ExpiryAction, &result.RequestedAt, &result.EnforcedAt, &result.Completed)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return ManagedUserSecondaryVerification{}, fmt.Errorf("%w: read request", ErrSecondaryVerificationUnavailable)
	}
	utcTimes(result.Deadline, result.RequestedAt, result.EnforcedAt)
	return result, nil
}

func utcTimes(values ...*time.Time) {
	for _, value := range values {
		if value != nil {
			*value = value.UTC()
		}
	}
}

func (s *Store) getManagedUserSecondaryVerification(ctx context.Context, actor Actor, userID, scopeID uuid.UUID) (ManagedUserSecondaryVerification, error) {
	var result ManagedUserSecondaryVerification
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if err := s.authorizeLoginSecurityActor(ctx, tx, actor); err != nil {
			return err
		}
		if _, _, err := loginSecurityTargetTx(ctx, tx, userID, scopeID); err != nil {
			return err
		}
		var err error
		result, err = ReadSecondaryVerificationTx(ctx, tx, userID, scopeID)
		return err
	})
	return result, stableSecondaryVerificationError(err)
}

func (s *Store) updateManagedUserSecondaryVerification(ctx context.Context, actor Actor, input UpdateManagedUserSecondaryVerificationInput,
	digest [sha256.Size]byte, notifier SecondaryVerificationNotifier) (ManagedUserSecondaryVerification, error) {
	var result ManagedUserSecondaryVerification
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate, []uuid.UUID{actor.ScopeID, input.TenantScopeID}); err != nil {
			return err
		}
		if err := s.authorizeLoginSecurityActor(ctx, tx, actor); err != nil {
			return err
		}
		if _, _, err := loginSecurityTargetTx(ctx, tx, input.UserID, input.TenantScopeID); err != nil {
			return err
		}
		write, err := s.claimIdentityWrite(ctx, tx, actor, secondaryVerificationOperation, input.IdempotencyKey, digest, "", "")
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		previous, err := ReadSecondaryVerificationTx(ctx, tx, input.UserID, input.TenantScopeID)
		if err != nil {
			return err
		}
		if previous.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		// A new request starts when it is switched on; editing an active request
		// keeps requested_at, so an earlier completed reverification still counts.
		newRequest := input.Enabled && !previous.Enabled
		requestedAt := previous.RequestedAt
		var enforcedAt *time.Time
		if input.Enabled {
			if newRequest {
				requestedAt = &now
			} else if sameDeadline(previous.Deadline, input.Deadline) && previous.ExpiryAction == input.ExpiryAction {
				enforcedAt = previous.EnforcedAt
			}
		} else {
			requestedAt = nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_user_secondary_verification
			(scope_id,user_id,revision,enabled,deadline,expiry_action,requested_at,enforced_at,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(scope_id,user_id) DO UPDATE SET
			revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,deadline=EXCLUDED.deadline,expiry_action=EXCLUDED.expiry_action,
			requested_at=EXCLUDED.requested_at,enforced_at=EXCLUDED.enforced_at,
			updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			input.TenantScopeID, input.UserID, previous.Revision+1, input.Enabled, input.Deadline, input.ExpiryAction,
			requestedAt, enforcedAt, actor.UserID, now); err != nil {
			return err
		}
		if result, err = ReadSecondaryVerificationTx(ctx, tx, input.UserID, input.TenantScopeID); err != nil {
			return err
		}
		if newRequest && notifier != nil {
			var username string
			if err := tx.QueryRow(ctx, `SELECT username FROM users WHERE id=$1`, input.UserID).Scan(&username); err != nil {
				return err
			}
			if err := notifier.NotifySecondaryVerificationTx(ctx, tx, SecondaryVerificationNotice{
				ScopeID: input.TenantScopeID, UserID: input.UserID, Username: username, Deadline: input.Deadline,
				RequestedAt: now, RequestID: input.RequestID,
			}); err != nil {
				return fmt.Errorf("%w: notify", ErrSecondaryVerificationUnavailable)
			}
		}
		payload := map[string]any{
			"tenant_scope_id": input.TenantScopeID.String(), "previous_revision": previous.Revision, "revision": result.Revision,
			"enabled": result.Enabled, "expiry_action": result.ExpiryAction, "notified": newRequest && notifier != nil,
		}
		if result.Deadline != nil {
			payload["deadline"] = result.Deadline.Format(time.RFC3339)
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: secondaryVerificationOperation,
			ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID, Result: "success", Payload: payload}); err != nil {
			return err
		}
		return s.completeIdentityWrite(ctx, tx, actor.UserID, secondaryVerificationOperation, input.IdempotencyKey, input.UserID, 200, result)
	})
	return result, stableSecondaryVerificationError(err)
}

func sameDeadline(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func stableSecondaryVerificationError(err error) error {
	switch {
	case err == nil, errors.Is(err, ErrInvalidSession), errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrInvalidUserInput),
		errors.Is(err, ErrUserNotFound), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrIdempotencyConflict),
		errors.Is(err, ErrSecondaryVerificationUnavailable):
		return err
	default:
		return ErrSecondaryVerificationUnavailable
	}
}
