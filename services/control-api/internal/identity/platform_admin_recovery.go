package identity

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const platformAdministratorRecoveryAction = "identity.platform_admin.recover"

var (
	ErrPlatformRecoveryInput        = errors.New("platform_recovery_invalid_input")
	ErrPlatformRecoveryPrecondition = errors.New("platform_recovery_precondition_failed")
	ErrPlatformRecoveryConflict     = errors.New("platform_recovery_username_conflict")
	ErrPlatformRecoveryRequestUsed  = errors.New("platform_recovery_request_already_used_check_status")
	ErrPlatformRecoveryUnavailable  = errors.New("platform_recovery_unavailable_check_status")
)

type PlatformAdministratorRecoveryInput struct {
	UserID           uuid.UUID
	ScopeID          uuid.UUID
	ExpectedUsername string
	ExpectedRevision int64
	NewUsername      string
	NewPassword      string
	RequestID        string
}

type PlatformAdministratorRecoveryReceipt struct {
	UserID           uuid.UUID `json:"user_id"`
	ScopeID          uuid.UUID `json:"scope_id"`
	RequestID        string    `json:"request_id"`
	PreviousUsername string    `json:"previous_username"`
	Username         string    `json:"username"`
	PreviousRevision int64     `json:"previous_revision"`
	Revision         int64     `json:"revision"`
	RevokedSessions  int64     `json:"revoked_sessions"`
	Execution        string    `json:"execution"`
}

// RecoverPlatformAdministrator is called only by the Linux root-local CLI. It
// deliberately has no HTTP adapter and never creates users or role assignments.
// A request is single-use; an ambiguous commit must be inspected with Status.
func (s *Store) RecoverPlatformAdministrator(ctx context.Context, input PlatformAdministratorRecoveryInput) (PlatformAdministratorRecoveryReceipt, error) {
	var receipt PlatformAdministratorRecoveryReceipt
	requestID, err := uuid.Parse(input.RequestID)
	if ctx == nil || input.UserID == uuid.Nil || input.ScopeID == uuid.Nil ||
		err != nil || requestID == uuid.Nil || requestID.String() != input.RequestID ||
		!validUsername(input.ExpectedUsername) || !validUsername(input.NewUsername) || input.ExpectedRevision < 1 {
		return receipt, ErrPlatformRecoveryInput
	}
	hash, err := HashPassword(input.NewPassword)
	if err != nil {
		return receipt, ErrPlatformRecoveryInput
	}
	input.NewPassword = ""
	if !s.configured() {
		return receipt, ErrPlatformRecoveryUnavailable
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Take the same global lock as login/refresh before collecting all user
		// scopes. This also prevents scope hints changing before session revoke.
		if err := protocol.AcquireExclusive(ctx, tx); err != nil {
			return err
		}
		scopes, err := collectUserAuthorityScopes(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationPasswordChange,
			mergeAuthorityScopes(scopes, input.ScopeID)); err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events
			WHERE action=$1 AND request_id=$2)`, platformAdministratorRecoveryAction, input.RequestID).Scan(&used); err != nil {
			return err
		}
		if used {
			return ErrPlatformRecoveryRequestUsed
		}
		var username string
		var revision int64
		if err := tx.QueryRow(ctx, `SELECT account.username,account.revision
			FROM users account
			JOIN memberships membership ON membership.user_id=account.id AND membership.scope_id=$2
			JOIN access_scopes scope ON scope.id=membership.scope_id
			WHERE account.id=$1 AND account.status='active' AND membership.status='active'
			  AND scope.kind='platform' AND scope.tenant_id IS NULL
			  AND EXISTS(SELECT 1 FROM role_assignments assignment
			    JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
			    WHERE assignment.user_id=account.id AND assignment.scope_id=scope.id
			      AND role.system_role AND role.name='platform_owner')
			FOR UPDATE OF account,membership,scope`, input.UserID, input.ScopeID).Scan(&username, &revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrPlatformRecoveryPrecondition
			}
			return err
		}
		if username != input.ExpectedUsername || revision != input.ExpectedRevision {
			return ErrPlatformRecoveryPrecondition
		}
		now := s.now().UTC()
		updated, err := tx.Exec(ctx, `UPDATE users SET username=$4,password_hash=$5,
			revision=revision+1,updated_at=$6 WHERE id=$1 AND username=$2 AND revision=$3`,
			input.UserID, input.ExpectedUsername, input.ExpectedRevision, input.NewUsername, hash, now)
		if isUniqueViolation(err) {
			return ErrPlatformRecoveryConflict
		}
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 1 {
			return ErrPlatformRecoveryPrecondition
		}
		revoked, err := tx.Exec(ctx, `UPDATE auth_sessions SET revoked_at=$2,
			revocation_reason='platform_admin_recovery' WHERE user_id=$1 AND revoked_at IS NULL`, input.UserID, now)
		if err != nil {
			return err
		}
		receipt = PlatformAdministratorRecoveryReceipt{
			UserID: input.UserID, ScopeID: input.ScopeID, RequestID: input.RequestID,
			PreviousUsername: username, Username: input.NewUsername,
			PreviousRevision: revision, Revision: revision + 1,
			RevokedSessions: revoked.RowsAffected(), Execution: "local_root",
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: input.ScopeID, Action: platformAdministratorRecoveryAction,
			ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{
				"user_id": receipt.UserID, "scope_id": receipt.ScopeID, "request_id": receipt.RequestID,
				"previous_username": receipt.PreviousUsername, "username": receipt.Username,
				"previous_revision": receipt.PreviousRevision, "revision": receipt.Revision,
				"revoked_sessions": receipt.RevokedSessions, "execution": receipt.Execution,
			},
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrPlatformRecoveryPrecondition), errors.Is(err, ErrPlatformRecoveryConflict),
			errors.Is(err, ErrPlatformRecoveryRequestUsed):
			return PlatformAdministratorRecoveryReceipt{}, err
		default:
			// Never propagate database errors: details may contain credential data.
			return PlatformAdministratorRecoveryReceipt{}, ErrPlatformRecoveryUnavailable
		}
	}
	return receipt, nil
}

func (s *Store) PlatformAdministratorRecoveryStatus(ctx context.Context, userID, scopeID uuid.UUID, requestID string) (PlatformAdministratorRecoveryReceipt, bool, error) {
	var receipt PlatformAdministratorRecoveryReceipt
	parsed, err := uuid.Parse(requestID)
	if ctx == nil || userID == uuid.Nil || scopeID == uuid.Nil || err != nil || parsed == uuid.Nil || parsed.String() != requestID {
		return receipt, false, ErrPlatformRecoveryInput
	}
	if !s.configured() {
		return receipt, false, ErrPlatformRecoveryUnavailable
	}
	var encoded []byte
	err = s.pool.QueryRow(ctx, `SELECT payload FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_type='user' AND resource_id=$3
		  AND request_id=$4 AND result='success'`, scopeID, platformAdministratorRecoveryAction,
		userID.String(), requestID).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return receipt, false, nil
	}
	if err != nil || json.Unmarshal(encoded, &receipt) != nil || receipt.UserID != userID ||
		receipt.ScopeID != scopeID || receipt.RequestID != requestID || receipt.Execution != "local_root" ||
		!validUsername(receipt.PreviousUsername) || !validUsername(receipt.Username) ||
		receipt.PreviousRevision < 1 || receipt.Revision != receipt.PreviousRevision+1 || receipt.RevokedSessions < 0 {
		return PlatformAdministratorRecoveryReceipt{}, false, ErrPlatformRecoveryUnavailable
	}
	return receipt, true, nil
}
