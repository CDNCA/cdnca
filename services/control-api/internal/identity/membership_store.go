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

const membershipSuspendOperation = "identity.membership.suspend"

func (s *Store) suspendMembership(
	ctx context.Context,
	actor Actor,
	input SuspendMembershipInput,
	digest [32]byte,
) (MembershipMutationResult, error) {
	var result MembershipMutationResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationMembershipSuspend, []uuid.UUID{actor.ScopeID, input.ScopeID},
		); err != nil {
			return err
		}
		if err := authorizeMembershipSuspension(ctx, tx, actor, input.ScopeID); err != nil {
			return err
		}

		var currentStatus string
		if err := tx.QueryRow(ctx, `
			SELECT membership.status
			FROM memberships membership
			JOIN users target_user ON target_user.id = membership.user_id
			JOIN access_scopes target_scope ON target_scope.id = membership.scope_id
			WHERE membership.scope_id = $1 AND membership.user_id = $2
			  AND target_scope.kind = 'tenant'
			FOR UPDATE OF membership, target_user, target_scope`, input.ScopeID, input.UserID,
		).Scan(&currentStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMembershipNotFound
			}
			return err
		}

		write, err := s.claimIdentityWrite(
			ctx, tx, actor, membershipSuspendOperation, input.IdempotencyKey, digest, "", "",
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		if currentStatus != input.ExpectedStatus {
			return ErrMembershipStatusConflict
		}

		now := s.now().UTC()
		command, err := tx.Exec(ctx, `
			UPDATE memberships
			SET status = $3
			WHERE scope_id = $1 AND user_id = $2 AND status = $4`,
			input.ScopeID, input.UserID, MembershipStatusSuspended, MembershipStatusActive,
		)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrMembershipStatusConflict
		}
		sessions, err := tx.Exec(ctx, `
			UPDATE auth_sessions
			SET revoked_at = $3, revocation_reason = 'membership_suspended'
			WHERE scope_id = $1 AND user_id = $2 AND revoked_at IS NULL`,
			input.ScopeID, input.UserID, now,
		)
		if err != nil {
			return err
		}
		result = MembershipMutationResult{
			ScopeID: input.ScopeID, UserID: input.UserID,
			PreviousStatus: currentStatus, Status: MembershipStatusSuspended,
			ReasonCode: input.ReasonCode, SessionsRevoked: sessions.RowsAffected(), SuspendedAt: now,
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: membershipSuspendOperation, ResourceType: "membership",
			ResourceID: input.ScopeID.String() + ":" + input.UserID.String(),
			RequestID:  input.RequestID, Result: "success", Payload: map[string]any{
				"target_scope_id": input.ScopeID.String(), "target_user_id": input.UserID.String(),
				"previous_status": currentStatus, "status": MembershipStatusSuspended,
				"reason_code": input.ReasonCode, "trace_id": input.TraceID,
				"sessions_revoked": result.SessionsRevoked,
			},
		}); err != nil {
			return err
		}
		return s.completeIdentityWrite(
			ctx, tx, actor.UserID, membershipSuspendOperation, input.IdempotencyKey,
			input.UserID, 200, result,
		)
	})
	if err != nil {
		return MembershipMutationResult{}, mapMembershipMutationError(err)
	}
	return result, nil
}

func authorizeMembershipSuspension(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
) error {
	var storedScopeKind string
	if err := tx.QueryRow(ctx, `
		SELECT actor_scope.kind
		FROM users actor_user
		JOIN memberships actor_membership
		  ON actor_membership.scope_id = $2 AND actor_membership.user_id = actor_user.id
		JOIN access_scopes actor_scope ON actor_scope.id = actor_membership.scope_id
		WHERE actor_user.id = $1 AND actor_user.status = 'active'
		  AND actor_membership.status = 'active'
		FOR UPDATE OF actor_user, actor_membership, actor_scope`, actor.UserID, actor.ScopeID,
	).Scan(&storedScopeKind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return err
	}
	if storedScopeKind != actor.ScopeKind ||
		(storedScopeKind == "tenant" && actor.ScopeID != targetScopeID) {
		return ErrPermissionDenied
	}

	permissions := []string{"identity.users.manage"}
	if storedScopeKind == "platform" {
		permissions = append(permissions, "platform.admin")
	}
	var permission string
	if err := tx.QueryRow(ctx, `
		SELECT role_permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.scope_id = assignment.scope_id AND role.id = assignment.role_id
		JOIN role_permissions role_permission ON role_permission.role_id = role.id
		WHERE assignment.scope_id = $1 AND assignment.user_id = $2
		  AND role_permission.permission_name = ANY($3::text[])
		ORDER BY role.id
		LIMIT 1
		FOR UPDATE OF assignment, role, role_permission`, actor.ScopeID, actor.UserID, permissions,
	).Scan(&permission); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPermissionDenied
		}
		return err
	}
	if permission != "identity.users.manage" &&
		!(storedScopeKind == "platform" && permission == "platform.admin") {
		return ErrPermissionDenied
	}
	return nil
}

func mapMembershipMutationError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrPermissionDenied):
		return ErrPermissionDenied
	case errors.Is(err, ErrMembershipNotFound):
		return ErrMembershipNotFound
	case errors.Is(err, ErrMembershipStatusConflict):
		return ErrMembershipStatusConflict
	case errors.Is(err, ErrIdempotencyConflict):
		return ErrIdempotencyConflict
	default:
		return ErrMembershipUnavailable
	}
}
