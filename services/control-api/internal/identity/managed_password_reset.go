package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	ManagedPasswordResetStepUpAudience = "identity.user.password.reset"
	ManagedPasswordResetStepUpAction   = "identity.user.password.reset"
	managedPasswordResetOperation      = "identity.user.password.reset"
)

type ManagedPasswordResetStepUpActor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
}

type ManagedPasswordResetStepUpRequest struct {
	Token                 string
	TenantID              uuid.UUID
	Audience              string
	Action                string
	ResourceBindingDigest []byte
	RequestID             string
	TraceID               string
}

type ManagedPasswordResetStepUpEvidence struct {
	ProofID               uuid.UUID
	ActorUserID           uuid.UUID
	ActorScopeID          uuid.UUID
	SessionID             uuid.UUID
	TenantID              uuid.UUID
	Method                string
	Audience              string
	Action                string
	VerifiedAt            time.Time
	ExpiresAt             time.Time
	UseOrdinal            int
	ResourceBindingDigest []byte
}

type ManagedPasswordResetStepUpConsumer interface {
	BeginManagedPasswordResetAuthorityMutation(
		context.Context,
		pgx.Tx,
		[]uuid.UUID,
	) ([]uuid.UUID, error)
	ConsumeManagedPasswordResetStepUp(
		context.Context,
		pgx.Tx,
		ManagedPasswordResetStepUpActor,
		[]uuid.UUID,
		ManagedPasswordResetStepUpRequest,
	) (ManagedPasswordResetStepUpEvidence, error)
}

func (s *Service) SetManagedPasswordResetStepUpConsumer(consumer ManagedPasswordResetStepUpConsumer) {
	if s != nil {
		s.managedPasswordResetStepUpConsumer = consumer
	}
}

func (s *Service) ResetManagedUserPassword(
	ctx context.Context,
	actor Actor,
	input ResetManagedUserPasswordInput,
) (ManagedUser, error) {
	input.StepUpToken = strings.TrimSpace(input.StepUpToken)
	if !validAdminActor(actor) || actor.SessionID == uuid.Nil || input.ID == uuid.Nil ||
		input.TenantScopeID == uuid.Nil || input.ExpectedRevision < 1 ||
		input.StepUpToken == "" || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ManagedUser{}, ErrInvalidUserInput
	}
	if err := CheckNewPassword(input.NewPassword); err != nil {
		return ManagedUser{}, err
	}
	if s == nil || s.store == nil || s.managedPasswordResetStepUpConsumer == nil {
		return ManagedUser{}, ErrManagedPasswordResetUnavailable
	}
	passwordHash, err := HashPassword(input.NewPassword)
	if err != nil {
		return ManagedUser{}, ErrInvalidUserInput
	}
	requestDigest, err := digestIdentityRequest(struct {
		ID               uuid.UUID `json:"id"`
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{input.ID, input.TenantScopeID, input.ExpectedRevision})
	if err != nil {
		return ManagedUser{}, ErrManagedPasswordResetUnavailable
	}
	return s.store.resetManagedUserPassword(
		ctx, actor, input, requestDigest, passwordHash, s.managedPasswordResetStepUpConsumer,
	)
}

func (s *Store) resetManagedUserPassword(
	ctx context.Context,
	actor Actor,
	input ResetManagedUserPasswordInput,
	requestDigest [sha256.Size]byte,
	passwordHash string,
	consumer ManagedPasswordResetStepUpConsumer,
) (ManagedUser, error) {
	var result ManagedUser
	var outcome error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		lockedScopes, err := consumer.BeginManagedPasswordResetAuthorityMutation(
			ctx, tx, []uuid.UUID{actor.ScopeID, input.TenantScopeID},
		)
		if err != nil {
			return ErrManagedPasswordResetUnavailable
		}
		if err := authenticateManagedPasswordResetActor(ctx, tx, actor, s.now().UTC()); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}

		var tenantID uuid.UUID
		var revision int64
		err = tx.QueryRow(ctx, `
			SELECT scope.tenant_id,target.revision
			FROM users target
			JOIN memberships target_membership
			  ON target_membership.user_id=target.id AND target_membership.scope_id=$2
			JOIN access_scopes scope
			  ON scope.id=target_membership.scope_id AND scope.kind='tenant' AND scope.tenant_id IS NOT NULL
			JOIN tenants tenant ON tenant.id=scope.tenant_id
			WHERE target.id=$1
			FOR UPDATE OF target,target_membership,scope,tenant`, input.ID, input.TenantScopeID,
		).Scan(&tenantID, &revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserNotFound
		}
		if err != nil {
			return ErrManagedPasswordResetUnavailable
		}

		write, err := s.claimIdentityWrite(ctx, tx, actor, managedPasswordResetOperation,
			input.IdempotencyKey, requestDigest, passwordHash, input.NewPassword)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return ErrManagedPasswordResetUnavailable
			}
			return nil
		}
		if revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}

		bindingDigest := managedPasswordResetBindingDigest(requestDigest, write.SecretHash)
		evidence, err := consumer.ConsumeManagedPasswordResetStepUp(ctx, tx, ManagedPasswordResetStepUpActor{
			UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID,
		}, lockedScopes, ManagedPasswordResetStepUpRequest{
			Token: input.StepUpToken, TenantID: tenantID,
			Audience: ManagedPasswordResetStepUpAudience, Action: ManagedPasswordResetStepUpAction,
			ResourceBindingDigest: bindingDigest[:],
			RequestID:             input.RequestID, TraceID: input.RequestID,
		})
		if err != nil || !validManagedPasswordResetEvidence(evidence, actor, tenantID, bindingDigest) {
			if _, deleteErr := tx.Exec(ctx, `DELETE FROM identity_write_requests
				WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
				actor.UserID, managedPasswordResetOperation, input.IdempotencyKey); deleteErr != nil {
				return ErrManagedPasswordResetUnavailable
			}
			if errors.Is(err, ErrManagedPasswordResetUnavailable) {
				outcome = ErrManagedPasswordResetUnavailable
			} else {
				outcome = ErrManagedPasswordResetStepUpRequired
			}
			return nil
		}

		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `UPDATE users
			SET password_hash=$2,revision=revision+1,updated_at=$3 WHERE id=$1`, input.ID, write.SecretHash, now); err != nil {
			return ErrManagedPasswordResetUnavailable
		}
		if err := revokeUserSessions(ctx, tx, input.ID, now, "managed_password_reset"); err != nil {
			return ErrManagedPasswordResetUnavailable
		}
		result, err = getManagedUserTx(ctx, tx, input.ID)
		if err != nil {
			return ErrManagedPasswordResetUnavailable
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: managedPasswordResetOperation,
			ResourceType: "user", ResourceID: input.ID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{
				"tenant_id": tenantID.String(), "tenant_scope_id": input.TenantScopeID.String(),
				"previous_revision": revision, "revision": result.Revision,
				"step_up_proof_id": evidence.ProofID.String(), "step_up_use_ordinal": evidence.UseOrdinal,
			},
		}); err != nil {
			return ErrManagedPasswordResetUnavailable
		}
		if err := s.completeIdentityWrite(ctx, tx, actor.UserID, managedPasswordResetOperation,
			input.IdempotencyKey, input.ID, 200, result); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("reset managed user password: %w", stableManagedPasswordResetError(err))
	}
	if outcome != nil {
		return ManagedUser{}, outcome
	}
	return result, nil
}

func authenticateManagedPasswordResetActor(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	now time.Time,
) error {
	var found bool
	err := tx.QueryRow(ctx, `
		SELECT true
		FROM auth_sessions session
		JOIN users actor_user ON actor_user.id=session.user_id AND actor_user.status='active'
		JOIN memberships actor_membership
		  ON actor_membership.scope_id=session.scope_id AND actor_membership.user_id=session.user_id
		 AND actor_membership.status='active'
		JOIN access_scopes actor_scope
		  ON actor_scope.id=actor_membership.scope_id AND actor_scope.kind='platform' AND actor_scope.tenant_id IS NULL
		WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3
		  AND session.revoked_at IS NULL AND session.expires_at>$4
		FOR UPDATE OF session,actor_user,actor_membership,actor_scope`,
		actor.SessionID, actor.UserID, actor.ScopeID, now,
	).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) || !found {
		return ErrInvalidSession
	}
	if err != nil {
		return ErrManagedPasswordResetUnavailable
	}
	return nil
}

func managedPasswordResetBindingDigest(requestDigest [sha256.Size]byte, secretHash string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca/identity/managed-password-reset/v1\x00"))
	_, _ = hash.Write(requestDigest[:])
	_, _ = hash.Write([]byte(secretHash))
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validManagedPasswordResetEvidence(
	evidence ManagedPasswordResetStepUpEvidence,
	actor Actor,
	tenantID uuid.UUID,
	binding [sha256.Size]byte,
) bool {
	return evidence.ProofID != uuid.Nil && evidence.ActorUserID == actor.UserID &&
		evidence.ActorScopeID == actor.ScopeID && evidence.SessionID == actor.SessionID &&
		evidence.TenantID == tenantID && evidence.Audience == ManagedPasswordResetStepUpAudience &&
		evidence.Action == ManagedPasswordResetStepUpAction && evidence.UseOrdinal == 1 &&
		bytes.Equal(evidence.ResourceBindingDigest, binding[:])
}

func stableManagedPasswordResetError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidSession), errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrUserNotFound), errors.Is(err, ErrRevisionConflict),
		errors.Is(err, ErrIdempotencyConflict), errors.Is(err, ErrManagedPasswordResetStepUpRequired),
		errors.Is(err, ErrManagedPasswordResetUnavailable):
		return err
	default:
		return ErrManagedPasswordResetUnavailable
	}
}
