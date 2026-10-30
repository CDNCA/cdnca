package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const loginSecurityOperation = "identity.user.login_security.update"

// ReadLoginSecurityTx also serves challenge issuance; the caller owns its transaction.
func ReadLoginSecurityTx(ctx context.Context, tx pgx.Tx, userID, scopeID uuid.UUID) (ManagedUserLoginSecurity, error) {
	result := ManagedUserLoginSecurity{UserID: userID, TenantScopeID: scopeID, LoginVerification: "none", LoginAllowlist: []string{}}
	err := tx.QueryRow(ctx, `SELECT revision,login_verification,login_allowlist FROM identity_user_login_security WHERE scope_id=$1 AND user_id=$2`, scopeID, userID).Scan(&result.Revision, &result.LoginVerification, &result.LoginAllowlist)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return ManagedUserLoginSecurity{}, fmt.Errorf("%w: read policy", ErrLoginSecurityUnavailable)
	}
	return result, nil
}

func checkLoginChannelTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, channel, contact string, consumer LoginChallengeConsumer) error {
	if contact == "" {
		return ErrLoginSecurityContactRequired
	}
	if consumer == nil || !consumer.LoginChannelAvailable(channel) {
		return ErrLoginSecurityUnavailable
	}
	policy, err := systemusersettings.GetPublicTx(ctx, tx, scopeID)
	if err != nil {
		return ErrLoginSecurityUnavailable
	}
	if channel == "email" && policy.EmailCodeLoginEnabled || channel == "sms" && policy.SMSCodeLoginEnabled {
		return nil
	}
	return ErrLoginMethodDisabled
}

func (s *Store) authorizeLoginSecurityActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if err := authenticateManagedPasswordResetActor(ctx, tx, actor, s.now().UTC()); err != nil {
		if errors.Is(err, ErrManagedPasswordResetUnavailable) {
			return ErrLoginSecurityUnavailable
		}
		return err
	}
	return authorizeManagedUserActor(ctx, tx, actor)
}

func loginSecurityTargetTx(ctx context.Context, tx pgx.Tx, userID, scopeID uuid.UUID) (string, string, error) {
	var email, phone string
	err := tx.QueryRow(ctx, `SELECT COALESCE(u.email,''),COALESCE(u.phone,'') FROM users u
		JOIN memberships m ON m.user_id=u.id AND m.scope_id=$2
		JOIN access_scopes s ON s.id=m.scope_id AND s.kind='tenant' AND s.tenant_id IS NOT NULL
		JOIN tenants t ON t.id=s.tenant_id
		WHERE u.id=$1 FOR UPDATE OF u,m,s,t`, userID, scopeID).Scan(&email, &phone)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrUserNotFound
	}
	return email, phone, err
}

func (s *Store) getManagedUserLoginSecurity(ctx context.Context, actor Actor, userID, scopeID uuid.UUID) (ManagedUserLoginSecurity, error) {
	var result ManagedUserLoginSecurity
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
		result, err = ReadLoginSecurityTx(ctx, tx, userID, scopeID)
		return err
	})
	return result, stableLoginSecurityError(err)
}

func (s *Store) updateManagedUserLoginSecurity(ctx context.Context, actor Actor, input UpdateManagedUserLoginSecurityInput, digest [sha256.Size]byte, consumer LoginChallengeConsumer) (ManagedUserLoginSecurity, error) {
	var result ManagedUserLoginSecurity
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate, []uuid.UUID{actor.ScopeID, input.TenantScopeID}); err != nil {
			return err
		}
		if err := s.authorizeLoginSecurityActor(ctx, tx, actor); err != nil {
			return err
		}
		email, phone, err := loginSecurityTargetTx(ctx, tx, input.UserID, input.TenantScopeID)
		if err != nil {
			return err
		}
		write, err := s.claimIdentityWrite(ctx, tx, actor, loginSecurityOperation, input.IdempotencyKey, digest, "", "")
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		previous, err := ReadLoginSecurityTx(ctx, tx, input.UserID, input.TenantScopeID)
		if err != nil {
			return err
		}
		if previous.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if input.LoginVerification != "none" {
			contact := email
			if input.LoginVerification == "sms" {
				contact = phone
			}
			if err := checkLoginChannelTx(ctx, tx, input.TenantScopeID, input.LoginVerification, contact, consumer); err != nil {
				return err
			}
		}
		result = ManagedUserLoginSecurity{UserID: input.UserID, TenantScopeID: input.TenantScopeID, Revision: previous.Revision + 1, LoginVerification: input.LoginVerification, LoginAllowlist: input.LoginAllowlist}
		if _, err := tx.Exec(ctx, `INSERT INTO identity_user_login_security(scope_id,user_id,revision,login_verification,login_allowlist,updated_by_user_id,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(scope_id,user_id) DO UPDATE SET revision=EXCLUDED.revision,
			login_verification=EXCLUDED.login_verification,login_allowlist=EXCLUDED.login_allowlist,updated_by_user_id=EXCLUDED.updated_by_user_id,updated_at=EXCLUDED.updated_at`,
			input.TenantScopeID, input.UserID, result.Revision, result.LoginVerification, result.LoginAllowlist, actor.UserID, s.now().UTC()); err != nil {
			return err
		}
		encoded, _ := json.Marshal(result.LoginAllowlist)
		allowlistHash := sha256.Sum256(encoded)
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: loginSecurityOperation,
			ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID, Result: "success", Payload: map[string]any{
				"tenant_scope_id": input.TenantScopeID.String(), "previous_revision": previous.Revision, "revision": result.Revision,
				"login_verification": result.LoginVerification, "allowlist_count": len(result.LoginAllowlist), "allowlist_sha256": hex.EncodeToString(allowlistHash[:]),
			}}); err != nil {
			return err
		}
		return s.completeIdentityWrite(ctx, tx, actor.UserID, loginSecurityOperation, input.IdempotencyKey, input.UserID, 200, result)
	})
	return result, stableLoginSecurityError(err)
}

func stableLoginSecurityError(err error) error {
	switch {
	case err == nil, errors.Is(err, ErrInvalidSession), errors.Is(err, ErrPermissionDenied),
		errors.Is(err, ErrUserNotFound), errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrIdempotencyConflict),
		errors.Is(err, ErrLoginMethodDisabled), errors.Is(err, ErrLoginSecurityContactRequired), errors.Is(err, ErrLoginSecurityUnavailable):
		return err
	default:
		return ErrLoginSecurityUnavailable
	}
}
