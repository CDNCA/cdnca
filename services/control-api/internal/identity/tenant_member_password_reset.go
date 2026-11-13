package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/mfacipher"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Tenant member password reset with a retrievable result (migration 487).
//
// If the response of a reset is lost, the password was already changed and
// the member signed out, but the administrator never saw the new password.
// So the generated password is kept encrypted for 10 minutes, bound to the
// actor (user and scope), the member and the Idempotency-Key. Sending the same
// request again (same actor, same key) returns it once and clears the
// ciphertext; afterwards, after expiry, or once a later reset replaced the
// password, that key answers ErrTenantMemberPasswordResetGone instead of
// resetting again. Another actor or another member under the same key is an
// idempotency conflict. Every reset also sets "change the password at the
// next sign-in".

const (
	tenantMemberTemporaryPasswordBytes = 18 // 24 base64url characters
	TenantMemberPasswordResetResultTTL = 10 * time.Minute
	// Retrieved/expired rows stay as tombstones so a late retry of the same key
	// is refused instead of resetting again.
	tenantMemberPasswordResetTombstoneTTL = 24 * time.Hour
)

var (
	// ErrTenantMemberPasswordResetGone: the key's result was already retrieved,
	// expired, or replaced by a later reset. Nothing was changed.
	ErrTenantMemberPasswordResetGone = errors.New("tenant member password reset result is gone")
	// ErrTenantMemberPasswordResetUnavailable: no result cipher configured.
	ErrTenantMemberPasswordResetUnavailable = errors.New("tenant member password reset is unavailable")
)

type TenantMemberPasswordReset struct {
	UserID            uuid.UUID `json:"user_id"`
	TemporaryPassword string    `json:"temporary_password"`
	// PasswordChangeRequired is always true: the member must change it at the next sign-in.
	PasswordChangeRequired bool `json:"password_change_required"`
	// Replayed: this is the retained result of an earlier request with the same key.
	Replayed        bool      `json:"replayed"`
	ResultExpiresAt time.Time `json:"result_expires_at"`
}

// SetTenantMemberPasswordResetCipher sets the cipher of the retained results.
func (s *Service) SetTenantMemberPasswordResetCipher(cipher *mfacipher.Cipher) error {
	if s == nil || cipher == nil {
		return errors.New("tenant member password reset cipher is required")
	}
	s.passwordResetCipher = cipher
	return nil
}

// ResetTenantMemberPassword gives a sub-account a new random password (only its
// hash is stored on the user), requires a change at the next sign-in and
// revokes the member's sessions; or, for a key already used by this actor for
// this member, returns the retained result once.
func (s *Service) ResetTenantMemberPassword(ctx context.Context, actor Principal, userID uuid.UUID, idempotencyKey, requestID string) (TenantMemberPasswordReset, error) {
	if userID == uuid.Nil || !validWriteMetadata(idempotencyKey, requestID) {
		return TenantMemberPasswordReset{}, ErrInvalidUserInput
	}
	if s.passwordResetCipher == nil {
		return TenantMemberPasswordReset{}, ErrTenantMemberPasswordResetUnavailable
	}
	raw := make([]byte, tenantMemberTemporaryPasswordBytes)
	if _, err := rand.Read(raw); err != nil {
		return TenantMemberPasswordReset{}, err
	}
	password := base64.RawURLEncoding.EncodeToString(raw)
	hash, err := HashPassword(password)
	if err != nil {
		return TenantMemberPasswordReset{}, err
	}
	keyID, envelope, err := s.passwordResetCipher.Encrypt([]byte(password))
	if err != nil {
		return TenantMemberPasswordReset{}, ErrTenantMemberPasswordResetUnavailable
	}
	var result TenantMemberPasswordReset
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		if err := s.store.authorizeTenantMemberAdminTx(ctx, tx, actor); err != nil {
			return err
		}
		if err := lockTenantMemberTargetTx(ctx, tx, actor, userID); err != nil {
			return err
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tenant-member-password-reset:' || $1,0))`, idempotencyKey); err != nil {
			return err
		}
		var storedActor, storedScope, storedMember uuid.UUID
		var storedKeyID *string
		var storedEnvelope []byte
		var expiresAt time.Time
		err := tx.QueryRow(ctx, `SELECT actor_user_id,actor_scope_id,member_user_id,key_id,envelope,expires_at
			FROM tenant_member_password_reset_results WHERE idempotency_key=$1 FOR UPDATE`, idempotencyKey).
			Scan(&storedActor, &storedScope, &storedMember, &storedKeyID, &storedEnvelope, &expiresAt)
		if err == nil {
			return s.retrieveTenantMemberPasswordResetTx(ctx, tx, actor, userID, idempotencyKey, requestID, now,
				storedActor, storedScope, storedMember, storedKeyID, storedEnvelope, expiresAt, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2,password_change_required=true,revision=revision+1,updated_at=$3 WHERE id=$1`,
			userID, hash, now); err != nil {
			return err
		}
		if err := revokeUserSessions(ctx, tx, userID, now, "tenant_member_password_reset"); err != nil {
			return err
		}
		// An earlier reset's password no longer works: drop its retained result.
		if _, err := tx.Exec(ctx, `UPDATE tenant_member_password_reset_results SET key_id=NULL,envelope=NULL
			WHERE member_user_id=$1 AND envelope IS NOT NULL`, userID); err != nil {
			return err
		}
		expiresAt = now.Add(TenantMemberPasswordResetResultTTL)
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_member_password_reset_results
			(idempotency_key,actor_user_id,actor_scope_id,member_user_id,key_id,envelope,created_at,expires_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, idempotencyKey, actor.UserID, actor.ScopeID, userID, keyID, envelope, now, expiresAt); err != nil {
			return err
		}
		result = TenantMemberPasswordReset{UserID: userID, TemporaryPassword: password, PasswordChangeRequired: true, ResultExpiresAt: expiresAt}
		return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: "identity.tenant_member.password.reset", ResourceType: "user", ResourceID: userID.String(),
			RequestID: requestID, Result: "success", Payload: map[string]any{
				"sessions_revoked": true, "password_change_required": true,
				"result_retained_seconds": int(TenantMemberPasswordResetResultTTL / time.Second)}})
	})
	if err != nil {
		return TenantMemberPasswordReset{}, err
	}
	return result, nil
}

func (s *Service) retrieveTenantMemberPasswordResetTx(ctx context.Context, tx pgx.Tx, actor Principal, userID uuid.UUID,
	idempotencyKey, requestID string, now time.Time, storedActor, storedScope, storedMember uuid.UUID,
	storedKeyID *string, storedEnvelope []byte, expiresAt time.Time, result *TenantMemberPasswordReset,
) error {
	if storedActor != actor.UserID || storedScope != actor.ScopeID || storedMember != userID {
		return ErrIdempotencyConflict
	}
	if storedKeyID == nil || storedEnvelope == nil || !now.Before(expiresAt) {
		return ErrTenantMemberPasswordResetGone
	}
	plaintext, err := s.passwordResetCipher.Decrypt(*storedKeyID, storedEnvelope)
	if err != nil {
		return ErrTenantMemberPasswordResetUnavailable
	}
	defer clear(plaintext)
	// Returned once: clear the ciphertext in the same transaction.
	if _, err := tx.Exec(ctx, `UPDATE tenant_member_password_reset_results SET key_id=NULL,envelope=NULL,retrieved_at=$2
		WHERE idempotency_key=$1`, idempotencyKey, now); err != nil {
		return err
	}
	*result = TenantMemberPasswordReset{UserID: userID, TemporaryPassword: string(plaintext), PasswordChangeRequired: true,
		Replayed: true, ResultExpiresAt: expiresAt}
	return s.store.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
		Action: "identity.tenant_member.password.reset_result.retrieve", ResourceType: "user", ResourceID: userID.String(),
		RequestID: requestID, Result: "success", Payload: map[string]any{"idempotent_replay": true}})
}

// PurgeTenantMemberPasswordResetResults clears the ciphertext of expired
// results and deletes tombstones older than a day. Run by the minute loop.
func (s *Store) PurgeTenantMemberPasswordResetResults(ctx context.Context) (int64, error) {
	now := s.now().UTC()
	cleared, err := s.pool.Exec(ctx, `UPDATE tenant_member_password_reset_results SET key_id=NULL,envelope=NULL
		WHERE envelope IS NOT NULL AND expires_at<=$1`, now)
	if err != nil {
		return 0, err
	}
	deleted, err := s.pool.Exec(ctx, `DELETE FROM tenant_member_password_reset_results WHERE created_at<=$1`,
		now.Add(-tenantMemberPasswordResetTombstoneTTL))
	if err != nil {
		return 0, err
	}
	return cleared.RowsAffected() + deleted.RowsAffected(), nil
}
