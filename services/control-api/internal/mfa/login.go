package mfa

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ADR 0019 BB-05: the billing bridge one-time sign-in reuses the account's
// TOTP / recovery code when the plugin setting sso_require_mfa is on. There
// is no session yet, so the code is checked against the user's active
// credential inside the caller's sign-in transaction (same counters, replay
// and recovery-code rules as a step-up).

// Enabled reports, in tx, whether userID has an active MFA credential in scopeID.
func (s *Service) EnabledTx(ctx context.Context, tx pgx.Tx, userID, scopeID uuid.UUID) (bool, error) {
	if s == nil || tx == nil || userID == uuid.Nil || scopeID == uuid.Nil {
		return false, ErrInvalidInput
	}
	return hasActiveCredential(ctx, tx, Actor{UserID: userID, ScopeID: scopeID})
}

// VerifyLoginTx checks authentication against the user's active credential
// and records the verification event; ErrInvalidCode / ErrCodeReplayed /
// ErrRecoveryCodeUsed are the caller's denials. idempotencyKey must be unique
// per sign-in attempt.
func (s *Service) VerifyLoginTx(ctx context.Context, tx pgx.Tx, userID, scopeID uuid.UUID,
	authentication Authentication, idempotencyKey string, request RequestContext,
) error {
	if s == nil || tx == nil || userID == uuid.Nil || scopeID == uuid.Nil || !validAuthentication(authentication) ||
		!validMutation(idempotencyKey, request) {
		return ErrInvalidInput
	}
	credential, err := lockActiveCredential(ctx, tx, Actor{UserID: userID, ScopeID: scopeID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotActive
	}
	if err != nil {
		return err
	}
	codeDigest := sha256.Sum256([]byte(normalizeAuthenticationCode(authentication)))
	digest := requestDigest(struct {
		Purpose    string   `json:"purpose"`
		Method     string   `json:"method"`
		CodeDigest [32]byte `json:"code_digest"`
	}{"billing_bridge_sso", authentication.Method, codeDigest})
	_, err = s.authenticate(ctx, tx, credential, authentication, idempotencyKey, digest, request, storeTime(s.now()))
	return err
}
