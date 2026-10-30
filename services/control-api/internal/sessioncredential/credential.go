package sessioncredential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidConfig     = errors.New("session credential verifier configuration invalid")
	ErrInvalidCredential = errors.New("session credential invalid")
	ErrProtocolRequired  = errors.New("IAM global lock protocol required")
	ErrUnavailable       = errors.New("session credential verifier unavailable")
)

type Clock func() time.Time

type Verifier struct {
	tokens *identity.TokenManager
	now    Clock
}

// Credential is a sealed result of token verification and locked PostgreSQL fact checks.
type Credential struct {
	userID    uuid.UUID
	scopeID   uuid.UUID
	tenantID  uuid.UUID
	sessionID uuid.UUID
	scopeKind string
	createdAt time.Time
	expiresAt time.Time
}

func NewVerifier(tokens *identity.TokenManager, now Clock) (*Verifier, error) {
	if tokens == nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Verifier{tokens: tokens, now: now}, nil
}

// Configured reports whether NewVerifier initialized the verifier's in-memory dependencies.
// It does not check dependency health.
func (verifier *Verifier) Configured() bool {
	return verifier != nil && verifier.tokens.Configured() && verifier.now != nil
}

// CredentialScope verifies the access-token signature and returns its signed scope.
// It performs no PostgreSQL access and does not return an authenticated credential.
func (verifier *Verifier) CredentialScope(rawToken string) (uuid.UUID, error) {
	if verifier == nil || verifier.tokens == nil || len(rawToken) == 0 || len(rawToken) > 8192 {
		return uuid.Nil, ErrInvalidCredential
	}
	_, scopeID, _, err := verifier.tokens.Parse(rawToken)
	if err != nil || scopeID == uuid.Nil {
		return uuid.Nil, ErrInvalidCredential
	}
	return scopeID, nil
}

func (verifier *Verifier) VerifyTx(
	ctx context.Context,
	tx pgx.Tx,
	rawToken string,
	lockedScopes []uuid.UUID,
) (Credential, error) {
	if verifier == nil || verifier.tokens == nil || verifier.now == nil || tx == nil ||
		len(rawToken) == 0 || len(rawToken) > 8192 || len(lockedScopes) == 0 {
		return Credential{}, ErrInvalidCredential
	}
	userID, scopeID, sessionID, err := verifier.tokens.Parse(rawToken)
	if err != nil || userID == uuid.Nil || scopeID == uuid.Nil || sessionID == uuid.Nil ||
		!containsScope(lockedScopes, scopeID) {
		return Credential{}, ErrInvalidCredential
	}
	if _, err := tx.Exec(ctx, `SELECT iam_assert_scope_locks_v1($1::uuid[])`, lockedScopes); err != nil {
		return Credential{}, fmt.Errorf("%w: assert session credential locks", ErrProtocolRequired)
	}

	var scopeKind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR KEY SHARE`, scopeID).Scan(&scopeKind, &tenantID); err != nil {
		return Credential{}, credentialFactError(err)
	}
	if scopeKind != "platform" && scopeKind != "tenant" ||
		scopeKind == "platform" && tenantID != nil ||
		scopeKind == "tenant" && (tenantID == nil || *tenantID == uuid.Nil) {
		return Credential{}, ErrInvalidCredential
	}
	if tenantID != nil {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).Scan(&status); err != nil {
			return Credential{}, credentialFactError(err)
		}
		if status != "active" {
			return Credential{}, ErrInvalidCredential
		}
	}
	var userStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, userID).Scan(&userStatus); err != nil {
		return Credential{}, credentialFactError(err)
	}
	var membershipStatus string
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, scopeID, userID).Scan(&membershipStatus); err != nil {
		return Credential{}, credentialFactError(err)
	}
	var createdAt, expiresAt time.Time
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT created_at,expires_at,revoked_at FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR SHARE`, sessionID, userID, scopeID).Scan(
		&createdAt, &expiresAt, &revokedAt); err != nil {
		return Credential{}, credentialFactError(err)
	}
	now := verifier.now().UTC()
	if userStatus != "active" || membershipStatus != "active" || revokedAt != nil ||
		createdAt.IsZero() || !createdAt.Before(expiresAt) || !now.Before(expiresAt) {
		return Credential{}, ErrInvalidCredential
	}
	credential := Credential{
		userID: userID, scopeID: scopeID, sessionID: sessionID, scopeKind: scopeKind,
		createdAt: createdAt.UTC(), expiresAt: expiresAt.UTC(),
	}
	if tenantID != nil {
		credential.tenantID = *tenantID
	}
	if !credential.Valid() {
		return Credential{}, ErrInvalidCredential
	}
	return credential, nil
}

func (credential Credential) UserID() uuid.UUID    { return credential.userID }
func (credential Credential) ScopeID() uuid.UUID   { return credential.scopeID }
func (credential Credential) SessionID() uuid.UUID { return credential.sessionID }
func (credential Credential) ScopeKind() string    { return credential.scopeKind }
func (credential Credential) CreatedAt() time.Time { return credential.createdAt }
func (credential Credential) ExpiresAt() time.Time { return credential.expiresAt }

func (credential Credential) TenantID() (uuid.UUID, bool) {
	return credential.tenantID, credential.tenantID != uuid.Nil
}

func (credential Credential) Valid() bool {
	if credential.userID == uuid.Nil || credential.scopeID == uuid.Nil ||
		credential.sessionID == uuid.Nil || credential.createdAt.IsZero() ||
		!credential.createdAt.Before(credential.expiresAt) {
		return false
	}
	return credential.scopeKind == "platform" && credential.tenantID == uuid.Nil ||
		credential.scopeKind == "tenant" && credential.tenantID != uuid.Nil
}

func (Credential) String() string   { return "sessioncredential.Credential{redacted}" }
func (Credential) GoString() string { return "sessioncredential.Credential{redacted}" }

func (Credential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("session credential serialization forbidden")
}

func credentialFactError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidCredential
	}
	return fmt.Errorf("%w: read session credential facts", ErrUnavailable)
}

func containsScope(scopes []uuid.UUID, wanted uuid.UUID) bool {
	for _, scopeID := range scopes {
		if scopeID == wanted {
			return true
		}
	}
	return false
}

var _ json.Marshaler = Credential{}
