package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ImpersonationDelegateUserAgent marks the auth_sessions row that carries an
// authorized impersonation session (fix-imperson, 1.0.35).
const ImpersonationDelegateUserAgent = "cdnca-impersonation"

// ImpersonationAccessToken returns a short-lived access token for the target
// user of an already authorized impersonation session. Every handler then sees
// the target's own session: the ones that only authenticate the Bearer, and the
// ones that re-verify the raw token or the session ID in their transaction
// (iamlock, rbacmanager). The backing auth_sessions row has the impersonation
// session's ID and expiry; its refresh token is random and never issued, and
// the access token never leaves the process (it only replaces the request's
// Authorization header). A revoked or expired row is refused.
func (s *Service) ImpersonationAccessToken(
	ctx context.Context, sessionID, userID, scopeID uuid.UUID, expiresAt time.Time,
) (string, error) {
	if s == nil || !s.store.configured() || !s.tokens.Configured() ||
		sessionID == uuid.Nil || userID == uuid.Nil || scopeID == uuid.Nil {
		return "", ErrInvalidSession
	}
	now := s.now().UTC()
	if !now.Before(expiresAt) {
		return "", ErrInvalidSession
	}
	active, found, err := s.store.delegateSessionState(ctx, sessionID, userID, scopeID, now)
	if err != nil {
		return "", err
	}
	if found && !active {
		return "", ErrInvalidSession
	}
	if !found {
		if err := s.store.createDelegateSession(ctx, sessionID, userID, scopeID, now, expiresAt.UTC()); err != nil {
			return "", err
		}
	}
	token, _, err := s.tokens.Mint(userID, scopeID, sessionID)
	return token, err
}

func (s *Store) delegateSessionState(
	ctx context.Context, sessionID, userID, scopeID uuid.UUID, now time.Time,
) (active, found bool, err error) {
	var expiresAt time.Time
	var revokedAt *time.Time
	err = s.pool.QueryRow(ctx, `SELECT expires_at,revoked_at FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3`, sessionID, userID, scopeID).Scan(&expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read impersonation delegate session: %w", err)
	}
	return revokedAt == nil && now.Before(expiresAt), true, nil
}

func (s *Store) createDelegateSession(
	ctx context.Context, sessionID, userID, scopeID uuid.UUID, now, expiresAt time.Time,
) error {
	refresh := make([]byte, 32)
	if _, err := rand.Read(refresh); err != nil {
		return fmt.Errorf("generate impersonation delegate secret: %w", err)
	}
	digest := sha256.Sum256(refresh)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationSessionCreate, []uuid.UUID{scopeID},
		); err != nil {
			return err
		}
		// A concurrent first request of the same impersonation session may have
		// inserted it already; the row is identical in what matters.
		_, err := tx.Exec(ctx, `INSERT INTO auth_sessions (
				id,family_id,user_id,scope_id,refresh_token_hash,user_agent,created_at,expires_at
			) VALUES ($1,$1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
			sessionID, userID, scopeID, digest[:], ImpersonationDelegateUserAgent, now, expiresAt)
		if err != nil {
			return fmt.Errorf("create impersonation delegate session: %w", err)
		}
		return nil
	})
}
