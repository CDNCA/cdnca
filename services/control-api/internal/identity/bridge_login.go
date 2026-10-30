package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuthenticationBillingBridge is the sign-in method of a billing bridge
// one-time ticket (ADR 0019 BB-05); auth.login records it as
// authentication_method and auth.session.bridge_sso is written beside it.
const AuthenticationBillingBridge = "billing_bridge"

// BridgeTicketConsumer runs inside the session transaction, after the user
// and membership rows are locked: it claims the ticket (single use) and
// returns the user and scope it was issued for. sessionID is the session
// being created (the ticket records it). Any error aborts the sign-in.
type BridgeTicketConsumer func(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID) (userID, scopeID uuid.UUID, err error)

// LoginBridge signs a customer in from a billing bridge ticket: an ordinary
// session of the customer itself (not impersonation). The ticket, the user
// and membership status, and the login IP allowlist are checked in one
// transaction; the account's own e-mail/SMS login verification is the
// billing system's job (Q4 a), the caller enforces sso_require_mfa.
func (s *Service) LoginBridge(ctx context.Context, userID, scopeID uuid.UUID, consume BridgeTicketConsumer,
	request RequestInfo,
) (AuthResult, error) {
	if userID == uuid.Nil || scopeID == uuid.Nil || consume == nil {
		return AuthResult{}, ErrInvalidCredentials
	}
	if err := s.checkAdminAccessForScope(ctx, scopeID, request.SourceIP); err != nil {
		return AuthResult{}, err
	}
	sessionID, err := newUUID()
	if err != nil {
		return AuthResult{}, err
	}
	familyID, err := newUUID()
	if err != nil {
		return AuthResult{}, err
	}
	refreshToken, refreshHash, err := generateRefreshToken()
	if err != nil {
		return AuthResult{}, err
	}
	refreshTTL, err := s.sessionTTL(ctx, scopeID)
	if err != nil {
		return AuthResult{}, err
	}
	refreshExpires := s.now().UTC().Add(refreshTTL)
	principal, err := s.store.createBridgeSession(ctx, SessionInput{ID: sessionID, FamilyID: familyID, UserID: userID,
		ScopeID: scopeID, RefreshTokenHash: refreshHash, UserAgent: request.UserAgent, SourceIP: request.SourceIP,
		ExpiresAt: refreshExpires, RequestID: request.RequestID, AuthenticationMethod: AuthenticationBillingBridge}, consume)
	if err != nil {
		return AuthResult{}, err
	}
	accessToken, accessExpires, err := s.tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		return AuthResult{}, err
	}
	s.recordSessionRegion(ctx, familyID, userID, request.SourceIP)
	return AuthResult{AccessToken: accessToken, ExpiresAt: accessExpires, RefreshToken: refreshToken,
		RefreshExpiresAt: refreshExpires, Principal: principal}, nil
}

func (s *Store) createBridgeSession(ctx context.Context, input SessionInput, consume BridgeTicketConsumer) (Principal, error) {
	geo := s.loginGeo(ctx, input.SourceIP)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationSessionCreate, []uuid.UUID{input.ScopeID},
		); err != nil {
			return err
		}
		var userStatus, membershipStatus string
		if err := tx.QueryRow(ctx, `SELECT u.status, m.status FROM users u
			JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2
			WHERE u.id = $1 FOR UPDATE OF u, m`, input.UserID, input.ScopeID).Scan(&userStatus, &membershipStatus); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidCredentials
			}
			return err
		}
		if userStatus != "active" || membershipStatus != "active" {
			return ErrInvalidCredentials
		}
		userID, scopeID, err := consume(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if userID != input.UserID || scopeID != input.ScopeID {
			return ErrInvalidCredentials
		}
		policy, err := ReadLoginSecurityTx(ctx, tx, input.UserID, input.ScopeID)
		if err != nil {
			return err
		}
		if err := checkLoginSecurity(policy, input.SourceIP, true, &LoginChallengeProof{}); err != nil {
			return err
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO auth_sessions (
				id, family_id, parent_id, user_id, scope_id, refresh_token_hash, user_agent, source_ip, created_at, expires_at
			) VALUES ($1, $2, NULL, $3, $4, $5, $6, $7, $8, $9)`, input.ID, input.FamilyID, input.UserID, input.ScopeID,
			input.RefreshTokenHash, input.UserAgent, nullableString(input.SourceIP), now, input.ExpiresAt); err != nil {
			return err
		}
		payload := map[string]any{"session_id": input.ID.String(), "authentication_method": AuthenticationBillingBridge,
			"geo_code": geo.CountryCode, "geo_region": geo.Region, "geo_city": geo.City, "geo_resolution": geo.Resolution}
		if err := s.auditor.Append(ctx, tx, audit.Event{ScopeID: input.ScopeID, ActorUserID: &input.UserID,
			Action: "auth.login", ResourceType: "session_family", ResourceID: input.FamilyID.String(),
			RequestID: input.RequestID, Result: "success", Payload: payload}); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: input.ScopeID, ActorUserID: &input.UserID,
			Action: "auth.session.bridge_sso", ResourceType: "session_family", ResourceID: input.FamilyID.String(),
			RequestID: input.RequestID, Result: "success", Payload: payload})
	})
	if err != nil {
		return Principal{}, fmt.Errorf("create bridge session: %w", err)
	}
	return s.PrincipalForSession(ctx, input.UserID, input.ScopeID, input.ID)
}
