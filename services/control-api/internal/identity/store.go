package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountDisabled    = errors.New("account disabled")
	ErrMembershipDisabled = errors.New("membership disabled")
	ErrInvalidSession     = errors.New("invalid session")
	ErrRefreshReplay      = errors.New("refresh token replayed")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrConflict           = errors.New("resource conflict")
)

type Principal struct {
	UserID      uuid.UUID  `json:"user_id"`
	DisplayID   string     `json:"display_id"`
	ScopeID     uuid.UUID  `json:"scope_id"`
	ScopeKind   string     `json:"scope_kind"`
	TenantID    *uuid.UUID `json:"tenant_id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Roles       []string   `json:"roles"`
	Permissions []string   `json:"permissions"`
	// PasswordChangeRequired: an administrator asked for a new password at
	// the next sign-in (migration 404). Until the user changes it, session
	// requests other than reading the session and changing the password are
	// refused with ErrPasswordChangeRequired.
	PasswordChangeRequired bool `json:"password_change_required,omitempty"`
}

type LoginIdentity struct {
	UserID           uuid.UUID
	ScopeID          uuid.UUID
	PasswordHash     string
	UserStatus       string
	MembershipStatus string
}

type SessionInput struct {
	ID                     uuid.UUID
	FamilyID               uuid.UUID
	ParentID               *uuid.UUID
	UserID                 uuid.UUID
	ScopeID                uuid.UUID
	RefreshTokenHash       []byte
	UserAgent              string
	SourceIP               string
	ExpiresAt              time.Time
	RequestID              string
	AuthenticationMethod   string
	passwordLogin          *passwordLogin
	loginChallenge         *LoginChallengeProof
	loginChallengeConsumer LoginChallengeConsumer
}

type GeoAttribution struct {
	CountryCode string
	Region      string
	City        string
	Resolution  string
}

type GeoResolver interface {
	Resolve(context.Context, string) (GeoAttribution, error)
}

type passwordLogin struct {
	password     string
	verifiedHash string
	upgradedHash string
	// legacy: the password matched the imported source hash (plan B); the
	// session consumes that hash and stores upgradedHash in one transaction.
	legacy LegacyPasswordVerifier
}

type RotatedSession struct {
	ID        uuid.UUID
	FamilyID  uuid.UUID
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	ExpiresAt time.Time
	// Reused: a concurrent request already rotated the presented token; this
	// is its live successor and no new refresh token was issued.
	Reused bool
}

type BootstrapResult struct {
	UserID  uuid.UUID
	ScopeID uuid.UUID
	RoleID  uuid.UUID
}

type Store struct {
	pool        *pgxpool.Pool
	auditor     *audit.Log
	now         func() time.Time
	geoResolver GeoResolver
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithGeo(pool, nil)
}

func NewStoreWithGeo(pool *pgxpool.Pool, resolver GeoResolver) *Store {
	return &Store{pool: pool, auditor: audit.New(pool), now: time.Now, geoResolver: resolver}
}

func (s *Store) configured() bool {
	return s != nil && poolConfigured(s.pool) && s.auditor != nil && s.now != nil
}

func poolConfigured(pool *pgxpool.Pool) (configured bool) {
	if pool == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			configured = false
		}
	}()
	return pool.Config() != nil
}

func (s *Store) FindLoginIdentity(ctx context.Context, username string, scopeID *uuid.UUID) (LoginIdentity, error) {
	var identity LoginIdentity
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, m.scope_id, u.password_hash, u.status, m.status
		FROM users u
		JOIN memberships m ON m.user_id = u.id
		JOIN access_scopes scope ON scope.id = m.scope_id
		WHERE u.username = $1
		  AND ($2::uuid IS NULL OR m.scope_id = $2)
		ORDER BY CASE scope.kind WHEN 'platform' THEN 0 ELSE 1 END, m.created_at
		LIMIT 1`, username, scopeID,
	).Scan(
		&identity.UserID,
		&identity.ScopeID,
		&identity.PasswordHash,
		&identity.UserStatus,
		&identity.MembershipStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginIdentity{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginIdentity{}, fmt.Errorf("find login identity: %w", err)
	}
	return identity, nil
}

func (s *Store) RecordLoginFailure(ctx context.Context, login LoginIdentity, request RequestInfo, reason string) error {
	if login.UserID == uuid.Nil || login.ScopeID == uuid.Nil ||
		(reason != "invalid_credentials" && reason != "account_disabled" && reason != "membership_disabled") {
		return ErrInvalidCredentials
	}
	sourceIP := request.SourceIP
	if net.ParseIP(sourceIP) == nil {
		sourceIP = "unknown"
	}
	geo := s.loginGeo(ctx, sourceIP)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      login.ScopeID,
			Action:       "auth.login",
			ResourceType: "user",
			ResourceID:   login.UserID.String(),
			RequestID:    request.RequestID,
			Result:       "denied",
			Payload: map[string]any{
				"reason_code":    reason,
				"source_ip":      sourceIP,
				"geo_code":       geo.CountryCode,
				"geo_region":     geo.Region,
				"geo_city":       geo.City,
				"geo_resolution": geo.Resolution,
				"user_agent":     safeAuditUserAgent(request.UserAgent),
			},
		})
	})
}

func safeAuditUserAgent(value string) string {
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return -1
		}
		return character
	}, value)
	if len(value) > 512 {
		for len(value) > 512 {
			_, size := utf8.DecodeLastRuneInString(value)
			value = value[:len(value)-size]
		}
	}
	return value
}

func (s *Store) CreateSession(ctx context.Context, input SessionInput) (Principal, error) {
	method := input.AuthenticationMethod
	if method == "" {
		method = AuthenticationPassword
	}
	if method != AuthenticationPassword && method != "email_code" && method != "sms_code" ||
		method == AuthenticationPassword && input.passwordLogin == nil ||
		method != AuthenticationPassword && input.passwordLogin != nil {
		return Principal{}, ErrInvalidCredentials
	}
	geo := s.loginGeo(ctx, input.SourceIP)
	var outcome error
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationSessionCreate, []uuid.UUID{input.ScopeID},
		); err != nil {
			return err
		}
		var userStatus, membershipStatus, currentPasswordHash, email, phone string
		if err := tx.QueryRow(ctx, `
			SELECT u.status, m.status, u.password_hash, COALESCE(u.email,''), COALESCE(u.phone,'')
			FROM users u
			JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2
			WHERE u.id = $1
			FOR UPDATE OF u, m`, input.UserID, input.ScopeID,
		).Scan(&userStatus, &membershipStatus, &currentPasswordHash, &email, &phone); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidCredentials
			}
			return err
		}
		if userStatus != "active" {
			return ErrAccountDisabled
		}
		if membershipStatus != "active" {
			return ErrMembershipDisabled
		}
		now := s.now().UTC()
		var passwordUpgrade string
		legacyUpgrade := false
		if input.passwordLogin != nil {
			login := input.passwordLogin
			if login.password == "" || login.verifiedHash == "" {
				return ErrInvalidCredentials
			}
			needsUpgrade := currentPasswordHash == login.verifiedHash && login.upgradedHash != ""
			if login.legacy != nil {
				consumed, err := login.legacy.ConsumeLegacyPasswordTx(ctx, tx, input.UserID)
				if err != nil {
					return err
				}
				if !consumed || currentPasswordHash != login.verifiedHash || login.upgradedHash == "" {
					return ErrInvalidCredentials
				}
				legacyUpgrade = true
			} else if currentPasswordHash != login.verifiedHash {
				verification := verifyPasswordHash(currentPasswordHash, login.password)
				if !verification.matches {
					return ErrInvalidCredentials
				}
				needsUpgrade = verification.needsUpgrade
			}
			if legacyUpgrade {
				if !verifyPasswordHash(login.upgradedHash, login.password).matches {
					return ErrInvalidCredentials
				}
				passwordUpgrade = login.upgradedHash
			} else if needsUpgrade {
				upgraded := verifyPasswordHash(login.upgradedHash, login.password)
				if !upgraded.matches || upgraded.needsUpgrade {
					return ErrInvalidCredentials
				}
				passwordUpgrade = login.upgradedHash
			}
		}
		policy, err := ReadLoginSecurityTx(ctx, tx, input.UserID, input.ScopeID)
		if err != nil {
			return err
		}
		deny := func(denial error, reason string) error {
			outcome = denial
			return s.auditor.Append(ctx, tx, audit.Event{ScopeID: input.ScopeID, ActorUserID: &input.UserID, Action: "auth.login", ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID, Result: "denied", Payload: map[string]any{"reason_code": reason, "login_security_revision": policy.Revision}})
		}
		if err := checkLoginSecurity(policy, input.SourceIP, input.passwordLogin != nil, input.loginChallenge); err != nil {
			return deny(err, "login_security_denied")
		}
		if input.loginChallenge != nil {
			proof := *input.loginChallenge
			if input.passwordLogin != nil {
				if policy.LoginVerification == "none" {
					return deny(ErrLoginChallengeInvalid, "unexpected_login_challenge")
				}
				proof.Channel = policy.LoginVerification
				proof.Identifier = email
				if proof.Channel == "sms" {
					proof.Identifier = phone
				}
			}
			contact := email
			if proof.Channel == "sms" {
				contact = phone
			}
			if err := checkLoginChannelTx(ctx, tx, input.ScopeID, proof.Channel, contact, input.loginChallengeConsumer); err != nil {
				return deny(err, "login_channel_unavailable")
			}
			denial, consumeErr := input.loginChallengeConsumer.ConsumeLoginChallengeTx(ctx, tx, LoginChallengeConsumeInput{UserID: input.UserID, ScopeID: input.ScopeID, PolicyRevision: policy.Revision, Contact: contact, SourceIP: input.SourceIP, RequestID: input.RequestID, Proof: proof})
			if consumeErr != nil {
				return consumeErr
			}
			if denial != nil {
				return deny(denial, "login_challenge_invalid")
			}
			if input.passwordLogin != nil {
				method = "password_" + proof.Channel + "_code"
			}
		} else if input.passwordLogin == nil {
			return deny(ErrLoginChallengeInvalid, "login_challenge_required")
		}
		if passwordUpgrade != "" {
			// A source password that breaks cdnca's policy still signs in
			// once, then the user must choose a new one (ADR 0016 §6.1).
			changeRequired := legacyUpgrade && passwordpolicy.Check(input.passwordLogin.password) != nil
			command, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2,updated_at=$3,
				password_change_required=password_change_required OR $5 WHERE id=$1 AND password_hash=$4`,
				input.UserID, passwordUpgrade, now, currentPasswordHash, changeRequired)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrInvalidCredentials
			}
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO auth_sessions (
				id, family_id, parent_id, user_id, scope_id, refresh_token_hash,
				user_agent, source_ip, created_at, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			input.ID,
			input.FamilyID,
			input.ParentID,
			input.UserID,
			input.ScopeID,
			input.RefreshTokenHash,
			input.UserAgent,
			nullableString(input.SourceIP),
			now,
			input.ExpiresAt,
		)
		if err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      input.ScopeID,
			ActorUserID:  &input.UserID,
			Action:       "auth.login",
			ResourceType: "session_family",
			ResourceID:   input.FamilyID.String(),
			RequestID:    input.RequestID,
			Result:       "success",
			Payload: map[string]any{
				"session_id": input.ID.String(), "authentication_method": method,
				"geo_code": geo.CountryCode, "geo_region": geo.Region, "geo_city": geo.City,
				"geo_resolution": geo.Resolution,
			},
		})
	})
	if err != nil {
		return Principal{}, fmt.Errorf("create session: %w", err)
	}
	if outcome != nil {
		return Principal{}, outcome
	}
	return s.PrincipalForSession(ctx, input.UserID, input.ScopeID, input.ID)
}

func (s *Store) loginGeo(ctx context.Context, sourceIP string) GeoAttribution {
	unknown := GeoAttribution{CountryCode: "unknown", Resolution: "unknown"}
	if s == nil || s.geoResolver == nil || net.ParseIP(sourceIP) == nil {
		return unknown
	}
	value, err := s.geoResolver.Resolve(ctx, sourceIP)
	if err != nil || !validGeoCountry(value.CountryCode) {
		return unknown
	}
	if !validGeoText(value.Region, 128) || !validGeoText(value.City, 128) {
		return unknown
	}
	if value.Resolution == "" {
		value.Resolution = "matched"
	}
	if value.Resolution != "matched" && value.Resolution != "unknown" {
		return unknown
	}
	return value
}

func validGeoCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func validGeoText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && value == strings.TrimSpace(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func (s *Store) RotateSession(
	ctx context.Context,
	oldTokenHash []byte,
	newSessionID uuid.UUID,
	newTokenHash []byte,
	newExpiresAt time.Time,
	requestID string,
	userAgent string,
	sourceIP string,
) (RotatedSession, Principal, error) {
	familyHint, scopeHints, err := collectSessionFamilyAuthorityScopes(ctx, s.pool, oldTokenHash)
	if err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("find refresh session family scopes: %w", err)
	}
	lockedScopes := scopeHints
	if familyHint == uuid.Nil {
		lockedScopes = []uuid.UUID{syntheticSessionScope(oldTokenHash)}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("begin refresh transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := protocol.BeginAuthorityMutation(
		ctx, tx, protocol.OperationSessionRotate, lockedScopes,
	); err != nil {
		return RotatedSession{}, Principal{}, err
	}
	currentFamily, currentScopes, err := collectSessionFamilyAuthorityScopes(ctx, tx, oldTokenHash)
	if err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("recheck refresh session family scopes: %w", err)
	}
	if familyHint == uuid.Nil || currentFamily != familyHint || !equalAuthorityScopes(currentScopes, scopeHints) {
		return RotatedSession{}, Principal{}, ErrInvalidSession
	}

	var old RotatedSession
	var userStatus, membershipStatus string
	var usedAt, revokedAt *time.Time
	var replacedBy *uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT sess.id, sess.family_id, sess.user_id, sess.scope_id, sess.expires_at,
		       sess.used_at, sess.revoked_at, sess.replaced_by_id, u.status, m.status
		FROM auth_sessions sess
		JOIN users u ON u.id = sess.user_id
		JOIN memberships m ON m.user_id = sess.user_id AND m.scope_id = sess.scope_id
		WHERE sess.refresh_token_hash = $1
		FOR UPDATE OF sess, u, m`, oldTokenHash,
	).Scan(
		&old.ID,
		&old.FamilyID,
		&old.UserID,
		&old.ScopeID,
		&old.ExpiresAt,
		&usedAt,
		&revokedAt,
		&replacedBy,
		&userStatus,
		&membershipStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return RotatedSession{}, Principal{}, ErrInvalidSession
	}
	if err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("find refresh session: %w", err)
	}
	if old.FamilyID != familyHint {
		return RotatedSession{}, Principal{}, ErrInvalidSession
	}

	now := s.now().UTC()
	if usedAt != nil || replacedBy != nil {
		// Two tabs (or a page load racing the renewal timer) send the same
		// cookie: the loser presents a token its sibling rotated a moment ago.
		// Within refreshReuseGrace that is not theft; answer with the live
		// successor (no new refresh token: the browser already holds it).
		if revokedAt == nil && userStatus == "active" && membershipStatus == "active" {
			successor, ok, err := refreshGraceSuccessor(ctx, tx, old, usedAt, replacedBy, now)
			if err != nil {
				return RotatedSession{}, Principal{}, err
			}
			if ok {
				if err := s.auditor.Append(ctx, tx, audit.Event{
					ScopeID:      old.ScopeID,
					ActorUserID:  &old.UserID,
					Action:       "auth.refresh",
					ResourceType: "session_family",
					ResourceID:   old.FamilyID.String(),
					RequestID:    requestID,
					Result:       "success",
					Payload: map[string]any{
						"previous_session_id": old.ID.String(),
						"session_id":          successor.ID.String(),
						"concurrent_reuse":    true,
					},
				}); err != nil {
					return RotatedSession{}, Principal{}, err
				}
				if err := tx.Commit(ctx); err != nil {
					return RotatedSession{}, Principal{}, fmt.Errorf("commit concurrent refresh: %w", err)
				}
				principal, err := s.PrincipalForSession(ctx, successor.UserID, successor.ScopeID, successor.ID)
				if err != nil {
					return RotatedSession{}, Principal{}, err
				}
				return successor, principal, nil
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE auth_sessions
			SET revoked_at = COALESCE(revoked_at, $2),
			    revocation_reason = COALESCE(revocation_reason, 'refresh_replay')
			WHERE family_id = $1`, old.FamilyID, now); err != nil {
			return RotatedSession{}, Principal{}, fmt.Errorf("revoke replayed family: %w", err)
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      old.ScopeID,
			ActorUserID:  &old.UserID,
			Action:       "auth.refresh.replay",
			ResourceType: "session_family",
			ResourceID:   old.FamilyID.String(),
			RequestID:    requestID,
			Result:       "denied",
			Payload:      map[string]any{"replayed_session_id": old.ID.String()},
		}); err != nil {
			return RotatedSession{}, Principal{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RotatedSession{}, Principal{}, fmt.Errorf("commit replay revocation: %w", err)
		}
		return RotatedSession{}, Principal{}, ErrRefreshReplay
	}
	if revokedAt != nil || !now.Before(old.ExpiresAt) {
		return RotatedSession{}, Principal{}, ErrInvalidSession
	}
	if userStatus != "active" || membershipStatus != "active" {
		reason := "account_disabled"
		resultErr := ErrAccountDisabled
		if userStatus == "active" {
			reason = "membership_disabled"
			resultErr = ErrMembershipDisabled
		}
		if _, err := tx.Exec(ctx, `
			UPDATE auth_sessions
			SET revoked_at = COALESCE(revoked_at, $2),
			    revocation_reason = COALESCE(revocation_reason, $3)
			WHERE family_id = $1`, old.FamilyID, now, reason); err != nil {
			return RotatedSession{}, Principal{}, fmt.Errorf("revoke disabled principal sessions: %w", err)
		}
		if err := s.auditor.Append(ctx, tx, refreshPrincipalDisabledAuditEvent(old, requestID, reason)); err != nil {
			return RotatedSession{}, Principal{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return RotatedSession{}, Principal{}, fmt.Errorf("commit disabled principal revocation: %w", err)
		}
		return RotatedSession{}, Principal{}, resultErr
	}

	current := RotatedSession{
		ID:        newSessionID,
		FamilyID:  old.FamilyID,
		UserID:    old.UserID,
		ScopeID:   old.ScopeID,
		ExpiresAt: newExpiresAt,
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth_sessions (
			id, family_id, parent_id, user_id, scope_id, refresh_token_hash,
			user_agent, source_ip, created_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		current.ID,
		current.FamilyID,
		old.ID,
		current.UserID,
		current.ScopeID,
		newTokenHash,
		userAgent,
		nullableString(sourceIP),
		now,
		current.ExpiresAt,
	); err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("insert rotated session: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE auth_sessions
		SET used_at = $2, replaced_by_id = $3
		WHERE id = $1`, old.ID, now, current.ID); err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("consume refresh session: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      old.ScopeID,
		ActorUserID:  &old.UserID,
		Action:       "auth.refresh",
		ResourceType: "session_family",
		ResourceID:   old.FamilyID.String(),
		RequestID:    requestID,
		Result:       "success",
		Payload: map[string]any{
			"previous_session_id": old.ID.String(),
			"session_id":          current.ID.String(),
		},
	}); err != nil {
		return RotatedSession{}, Principal{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RotatedSession{}, Principal{}, fmt.Errorf("commit session rotation: %w", err)
	}
	principal, err := s.PrincipalForSession(ctx, current.UserID, current.ScopeID, current.ID)
	if err != nil {
		return RotatedSession{}, Principal{}, err
	}
	return current, principal, nil
}

// refreshReuseGrace is how long a just-rotated refresh token may still be
// presented by a concurrent request of the same browser.
const refreshReuseGrace = 30 * time.Second

// refreshGraceSuccessor returns the direct successor of a token rotated within
// refreshReuseGrace, provided it is still live (unused, unrevoked, unexpired).
func refreshGraceSuccessor(
	ctx context.Context,
	tx pgx.Tx,
	old RotatedSession,
	usedAt *time.Time,
	replacedBy *uuid.UUID,
	now time.Time,
) (RotatedSession, bool, error) {
	if usedAt == nil || replacedBy == nil || now.Sub(*usedAt) > refreshReuseGrace || now.Before(usedAt.Add(-refreshReuseGrace)) {
		return RotatedSession{}, false, nil
	}
	successor := RotatedSession{ID: *replacedBy, FamilyID: old.FamilyID, UserID: old.UserID, ScopeID: old.ScopeID}
	var successorUsedAt, successorRevokedAt *time.Time
	err := tx.QueryRow(ctx, `
		SELECT expires_at, used_at, revoked_at FROM auth_sessions
		WHERE id = $1 AND family_id = $2 AND user_id = $3 AND scope_id = $4
		FOR UPDATE`, successor.ID, old.FamilyID, old.UserID, old.ScopeID,
	).Scan(&successor.ExpiresAt, &successorUsedAt, &successorRevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RotatedSession{}, false, nil
	}
	if err != nil {
		return RotatedSession{}, false, fmt.Errorf("find refresh successor: %w", err)
	}
	if successorUsedAt != nil || successorRevokedAt != nil || !now.Before(successor.ExpiresAt) {
		return RotatedSession{}, false, nil
	}
	successor.Reused = true
	return successor, true, nil
}

func refreshPrincipalDisabledAuditEvent(old RotatedSession, requestID, reason string) audit.Event {
	return audit.Event{
		ScopeID:      old.ScopeID,
		ActorUserID:  &old.UserID,
		Action:       "auth.refresh",
		ResourceType: "session_family",
		ResourceID:   old.FamilyID.String(),
		RequestID:    requestID,
		Result:       "denied",
		Payload: map[string]any{
			"reason_code":        reason,
			"revoked_session_id": old.ID.String(),
		},
	}
}

func (s *Store) RevokeSessionFamily(ctx context.Context, tokenHash []byte, requestID string) error {
	familyHint, scopeHints, err := collectSessionFamilyAuthorityScopes(ctx, s.pool, tokenHash)
	if err != nil {
		return fmt.Errorf("find logout session family scopes: %w", err)
	}
	lockedScopes := scopeHints
	if familyHint == uuid.Nil {
		lockedScopes = []uuid.UUID{syntheticSessionScope(tokenHash)}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin logout transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := protocol.BeginAuthorityMutation(
		ctx, tx, protocol.OperationSessionRevoke, lockedScopes,
	); err != nil {
		return err
	}
	currentFamily, currentScopes, err := collectSessionFamilyAuthorityScopes(ctx, tx, tokenHash)
	if err != nil {
		return fmt.Errorf("recheck logout session family scopes: %w", err)
	}
	if familyHint == uuid.Nil {
		if currentFamily != uuid.Nil || len(currentScopes) != 0 {
			return ErrInvalidSession
		}
		return tx.Commit(ctx)
	}
	if currentFamily != familyHint || !equalAuthorityScopes(currentScopes, scopeHints) {
		return ErrInvalidSession
	}

	var familyID, userID, actualScopeID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT family_id, user_id, scope_id
		FROM auth_sessions
		WHERE refresh_token_hash = $1
		FOR UPDATE`, tokenHash,
	).Scan(&familyID, &userID, &actualScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidSession
	}
	if err != nil {
		return fmt.Errorf("find logout session: %w", err)
	}
	if familyID != familyHint {
		return ErrInvalidSession
	}
	now := s.now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE auth_sessions
		SET revoked_at = COALESCE(revoked_at, $2),
		    revocation_reason = COALESCE(revocation_reason, 'logout')
		WHERE family_id = $1`, familyID, now); err != nil {
		return fmt.Errorf("revoke session family: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID:      actualScopeID,
		ActorUserID:  &userID,
		Action:       "auth.logout",
		ResourceType: "session_family",
		ResourceID:   familyID.String(),
		RequestID:    requestID,
		Result:       "success",
		Payload:      map[string]any{},
	}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit logout: %w", err)
	}
	return nil
}

func syntheticSessionScope(tokenHash []byte) uuid.UUID {
	name := append([]byte("cdnca/iam-stage2a/missing-session/v1\x00"), tokenHash...)
	return uuid.NewSHA1(uuid.NameSpaceOID, name)
}

func (s *Store) PrincipalForSession(
	ctx context.Context,
	userID uuid.UUID,
	scopeID uuid.UUID,
	sessionID uuid.UUID,
) (Principal, error) {
	principal := Principal{
		UserID:      userID,
		ScopeID:     scopeID,
		Roles:       []string{},
		Permissions: []string{},
	}
	err := s.pool.QueryRow(ctx, `
		SELECT u.display_id::text, scope.kind, scope.tenant_id, u.username, u.display_name, u.password_change_required,
		       COALESCE(array_agg(DISTINCT r.name) FILTER (WHERE r.name IS NOT NULL), '{}'::text[]),
		       COALESCE(array_agg(DISTINCT rp.permission_name) FILTER (WHERE rp.permission_name IS NOT NULL), '{}'::text[])
		FROM auth_sessions sess
		JOIN users u ON u.id = sess.user_id AND u.status = 'active'
		JOIN memberships m ON m.user_id = sess.user_id AND m.scope_id = sess.scope_id AND m.status = 'active'
		JOIN access_scopes scope ON scope.id = sess.scope_id
		LEFT JOIN role_assignments ra ON ra.scope_id = sess.scope_id AND ra.user_id = sess.user_id
		LEFT JOIN roles r ON r.id = ra.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE sess.id = $1
		  AND sess.user_id = $2
		  AND sess.scope_id = $3
		  AND sess.revoked_at IS NULL
		  AND sess.expires_at > $4
		GROUP BY u.display_id, scope.kind, scope.tenant_id, u.username, u.display_name, u.password_change_required`,
		sessionID, userID, scopeID, s.now().UTC(),
	).Scan(
		&principal.DisplayID,
		&principal.ScopeKind,
		&principal.TenantID,
		&principal.Username,
		&principal.DisplayName,
		&principal.PasswordChangeRequired,
		&principal.Roles,
		&principal.Permissions,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, ErrInvalidSession
	}
	if err != nil {
		return Principal{}, fmt.Errorf("load session principal: %w", err)
	}
	return principal, nil
}

func (s *Store) BootstrapPlatformUser(
	ctx context.Context,
	username string,
	displayName string,
	passwordHash string,
	requestID string,
) (BootstrapResult, error) {
	return s.BootstrapPlatformUserWithEmail(ctx, username, displayName, "", passwordHash, requestID)
}

func (s *Store) BootstrapPlatformUserWithEmail(
	ctx context.Context,
	username string,
	displayName string,
	email string,
	passwordHash string,
	requestID string,
) (BootstrapResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email != "" {
		address, err := mail.ParseAddress(email)
		if err != nil || address.Address != email || len(email) > 254 {
			return BootstrapResult{}, ErrInvalidUserInput
		}
	}
	var scopeCandidate uuid.UUID
	hadScopeHint := true
	err := s.pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind = 'platform'`).Scan(&scopeCandidate)
	if errors.Is(err, pgx.ErrNoRows) {
		hadScopeHint = false
		scopeCandidate, err = newUUID()
	}
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("find platform scope candidate: %w", err)
	}
	var result BootstrapResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationBootstrap, []uuid.UUID{scopeCandidate},
		); err != nil {
			return err
		}
		var currentScopeID uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT id FROM access_scopes WHERE kind = 'platform' FOR UPDATE`,
		).Scan(&currentScopeID)
		if errors.Is(err, pgx.ErrNoRows) {
			if hadScopeHint {
				return ErrConflict
			}
			result.ScopeID = scopeCandidate
			if _, err := tx.Exec(ctx,
				"INSERT INTO access_scopes (id, kind) VALUES ($1, 'platform')",
				result.ScopeID,
			); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if currentScopeID != scopeCandidate {
			return ErrConflict
		} else {
			result.ScopeID = currentScopeID
		}

		result.UserID, err = newUUID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (id, username, display_name, email, password_hash)
			VALUES ($1, $2, $3, $4, $5)`, result.UserID, username, displayName, nullableString(email), passwordHash); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO memberships (scope_id, user_id)
			VALUES ($1, $2)`, result.ScopeID, result.UserID); err != nil {
			return err
		}

		candidateRoleID, err := newUUID()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO roles (id, scope_id, name, description, system_role)
			VALUES ($1, $2, 'platform_owner', 'Initial platform owner', true)
			ON CONFLICT (scope_id, name) DO NOTHING`, candidateRoleID, result.ScopeID); err != nil {
			return err
		}
		var systemRole bool
		if err := tx.QueryRow(ctx, `
			SELECT id, system_role
			FROM roles
			WHERE scope_id = $1 AND name = 'platform_owner'`, result.ScopeID).Scan(&result.RoleID, &systemRole); err != nil {
			return err
		}
		if !systemRole {
			return ErrConflict
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_name)
			SELECT $1, name FROM permissions WHERE name <> 'jobs.manage'
			ON CONFLICT DO NOTHING`, result.RoleID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_assignments (scope_id, user_id, role_id)
			VALUES ($1, $2, $3)`, result.ScopeID, result.UserID, result.RoleID); err != nil {
			return err
		}
		// Fresh installs migrate before the first platform member exists, so
		// migration 137 could not seed the default TCP billing factor (it needs
		// created_by_user_id). Seed the same default here, once per platform.
		if _, err := tx.Exec(ctx, `
			INSERT INTO tcp_billing_factor_revisions(
				id,platform_scope_id,revision,factor,factor_numerator,factor_denominator,
				effective_at,reason,created_by_user_id,created_at)
			SELECT gen_random_uuid(),$1,1,'1.0',1,1,'2000-01-01T00:00:00Z'::timestamptz,
			       '默认 TCP 流量计费系数',$2,now()
			WHERE NOT EXISTS (SELECT 1 FROM tcp_billing_factor_revisions WHERE platform_scope_id=$1)`,
			result.ScopeID, result.UserID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID:      result.ScopeID,
			ActorUserID:  &result.UserID,
			Action:       "identity.bootstrap_user",
			ResourceType: "user",
			ResourceID:   result.UserID.String(),
			RequestID:    requestID,
			Result:       "success",
			Payload:      map[string]any{"username": username},
		})
	})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("bootstrap platform user: %w", err)
	}
	return result, nil
}

func newUUID() (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate UUIDv7: %w", err)
	}
	return id, nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(err, &pgErr) && pgErr.SQLState() == "23505"
}
