package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type RequestInfo struct {
	RequestID string
	UserAgent string
	SourceIP  string
}

type LoginInput struct {
	Username  string
	Password  string
	ScopeID   *uuid.UUID
	Challenge *LoginChallengeProof
	// Captcha is the solved built-in sign-in CAPTCHA, required once the
	// throttle's CAPTCHA threshold is reached.
	Captcha *LoginCaptchaProof
}

type VerifiedLoginInput struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	Method    string
	Challenge *LoginChallengeProof
}

const AuthenticationPassword = "password"

type AuthResult struct {
	AccessToken      string
	ExpiresAt        time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	Principal        Principal
}

type AuthenticatedSession struct {
	SessionID uuid.UUID
	Principal Principal
}

type Service struct {
	store                              *Store
	tokens                             *TokenManager
	refreshTTL                         time.Duration
	dummyHash                          string
	now                                func() time.Time
	managedPasswordResetStepUpConsumer ManagedPasswordResetStepUpConsumer
	publicSettings                     systemusersettings.PublicSettingsReader
	loginChallengeConsumer             LoginChallengeConsumer
	secondaryVerificationNotifier      SecondaryVerificationNotifier
	throttleKey                        []byte
	adminAccess                        adminAccessCache
	regionResolver                     RegionResolver
	regionPolicy                       sessionRegionPolicy
	legacyPasswords                    LegacyPasswordVerifier
	loginAllow                         LoginAllowRecorder
}

// LoginAllowRecorder is told about every successful sign-in (auto defense
// puts the source address on its allow list, ADR 0010 §7.2 item 3). It runs
// after the session exists; a failure is logged, never a sign-in failure.
type LoginAllowRecorder interface {
	AllowAdminLogin(ctx context.Context, scopeID, userID uuid.UUID, sourceIP, requestID string) error
}

// SetLoginAllowRecorder attaches the sign-in source recorder (nil: none).
func (s *Service) SetLoginAllowRecorder(recorder LoginAllowRecorder) {
	if s != nil {
		s.loginAllow = recorder
	}
}

// SetPublicSettingsReader attaches the platform policy projection used by
// session creation. A nil reader keeps the configured compatibility TTL.
func (s *Service) SetPublicSettingsReader(reader systemusersettings.PublicSettingsReader) {
	if s != nil {
		s.publicSettings = reader
	}
}

func NewService(store *Store, tokens *TokenManager, refreshTTL time.Duration) (*Service, error) {
	if refreshTTL <= 0 {
		return nil, errors.New("refresh token TTL must be positive")
	}
	dummyHash, err := HashPassword("invalid-credential-placeholder")
	if err != nil {
		return nil, fmt.Errorf("create timing-safe password placeholder: %w", err)
	}
	return &Service{
		store:      store,
		tokens:     tokens,
		refreshTTL: refreshTTL,
		dummyHash:  dummyHash,
		now:        time.Now,
	}, nil
}

// Configured reports whether NewService initialized the service's in-memory dependencies.
// It does not check dependency health.
func (s *Service) Configured() bool {
	return s != nil && s.store.configured() && s.tokens.Configured() &&
		s.refreshTTL > 0 && s.dummyHash != "" && s.now != nil
}

func (s *Service) Login(ctx context.Context, input LoginInput, request RequestInfo) (AuthResult, error) {
	reservation, err := s.reserveLoginAttempt(ctx, input.Username, request, input.Captcha)
	if err != nil {
		return AuthResult{}, err
	}
	login, password, err := s.verifyPasswordLogin(ctx, input, request)
	if err != nil {
		reservation.settle(ctx, err)
		return AuthResult{}, err
	}
	if err := s.checkAdminAccessForScope(ctx, login.ScopeID, request.SourceIP); err != nil {
		reservation.settle(ctx, errPasswordAccepted)
		return AuthResult{}, err
	}
	result, err := s.createSession(ctx, login.UserID, login.ScopeID, AuthenticationPassword, password, input.Challenge, request)
	if err != nil {
		// The password was right; a missing or wrong sign-in code is not a
		// password failure.
		reservation.settle(ctx, errPasswordAccepted)
		return AuthResult{}, err
	}
	reservation.settle(ctx, nil)
	return result, nil
}

func (s *Service) verifyPasswordLogin(ctx context.Context, input LoginInput, request RequestInfo) (LoginIdentity, *passwordLogin, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	if len(input.Username) < 3 || len(input.Username) > 128 || len(input.Password) == 0 || len(input.Password) > 1024 {
		return LoginIdentity{}, nil, ErrInvalidCredentials
	}
	login, err := s.store.FindLoginIdentity(ctx, input.Username, input.ScopeID)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			_ = VerifyPassword(s.dummyHash, input.Password)
		}
		return LoginIdentity{}, nil, err
	}
	deny := func(reason string, denial error) (LoginIdentity, *passwordLogin, error) {
		if err := s.store.RecordLoginFailure(ctx, login, request, reason); err != nil {
			return LoginIdentity{}, nil, fmt.Errorf("record login failure: %w", err)
		}
		return LoginIdentity{}, nil, denial
	}
	verification := verifyPasswordHash(login.PasswordHash, input.Password)
	legacy := false
	if !verification.matches && s.legacyPasswords != nil {
		// Plan B (ADR 0016 §6.1): an imported user's source hash. A miss is
		// the same invalid_credentials failure, counted by the same limiter.
		matched, err := s.legacyPasswords.VerifyLegacyPassword(ctx, login.UserID, input.Password)
		if err != nil {
			return LoginIdentity{}, nil, err
		}
		legacy = matched
	}
	if !verification.matches && !legacy {
		if !verification.validHash || verification.weakHash {
			_ = VerifyPassword(s.dummyHash, input.Password)
		}
		return deny("invalid_credentials", ErrInvalidCredentials)
	}
	if login.UserStatus != "active" {
		return deny("account_disabled", ErrAccountDisabled)
	}
	if login.MembershipStatus != "active" {
		return deny("membership_disabled", ErrMembershipDisabled)
	}
	if legacy {
		upgraded, err := hashLegacyUpgrade(input.Password)
		if err != nil {
			return LoginIdentity{}, nil, err
		}
		return login, &passwordLogin{password: input.Password, verifiedHash: login.PasswordHash, upgradedHash: upgraded,
			legacy: s.legacyPasswords}, nil
	}
	var upgraded string
	if verification.needsUpgrade {
		upgraded, err = hashPasswordUnchecked(input.Password)
		if err != nil {
			return LoginIdentity{}, nil, err
		}
	}
	return login, &passwordLogin{password: input.Password, verifiedHash: login.PasswordHash, upgradedHash: upgraded}, nil
}

// LoginVerified creates a session only after an authenticated account flow has
// supplied a one-time contact challenge. The store consumes it atomically with
// session creation and rechecks all caller-supplied identity hints.
func (s *Service) LoginVerified(ctx context.Context, input VerifiedLoginInput, request RequestInfo) (AuthResult, error) {
	if input.UserID == uuid.Nil || input.ScopeID == uuid.Nil || input.Challenge == nil ||
		(input.Method != "email_code" && input.Method != "sms_code") {
		return AuthResult{}, ErrInvalidCredentials
	}
	if err := s.checkAdminAccessForScope(ctx, input.ScopeID, request.SourceIP); err != nil {
		return AuthResult{}, err
	}
	return s.createSession(ctx, input.UserID, input.ScopeID, input.Method, nil, input.Challenge, request)
}

func (s *Service) createSession(
	ctx context.Context,
	userID, scopeID uuid.UUID,
	method string,
	password *passwordLogin,
	challenge *LoginChallengeProof,
	request RequestInfo,
) (AuthResult, error) {
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
	principal, err := s.store.CreateSession(ctx, SessionInput{
		ID:                     sessionID,
		FamilyID:               familyID,
		UserID:                 userID,
		ScopeID:                scopeID,
		RefreshTokenHash:       refreshHash,
		UserAgent:              request.UserAgent,
		SourceIP:               request.SourceIP,
		ExpiresAt:              refreshExpires,
		RequestID:              request.RequestID,
		AuthenticationMethod:   method,
		passwordLogin:          password,
		loginChallenge:         challenge,
		loginChallengeConsumer: s.loginChallengeConsumer,
	})
	if err != nil {
		return AuthResult{}, err
	}
	accessToken, accessExpires, err := s.tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		return AuthResult{}, err
	}
	s.recordSessionRegion(ctx, familyID, userID, request.SourceIP)
	if s.loginAllow != nil {
		if err := s.loginAllow.AllowAdminLogin(ctx, scopeID, userID, request.SourceIP, request.RequestID); err != nil {
			slog.WarnContext(ctx, "auto defense sign-in source not allowed", "error", err)
		}
	}
	return AuthResult{
		AccessToken:      accessToken,
		ExpiresAt:        accessExpires,
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpires,
		Principal:        principal,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, rawToken string, request RequestInfo) (AuthResult, error) {
	if rawToken == "" {
		return AuthResult{}, ErrInvalidSession
	}
	refreshTTL, err := s.sessionTTL(ctx, uuid.Nil)
	if err != nil {
		return AuthResult{}, err
	}
	newSessionID, err := newUUID()
	if err != nil {
		return AuthResult{}, err
	}
	newToken, newHash, err := generateRefreshToken()
	if err != nil {
		return AuthResult{}, err
	}
	newExpires := s.now().UTC().Add(refreshTTL)
	current, principal, err := s.store.RotateSession(
		ctx,
		hashRefreshToken(rawToken),
		newSessionID,
		newHash,
		newExpires,
		request.RequestID,
		request.UserAgent,
		request.SourceIP,
	)
	if err != nil {
		return AuthResult{}, err
	}
	// The rotation already happened; a refused address keeps the new family
	// unusable from here because every request is checked as well.
	if err := s.checkAdminAccess(ctx, principal.ScopeKind, request.SourceIP); err != nil {
		return AuthResult{}, err
	}
	accessToken, accessExpires, err := s.tokens.Mint(current.UserID, current.ScopeID, current.ID)
	if err != nil {
		return AuthResult{}, err
	}
	if current.Reused {
		// The concurrent request that rotated the token already set the
		// successor cookie; RefreshToken stays empty so it is not overwritten.
		return AuthResult{AccessToken: accessToken, ExpiresAt: accessExpires,
			RefreshExpiresAt: current.ExpiresAt, Principal: principal}, nil
	}
	return AuthResult{
		AccessToken:      accessToken,
		ExpiresAt:        accessExpires,
		RefreshToken:     newToken,
		RefreshExpiresAt: newExpires,
		Principal:        principal,
	}, nil
}

func (s *Service) sessionTTL(ctx context.Context, scopeID uuid.UUID) (time.Duration, error) {
	if s.publicSettings == nil {
		return s.refreshTTL, nil
	}
	policy, err := s.publicSettings.GetPublic(ctx, scopeID)
	if err != nil {
		return 0, fmt.Errorf("load public session policy: %w", err)
	}
	if policy.SessionTTLSeconds < 300 || policy.SessionTTLSeconds > 31536000 {
		return 0, errors.New("public session policy TTL is invalid")
	}
	return time.Duration(policy.SessionTTLSeconds) * time.Second, nil
}

func (s *Service) Logout(ctx context.Context, rawToken string, requestID string) error {
	if rawToken == "" {
		return nil
	}
	return s.store.RevokeSessionFamily(ctx, hashRefreshToken(rawToken), requestID)
}

func (s *Service) Authenticate(ctx context.Context, rawAccessToken string) (Principal, error) {
	userID, scopeID, sessionID, err := s.tokens.Parse(rawAccessToken)
	if err != nil {
		return Principal{}, ErrInvalidSession
	}
	principal, err := s.store.PrincipalForSession(ctx, userID, scopeID, sessionID)
	if err != nil {
		return Principal{}, err
	}
	if err := s.checkAdminAccess(ctx, principal.ScopeKind, audit.SourceIPFrom(ctx)); err != nil {
		return Principal{}, err
	}
	if err := s.checkSessionRegion(ctx, principal, sessionID); err != nil {
		return Principal{}, err
	}
	if err := checkPasswordChangeRequired(ctx, principal); err != nil {
		return Principal{}, err
	}
	return principal, nil
}

func (s *Service) AuthenticateSession(ctx context.Context, rawAccessToken string) (AuthenticatedSession, error) {
	userID, scopeID, sessionID, err := s.tokens.Parse(rawAccessToken)
	if err != nil {
		return AuthenticatedSession{}, ErrInvalidSession
	}
	principal, err := s.store.PrincipalForSession(ctx, userID, scopeID, sessionID)
	if err != nil {
		return AuthenticatedSession{}, err
	}
	if err := s.checkAdminAccess(ctx, principal.ScopeKind, audit.SourceIPFrom(ctx)); err != nil {
		return AuthenticatedSession{}, err
	}
	if err := s.checkSessionRegion(ctx, principal, sessionID); err != nil {
		return AuthenticatedSession{}, err
	}
	if err := checkPasswordChangeRequired(ctx, principal); err != nil {
		return AuthenticatedSession{}, err
	}
	return AuthenticatedSession{SessionID: sessionID, Principal: principal}, nil
}

func Authorize(principal Principal, permission string) error {
	for _, candidate := range principal.Permissions {
		if candidate == permission || candidate == "platform.admin" {
			return nil
		}
	}
	return ErrPermissionDenied
}

func generateRefreshToken() (string, []byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate refresh token: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return encoded, hashRefreshToken(encoded), nil
}

func hashRefreshToken(raw string) []byte {
	digest := sha256.Sum256([]byte(raw))
	return digest[:]
}
