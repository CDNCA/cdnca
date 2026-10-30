package identity

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/ipallowlist"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrLoginSourceDenied                 = errors.New("login source denied")
	ErrLoginChallengeInvalid             = errors.New("login challenge invalid")
	ErrLoginChallengeUsed                = errors.New("login challenge already used")
	ErrLoginChallengeIdempotencyConflict = errors.New("login challenge idempotency conflict")
	ErrLoginMethodDisabled               = errors.New("login verification method disabled")
	ErrLoginSecurityContactRequired      = errors.New("login security contact required")
	ErrLoginSecurityUnavailable          = errors.New("login security unavailable")
)

type ManagedUserLoginSecurity struct {
	UserID            uuid.UUID `json:"user_id"`
	TenantScopeID     uuid.UUID `json:"tenant_scope_id"`
	Revision          int64     `json:"revision"`
	LoginVerification string    `json:"login_verification"`
	LoginAllowlist    []string  `json:"login_allowlist"`
}

type UpdateManagedUserLoginSecurityInput struct {
	UserID            uuid.UUID
	TenantScopeID     uuid.UUID
	ExpectedRevision  int64
	LoginVerification string
	LoginAllowlist    []string
	IdempotencyKey    string
	RequestID         string
}

type LoginVerificationRequired struct {
	Channel string
	ScopeID uuid.UUID
}

func (*LoginVerificationRequired) Error() string { return "login verification is required" }

type LoginChallengeProof struct {
	ChallengeID    uuid.UUID
	OTP            string
	Identifier     string
	Channel        string
	IdempotencyKey string
}

type LoginChallengeConsumeInput struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	PolicyRevision int64
	Contact        string
	SourceIP       string
	RequestID      string
	Proof          LoginChallengeProof
}

// Domain denials must be committed so invalid attempts cannot be retried forever.
// The second error indicates a storage failure and requires a transaction rollback.
type LoginChallengeConsumer interface {
	ConsumeLoginChallengeTx(context.Context, pgx.Tx, LoginChallengeConsumeInput) (error, error)
	LoginChannelAvailable(string) bool
}

type PasswordLoginChallengeSubject struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	Channel        string
	Destination    string
	PolicyRevision int64
}

func (s *Service) SetLoginChallengeConsumer(consumer LoginChallengeConsumer) {
	if s != nil {
		s.loginChallengeConsumer = consumer
	}
}

func normalizeLoginSecurity(method string, values []string) ([]string, error) {
	if method != "none" && method != "email" && method != "sms" {
		return nil, ErrInvalidUserInput
	}
	result, err := ipallowlist.Normalize(values, 32)
	if err != nil {
		return nil, ErrInvalidUserInput
	}
	return result, nil
}

func checkLoginSecurity(policy ManagedUserLoginSecurity, source string, password bool, proof *LoginChallengeProof) error {
	if len(policy.LoginAllowlist) > 0 && !ipallowlist.Contains(policy.LoginAllowlist, source) {
		return ErrLoginSourceDenied
	}
	if policy.LoginVerification != "none" {
		if !password {
			return ErrLoginChallengeInvalid
		}
		if proof == nil {
			return &LoginVerificationRequired{Channel: policy.LoginVerification, ScopeID: policy.TenantScopeID}
		}
	}
	return nil
}

func (s *Service) GetManagedUserLoginSecurity(ctx context.Context, actor Actor, userID, tenantScopeID uuid.UUID) (ManagedUserLoginSecurity, error) {
	if !validAdminActor(actor) || actor.SessionID == uuid.Nil || userID == uuid.Nil || tenantScopeID == uuid.Nil {
		return ManagedUserLoginSecurity{}, ErrInvalidUserInput
	}
	return s.store.getManagedUserLoginSecurity(ctx, actor, userID, tenantScopeID)
}

func (s *Service) UpdateManagedUserLoginSecurity(ctx context.Context, actor Actor, input UpdateManagedUserLoginSecurityInput) (ManagedUserLoginSecurity, error) {
	if !validAdminActor(actor) || actor.SessionID == uuid.Nil || input.UserID == uuid.Nil || input.TenantScopeID == uuid.Nil || input.ExpectedRevision < 0 || input.ExpectedRevision == 1<<63-1 || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ManagedUserLoginSecurity{}, ErrInvalidUserInput
	}
	allowlist, err := normalizeLoginSecurity(input.LoginVerification, input.LoginAllowlist)
	if err != nil {
		return ManagedUserLoginSecurity{}, err
	}
	input.LoginAllowlist = allowlist
	digest, err := digestIdentityRequest(struct {
		ActorScopeID      uuid.UUID `json:"actor_scope_id"`
		UserID            uuid.UUID `json:"user_id"`
		TenantScopeID     uuid.UUID `json:"tenant_scope_id"`
		ExpectedRevision  int64     `json:"expected_revision"`
		LoginVerification string    `json:"login_verification"`
		LoginAllowlist    []string  `json:"login_allowlist"`
	}{actor.ScopeID, input.UserID, input.TenantScopeID, input.ExpectedRevision, input.LoginVerification, allowlist})
	if err != nil {
		return ManagedUserLoginSecurity{}, ErrLoginSecurityUnavailable
	}
	return s.store.updateManagedUserLoginSecurity(ctx, actor, input, digest, s.loginChallengeConsumer)
}

func (s *Service) PreparePasswordLoginChallenge(ctx context.Context, input LoginInput, request RequestInfo) (PasswordLoginChallengeSubject, error) {
	reservation, err := s.reserveLoginAttempt(ctx, input.Username, request, input.Captcha)
	if err != nil {
		return PasswordLoginChallengeSubject{}, err
	}
	login, _, err := s.verifyPasswordLogin(ctx, input, request)
	if err != nil {
		reservation.settle(ctx, err)
		return PasswordLoginChallengeSubject{}, err
	}
	// The sign-in completes only with the code; the failures stay until then.
	reservation.settle(ctx, errPasswordAccepted)
	var result PasswordLoginChallengeSubject
	err = pgx.BeginFunc(ctx, s.store.pool, func(tx pgx.Tx) error {
		policy, err := ReadLoginSecurityTx(ctx, tx, login.UserID, login.ScopeID)
		if err != nil {
			return err
		}
		if policy.LoginVerification == "none" {
			return ErrLoginChallengeInvalid
		}
		if err := checkLoginSecurity(policy, request.SourceIP, true, &LoginChallengeProof{}); err != nil {
			return err
		}
		var contact string
		if err := tx.QueryRow(ctx, `SELECT COALESCE(CASE WHEN $2='email' THEN email ELSE phone END,'') FROM users WHERE id=$1`, login.UserID, policy.LoginVerification).Scan(&contact); err != nil {
			return err
		}
		if err := checkLoginChannelTx(ctx, tx, login.ScopeID, policy.LoginVerification, contact, s.loginChallengeConsumer); err != nil {
			return err
		}
		result = PasswordLoginChallengeSubject{UserID: login.UserID, ScopeID: login.ScopeID, Channel: policy.LoginVerification, Destination: contact, PolicyRevision: policy.Revision}
		return nil
	})
	return result, err
}
