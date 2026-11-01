package accountregistration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// builtin registration: an installation without the Turnstile registration runtime
// (ACCOUNT_REGISTRATION_ENABLED=false, the fresh-install default) registers
// with the built-in image CAPTCHA (POST /v1/auth/login-captchas, the same
// "本地验证码" the sign-in throttle uses) instead of Turnstile plus a contact
// code. It is still gated by the 开放注册 switch, and refused while the
// platform asks for a verified email or phone, which it cannot prove.

var (
	// ErrCaptchaInvalid: the built-in CAPTCHA was wrong, expired or used.
	ErrCaptchaInvalid = errors.New("account registration captcha invalid")
	// ErrContactVerificationUnavailable: the policy requires a verified
	// contact, which built-in registration cannot provide.
	ErrContactVerificationUnavailable = errors.New("account registration contact verification unavailable")
)

// CaptchaVerifier spends one built-in CAPTCHA bound to the request source.
type CaptchaVerifier interface {
	ConsumeCaptcha(context.Context, identity.LoginCaptchaProof, string) error
}

// ReplayReader reports whether a completed registration receipt already
// exists for the key and digest, so an exact retry needs no new CAPTCHA.
type ReplayReader interface {
	CompletedRegistration(context.Context, string, [32]byte) (bool, error)
}

type BuiltInStore interface {
	Registrar
	ReplayReader
}

type BuiltInService struct {
	store     BuiltInStore
	policy    PublicSettingsReader
	captcha   CaptchaVerifier
	digestKey []byte
	now       func() time.Time
}

// BuiltInInput is a registration proved by a solved built-in CAPTCHA.
type BuiltInInput struct {
	RegisterInput
	Captcha identity.LoginCaptchaProof
}

func NewBuiltInService(store BuiltInStore, policy PublicSettingsReader, captcha CaptchaVerifier, digestKey []byte) (*BuiltInService, error) {
	if store == nil || policy == nil || captcha == nil || len(digestKey) < 32 {
		return nil, ErrInvalidService
	}
	return &BuiltInService{store: store, policy: policy, captcha: captcha,
		digestKey: append([]byte(nil), digestKey...), now: time.Now}, nil
}

// Available reports the 开放注册 switch for the login-methods projection.
func (service *BuiltInService) Available(ctx context.Context) (bool, error) {
	if service == nil {
		return false, nil
	}
	policy, err := service.policy.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return false, ErrRegistrationPolicyUnavailable
	}
	return policy.RegistrationEnabled, nil
}

func (service *BuiltInService) Register(ctx context.Context, input BuiltInInput) (RegisterResult, error) {
	if service == nil || service.store == nil || service.policy == nil || service.captcha == nil || len(service.digestKey) < 32 {
		return RegisterResult{}, ErrInvalidService
	}
	if input.Captcha.ID == uuid.Nil || input.Captcha.Answer == "" {
		return RegisterResult{}, ErrCaptchaInvalid
	}
	policy, err := service.policy.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return RegisterResult{}, ErrRegistrationPolicyUnavailable
	}
	if !policy.RegistrationEnabled {
		return RegisterResult{}, ErrRegistrationDisabled
	}
	phoneCode := ""
	if input.Phone != "" {
		phoneCode = policy.DefaultPhoneCountryCode
	}
	if input.VerificationChannel == "" {
		input.VerificationChannel = VerificationEmail
		if input.Email == "" && input.Phone != "" {
			input.VerificationChannel = VerificationSMS
		}
	}
	if err := normalizeRegistrationFields(&input.RegisterInput, phoneCode); err != nil {
		return RegisterResult{}, err
	}
	if policy.EmailRequired && input.Email == "" || policy.PhoneRequired && input.Phone == "" {
		return RegisterResult{}, ErrInvalidInput
	}
	if policy.EmailVerificationRequired || policy.PhoneVerificationRequired {
		return RegisterResult{}, ErrContactVerificationUnavailable
	}
	digester := &Service{digestKey: service.digestKey}
	subjectDigest, err := digester.subjectDigest(input.RegisterInput)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration subject: %w", err)
	}
	// The CAPTCHA id stands in for the proof evidence: the same key with
	// another CAPTCHA or other details is an idempotency conflict.
	requestDigest, err := digester.requestDigest(input.RegisterInput, input.Captcha.ID)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration request: %w", err)
	}
	replayed, err := service.store.CompletedRegistration(ctx, input.IdempotencyKey, requestDigest)
	if err != nil {
		return RegisterResult{}, err
	}
	if replayed {
		return RegisterResult{Accepted: true, Replayed: true}, nil
	}
	if err := service.captcha.ConsumeCaptcha(ctx, input.Captcha, input.Source); err != nil {
		if errors.Is(err, identity.ErrLoginCaptchaInvalid) {
			return RegisterResult{}, ErrCaptchaInvalid
		}
		return RegisterResult{}, fmt.Errorf("%w: %v", ErrProofUnavailable, err)
	}
	passwordHash, err := identity.HashPassword(input.Password)
	if err != nil {
		return RegisterResult{}, ErrInvalidInput
	}
	ids := make([]uuid.UUID, 7)
	for index := range ids {
		if ids[index], err = uuid.NewV7(); err != nil {
			return RegisterResult{}, fmt.Errorf("generate account registration identity: %w", err)
		}
	}
	stored, err := service.store.Register(ctx, RegistrationRecord{
		RegistrationID: ids[0], TenantID: ids[1], ScopeID: ids[2], UserID: ids[3],
		OwnerRoleID: ids[4], ViewerRoleID: ids[5], VerificationID: ids[6],
		Username: input.Username, PasswordHash: passwordHash, DisplayName: input.DisplayName,
		Email: input.Email, Phone: input.Phone, TermsVersion: input.TermsVersion,
		VerificationChannel: input.VerificationChannel, IdempotencyKey: input.IdempotencyKey,
		RequestID: input.RequestID, RequestDigest: requestDigest, SubjectDigest: subjectDigest,
		CreatedAt: service.now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{Accepted: true, Replayed: stored.Replayed}, nil
}

var _ PublicSettingsReader = (*systemusersettings.Service)(nil)
