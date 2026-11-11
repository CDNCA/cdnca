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
// code. It is still gated by the 开放注册 switch.
//
// while the platform asks for a verified email and/or
// phone, the human check moves to sending the code (the challenge service
// spends the image CAPTCHA) and the registration must carry one verified
// proof per required channel (EnableContactVerification); without the
// contact verification runtime (no notification runtime) such a policy is
// refused with ErrContactVerificationUnavailable.

var (
	// ErrCaptchaInvalid: the built-in CAPTCHA was wrong, expired or used.
	ErrCaptchaInvalid = errors.New("account registration captcha invalid")
	// ErrContactVerificationUnavailable: the policy requires a verified
	// contact and no contact verification runtime is mounted.
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
	proofs    ProofAuthority
	digestKey []byte
	now       func() time.Time
}

// EnableContactVerification lets built-in registration accept verified
// email / SMS proofs issued by the challenge service sharing its digest key.
func (service *BuiltInService) EnableContactVerification(proofs ProofAuthority) {
	if service != nil {
		service.proofs = proofs
	}
}

// ContactVerificationAvailable reports whether verified proofs are accepted.
func (service *BuiltInService) ContactVerificationAvailable() bool {
	return service != nil && service.proofs != nil
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
	policy, err := service.policy.GetPublic(ctx, uuid.Nil)
	if err != nil {
		return RegisterResult{}, ErrRegistrationPolicyUnavailable
	}
	if !policy.RegistrationEnabled {
		return RegisterResult{}, ErrRegistrationDisabled
	}
	required := RequiredProofChannels(policy)
	if len(required) > 0 && service.proofs == nil {
		return RegisterResult{}, ErrContactVerificationUnavailable
	}
	if len(required) == 0 && (input.Captcha.ID == uuid.Nil || input.Captcha.Answer == "") {
		return RegisterResult{}, ErrCaptchaInvalid
	}
	phoneCode := ""
	if input.Phone != "" {
		phoneCode = policy.DefaultPhoneCountryCode
	}
	if len(required) > 0 {
		input.VerificationChannel = required[0]
	} else if input.VerificationChannel == "" {
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
	if policy.EmailVerificationRequired && input.Email == "" || policy.PhoneVerificationRequired && input.Phone == "" {
		return RegisterResult{}, ErrInvalidInput
	}
	digester := &Service{digestKey: service.digestKey}
	subjectDigest, err := digester.subjectDigest(input.RegisterInput)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration subject: %w", err)
	}
	if len(required) > 0 {
		// The human check was spent when the codes were sent; the proofs are
		// replayable per idempotency key, so the receipt check comes after.
		evidence, err := consumeProofs(ctx, service.proofs, input.RegisterInput, required, subjectDigest,
			service.now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return RegisterResult{}, err
		}
		requestDigest, err := digester.requestDigest(input.RegisterInput, evidence)
		if err != nil {
			return RegisterResult{}, fmt.Errorf("digest account registration request: %w", err)
		}
		return service.storeRegistration(ctx, input.RegisterInput, requestDigest, subjectDigest)
	}
	// The CAPTCHA id stands in for the proof evidence: the same key with
	// another CAPTCHA or other details is an idempotency conflict.
	requestDigest, err := digester.requestDigest(input.RegisterInput, input.Captcha.ID.String())
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
	return service.storeRegistration(ctx, input.RegisterInput, requestDigest, subjectDigest)
}

// store_ hashes the password and writes the registration.
func (service *BuiltInService) storeRegistration(ctx context.Context, input RegisterInput, requestDigest, subjectDigest [32]byte) (RegisterResult, error) {
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
