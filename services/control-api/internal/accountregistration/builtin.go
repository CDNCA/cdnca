package accountregistration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
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

// CaptchaVerifier spends one built-in CAPTCHA bound to the browser
// (LoginCaptchaProof.Binding).
type CaptchaVerifier interface {
	ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error
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
	// termsRequired: whether sign-up must accept terms now
	// (some readable terms exist); nil: always.
	termsRequired func(context.Context) (bool, error)
}

// RequireTermsWhen sets what decides whether a sign-up must accept terms
// (registration-config terms_required). While it answers false, the terms
// acceptance is not checked and no acceptance is recorded.
func (service *BuiltInService) RequireTermsWhen(required func(context.Context) (bool, error)) {
	if service != nil {
		service.termsRequired = required
	}
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
	termsRequired := true
	if service.termsRequired != nil {
		if termsRequired, err = service.termsRequired(ctx); err != nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
	}
	required := RequiredProofChannels(policy)
	if len(required) > 0 && service.proofs == nil {
		return RegisterResult{}, ErrContactVerificationUnavailable
	}
	if len(required) == 0 && (input.Captcha.ID == uuid.Nil || input.Captcha.Answer == "") {
		return RegisterResult{}, refusalreason.Wrap(ErrCaptchaInvalid, identity.CaptchaReasonMissing)
	}
	phoneCode := ""
	if input.Phone != "" {
		phoneCode = policy.DefaultPhoneCountryCode
	}
	generated := fillUsername(&input.RegisterInput, service.digestKey, policy, phoneCode)
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
	if policy.EmailVerificationRequired && input.Email == "" || policy.PhoneVerificationRequired && input.Phone == "" ||
		policy.QQRequired && input.QQ == "" {
		return RegisterResult{}, ErrInvalidInput
	}
	// the terms accepted must be the ones in force now (the
	// built-in flow has no deployment override: it is the settings version).
	// An exact retry of a registration completed under the terms it names
	// replays the original receipt even after the terms changed, so the
	// acceptance is checked only once no completed receipt matches.
	// while no terms are required it is not checked at all (and
	// not recorded, storeRegistration); a retry replays either way.
	// Terms not accepted, or another version: account_registration_terms_required.
	var termsProblem error
	if termsRequired && (!input.TermsAccepted || input.TermsVersion != policy.TermsVersion) {
		termsProblem = ErrTermsOutdated
	}
	outdated := termsProblem != nil
	digester := &Service{digestKey: service.digestKey}
	subjectDigest, err := digester.subjectDigest(input.RegisterInput)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration subject: %w", err)
	}
	if len(required) > 0 {
		// Outdated terms without any receipt for the key cannot be a retry:
		// refused before a proof is spent.
		if outdated {
			exists, err := service.receiptExists(ctx, input.IdempotencyKey)
			if err != nil {
				return RegisterResult{}, err
			}
			if !exists {
				return RegisterResult{}, termsProblem
			}
		}
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
		if outdated {
			return service.replayOnly(ctx, input.RegisterInput, requestDigest, generated, termsProblem)
		}
		return service.storeRegistration(ctx, input.RegisterInput, requestDigest, subjectDigest, generated, termsRequired)
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
		return registerResult(true, generated, input.Username), nil
	}
	if outdated {
		return RegisterResult{}, termsProblem
	}
	if err := service.captcha.ConsumeCaptcha(ctx, input.Captcha); err != nil {
		if errors.Is(err, identity.ErrLoginCaptchaInvalid) {
			return RegisterResult{}, refusalreason.Wrap(ErrCaptchaInvalid, refusalreason.Of(err))
		}
		return RegisterResult{}, fmt.Errorf("%w: %v", ErrProofUnavailable, err)
	}
	return service.storeRegistration(ctx, input.RegisterInput, requestDigest, subjectDigest, generated, termsRequired)
}

// replayOnly answers a request whose terms acceptance does not hold now: the
// original receipt when it completed with this exact request, otherwise
// refused (ErrTermsOutdated, or the idempotency conflict
// CompletedRegistration reports).
func (service *BuiltInService) replayOnly(ctx context.Context, input RegisterInput, requestDigest [32]byte, generated bool, refused error) (RegisterResult, error) {
	replayed, err := service.store.CompletedRegistration(ctx, input.IdempotencyKey, requestDigest)
	if err != nil {
		return RegisterResult{}, err
	}
	if !replayed {
		return RegisterResult{}, refused
	}
	return registerResult(true, generated, input.Username), nil
}

// receiptExists reports whether the key has a registration receipt at all.
// A stored request digest is a keyed HMAC and never all zero, so reading the
// replay with the zero digest is a conflict exactly when a receipt exists.
func (service *BuiltInService) receiptExists(ctx context.Context, idempotencyKey string) (bool, error) {
	_, err := service.store.CompletedRegistration(ctx, idempotencyKey, [32]byte{})
	if errors.Is(err, ErrIdempotencyConflict) {
		return true, nil
	}
	return false, err
}

// storeRegistration hashes the password and writes the registration; the
// accepted terms version only while terms are required (none
// recorded otherwise, the user accepted no terms).
func (service *BuiltInService) storeRegistration(ctx context.Context, input RegisterInput, requestDigest, subjectDigest [32]byte, generated, termsRequired bool) (RegisterResult, error) {
	termsVersion := input.TermsVersion
	if !termsRequired {
		termsVersion = ""
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
		Email: input.Email, Phone: input.Phone, QQ: input.QQ, TermsVersion: termsVersion,
		VerificationChannel: input.VerificationChannel, IdempotencyKey: input.IdempotencyKey,
		RequestID: input.RequestID, RequestDigest: requestDigest, SubjectDigest: subjectDigest,
		CreatedAt: service.now().UTC().Truncate(time.Microsecond),
	})
	if err != nil {
		return RegisterResult{}, err
	}
	return registerResult(stored.Replayed, generated, input.Username), nil
}

var _ PublicSettingsReader = (*systemusersettings.Service)(nil)
