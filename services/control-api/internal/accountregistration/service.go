package accountregistration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/phonenumber"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

var (
	registrationUsernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	registrationMetadataPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	registrationProofPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	// registrationQQPattern: a QQ number, 5 to 12 digits without a leading zero.
	registrationQQPattern = regexp.MustCompile(`^[1-9][0-9]{4,11}$`)
)

type Service struct {
	store     Registrar
	limiter   RateLimiter
	proofs    ProofAuthority
	policy    PublicSettingsReader
	digestKey []byte
	now       func() time.Time
	// termsRequired: as BuiltInService.termsRequired; nil: always.
	termsRequired func(context.Context) (bool, error)
}

// RequireTermsWhen sets what decides whether a sign-up must accept terms
// (registration-config terms_required); false, the acceptance is neither
// checked nor recorded. The HTTP handler follows the same answer.
func (service *Service) RequireTermsWhen(required func(context.Context) (bool, error)) {
	if service != nil {
		service.termsRequired = required
	}
}

func NewService(store Registrar, limiter RateLimiter, config ServiceConfig) (*Service, error) {
	if store == nil || limiter == nil || config.ProofAuthority == nil || len(config.DigestKey) < 32 {
		return nil, ErrInvalidService
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	return &Service{
		store: store, limiter: limiter, proofs: config.ProofAuthority, policy: config.PublicSettings,
		digestKey: append([]byte(nil), config.DigestKey...), now: config.Clock,
	}, nil
}

func (service *Service) Register(ctx context.Context, input RegisterInput) (RegisterResult, error) {
	if service == nil || service.store == nil || service.limiter == nil || service.proofs == nil ||
		len(service.digestKey) < 32 || service.now == nil {
		return RegisterResult{}, ErrInvalidService
	}
	phoneCode, err := service.phoneCountryCode(ctx, input)
	if err != nil {
		return RegisterResult{}, err
	}
	var required []string
	var policy systemusersettings.PublicSettings
	generated := false
	if service.policy != nil {
		if input.ScopeID == uuid.Nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
		if policy, err = service.policy.GetPublic(ctx, input.ScopeID); err != nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
		generated = fillUsername(&input, service.digestKey, policy, phoneCode)
	}
	termsRequired := true
	if service.termsRequired != nil {
		if termsRequired, err = service.termsRequired(ctx); err != nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
	}
	if err := normalizeRegistrationInput(&input, phoneCode); err != nil {
		return RegisterResult{}, err
	}
	// (Turnstile flow), as the built-in one: while
	// terms are required they must be accepted in the version in force
	// (CurrentTermsVersion, from the HTTP entry); an exact retry of a
	// completed registration replays its receipt whatever changed since, so
	// that is checked only once no completed receipt matches. A first
	// submission is refused before any proof is spent.
	var termsProblem error
	if termsRequired && (!validTermsAcceptance(input) || input.CurrentTermsVersion != "" && input.TermsVersion != input.CurrentTermsVersion) {
		termsProblem = ErrTermsOutdated
	}
	replays, _ := service.store.(ReplayReader)
	if termsProblem != nil {
		if replays == nil {
			return RegisterResult{}, termsProblem
		}
		if _, err := replays.CompletedRegistration(ctx, input.IdempotencyKey, [32]byte{}); !errors.Is(err, ErrIdempotencyConflict) {
			// no receipt for the key (a stored digest is never all zero), or the read failed
			if err != nil {
				return RegisterResult{}, err
			}
			return RegisterResult{}, termsProblem
		}
	}
	if service.policy != nil {
		if !policy.RegistrationEnabled {
			return RegisterResult{}, ErrRegistrationDisabled
		}
		if policy.EmailRequired && input.Email == "" || policy.PhoneRequired && input.Phone == "" ||
			policy.EmailVerificationRequired && input.Email == "" || policy.PhoneVerificationRequired && input.Phone == "" ||
			policy.QQRequired && input.QQ == "" {
			return RegisterResult{}, ErrInvalidInput
		}
		required = RequiredProofChannels(policy)
	}
	if len(required) == 0 {
		// No verification required (or no policy reader): the chosen channel.
		required = []string{input.VerificationChannel}
	}
	subjectDigest, err := service.subjectDigest(input)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration subject: %w", err)
	}
	allowed, err := service.limiter.Allow(ctx, RateLimitRequest{
		Source: input.Source, SubjectDigest: subjectDigest, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return RegisterResult{}, fmt.Errorf("%w: %v", ErrRateLimitUnavailable, err)
	}
	if !allowed {
		return RegisterResult{}, ErrRateLimited
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	evidence, err := consumeProofs(ctx, service.proofs, input, required, subjectDigest, now)
	if err != nil {
		return RegisterResult{}, err
	}
	input.VerificationChannel = required[0]
	requestDigest, err := service.requestDigest(input, evidence)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration request: %w", err)
	}
	if termsProblem != nil {
		replayed, err := replays.CompletedRegistration(ctx, input.IdempotencyKey, requestDigest)
		if err != nil {
			return RegisterResult{}, err
		}
		if !replayed {
			return RegisterResult{}, termsProblem
		}
		return registerResult(true, generated, input.Username), nil
	}
	passwordHash, err := identity.HashPassword(input.Password)
	if err != nil {
		return RegisterResult{}, ErrInvalidInput
	}
	ids := make([]uuid.UUID, 7)
	for index := range ids {
		ids[index], err = uuid.NewV7()
		if err != nil {
			return RegisterResult{}, fmt.Errorf("generate account registration identity: %w", err)
		}
	}
	stored, err := service.store.Register(ctx, RegistrationRecord{
		RegistrationID: ids[0], TenantID: ids[1], ScopeID: ids[2], UserID: ids[3],
		OwnerRoleID: ids[4], ViewerRoleID: ids[5], VerificationID: ids[6],
		Username: input.Username, PasswordHash: passwordHash, DisplayName: input.DisplayName,
		Email: input.Email, Phone: input.Phone, QQ: input.QQ, TermsVersion: recordedTermsVersion(input, termsRequired),
		VerificationChannel: input.VerificationChannel, IdempotencyKey: input.IdempotencyKey,
		RequestID: input.RequestID, RequestDigest: requestDigest, SubjectDigest: subjectDigest,
		CreatedAt: now,
	})
	if err != nil {
		return RegisterResult{}, err
	}
	return registerResult(stored.Replayed, generated, input.Username), nil
}

// registerResult is the 202 body; a generated username is
// returned so the page can sign in with it.
func registerResult(replayed, generated bool, username string) RegisterResult {
	result := RegisterResult{Accepted: true, Replayed: replayed}
	if generated {
		result.Username = username
	}
	return result
}

// phoneCountryCode reads the platform default calling code for a bare phone
// number (FX38); unavailable settings fail closed like the policy check.
func (service *Service) phoneCountryCode(ctx context.Context, input RegisterInput) (string, error) {
	if service.policy == nil || strings.TrimSpace(input.Phone) == "" {
		return "", nil
	}
	if input.ScopeID == uuid.Nil {
		return "", ErrRegistrationPolicyUnavailable
	}
	code, err := systemusersettings.PhoneCountryCode(ctx, service.policy, input.ScopeID, input.Phone)
	if err != nil {
		return "", ErrRegistrationPolicyUnavailable
	}
	return code, nil
}

func normalizeRegistrationInput(input *RegisterInput, phoneCode string) error {
	if !validProofReferences(*input) {
		return ErrInvalidInput
	}
	return normalizeRegistrationFields(input, phoneCode)
}

// recordedTermsVersion is the accepted terms version a registration records:
// none while no terms are required (the user accepted none).
func recordedTermsVersion(input RegisterInput, termsRequired bool) string {
	if !termsRequired {
		return ""
	}
	return input.TermsVersion
}

// validTermsAcceptance: the terms are accepted and name a version (the
// Turnstile flow, while terms are required).
func validTermsAcceptance(input RegisterInput) bool {
	return input.TermsAccepted && registrationMetadataPattern.MatchString(input.TermsVersion)
}

// normalizeRegistrationFields checks everything but the proof reference and
// the terms acceptance; the built-in CAPTCHA registration (builtin.go) has no
// proof reference.
func normalizeRegistrationFields(input *RegisterInput, phoneCode string) error {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Phone = strings.TrimSpace(input.Phone)
	input.QQ = strings.TrimSpace(input.QQ)
	input.TermsVersion = strings.TrimSpace(input.TermsVersion)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Source = strings.TrimSpace(input.Source)
	if len(input.Username) < 3 || len(input.Username) > 128 ||
		!registrationUsernamePattern.MatchString(input.Username) ||
		utf8.RuneCountInString(input.DisplayName) < 1 || utf8.RuneCountInString(input.DisplayName) > 128 ||
		strings.IndexFunc(input.DisplayName, unicode.IsControl) >= 0 ||
		!registrationMetadataPattern.MatchString(input.IdempotencyKey) ||
		!registrationMetadataPattern.MatchString(input.RequestID) ||
		input.Source == "" || len(input.Source) > 256 ||
		strings.IndexFunc(input.Source, func(value rune) bool { return unicode.IsControl(value) || unicode.IsSpace(value) }) >= 0 {
		return ErrInvalidInput
	}
	if err := passwordpolicy.Check(input.Password); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if input.Email != "" {
		address, err := mail.ParseAddress(input.Email)
		if err != nil || address.Address != input.Email || len(input.Email) > 254 {
			return ErrInvalidInput
		}
	}
	if input.Phone != "" {
		phone, err := phonenumber.Normalize(input.Phone, phoneCode)
		if err != nil {
			return ErrInvalidInput
		}
		input.Phone = phone
	}
	if input.QQ != "" && !registrationQQPattern.MatchString(input.QQ) {
		return ErrInvalidInput
	}
	if input.Email == "" && input.Phone == "" {
		return ErrInvalidInput
	}
	if (input.VerificationChannel == VerificationEmail && input.Email == "") ||
		(input.VerificationChannel == VerificationSMS && input.Phone == "") ||
		(input.VerificationChannel != VerificationEmail && input.VerificationChannel != VerificationSMS) {
		return ErrInvalidInput
	}
	return nil
}

// requestDigest binds the request to its evidence: the proof evidence id(s)
// joined by "," (consumeProofs), or the built-in CAPTCHA id.
func (service *Service) requestDigest(input RegisterInput, proofEvidenceID string) ([32]byte, error) {
	request, err := json.Marshal(struct {
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Phone       string `json:"phone"`
		// omitempty: a request without a QQ keeps the digest it had before
		QQ                  string `json:"qq,omitempty"`
		TermsVersion        string `json:"terms_version"`
		VerificationChannel string `json:"verification_channel"`
		ProofEvidenceID     string `json:"proof_evidence_id"`
	}{
		input.Username, input.Password, input.DisplayName, input.Email, input.Phone, input.QQ,
		input.TermsVersion, input.VerificationChannel, proofEvidenceID,
	})
	if err != nil {
		return [32]byte{}, err
	}
	return keyedDigest(service.digestKey, request), nil
}

func (service *Service) subjectDigest(input RegisterInput) ([32]byte, error) {
	subject, err := json.Marshal(struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Phone    string `json:"phone"`
	}{input.Username, input.Email, input.Phone})
	if err != nil {
		return [32]byte{}, err
	}
	return keyedDigest(service.digestKey, subject), nil
}

func validRegistrationProof(proof RegistrationProof, channel, destination string, now time.Time) bool {
	return proof.EvidenceID != uuid.Nil && proof.Channel == channel && proof.Destination == destination &&
		!proof.HumanVerifiedAt.IsZero() && !proof.ContactVerifiedAt.IsZero() && !proof.ExpiresAt.IsZero() &&
		!proof.HumanVerifiedAt.After(now) && !proof.ContactVerifiedAt.After(now) && proof.ExpiresAt.After(now) &&
		!proof.HumanVerifiedAt.After(proof.ExpiresAt) && !proof.ContactVerifiedAt.After(proof.ExpiresAt)
}

func keyedDigest(key, value []byte) [32]byte {
	digest := hmac.New(sha256.New, key)
	_, _ = digest.Write(value)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}
