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
)

type Service struct {
	store     Registrar
	limiter   RateLimiter
	proofs    ProofAuthority
	policy    PublicSettingsReader
	digestKey []byte
	now       func() time.Time
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
	if err := normalizeRegistrationInput(&input, phoneCode); err != nil {
		return RegisterResult{}, err
	}
	if service.policy != nil {
		if input.ScopeID == uuid.Nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
		policy, err := service.policy.GetPublic(ctx, input.ScopeID)
		if err != nil {
			return RegisterResult{}, ErrRegistrationPolicyUnavailable
		}
		if !policy.RegistrationEnabled {
			return RegisterResult{}, ErrRegistrationDisabled
		}
		if policy.EmailRequired && input.Email == "" || policy.PhoneRequired && input.Phone == "" ||
			policy.EmailVerificationRequired && input.Email == "" || policy.PhoneVerificationRequired && input.Phone == "" {
			return RegisterResult{}, ErrInvalidInput
		}
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
	destination := input.Email
	if input.VerificationChannel == VerificationSMS {
		destination = input.Phone
	}
	proof, err := service.proofs.VerifyAndConsume(ctx, RegistrationProofRequest{
		Reference: input.ProofReference, Channel: input.VerificationChannel, Destination: destination,
		Source: input.Source, IdempotencyKey: input.IdempotencyKey, SubjectDigest: subjectDigest,
	})
	if err != nil {
		if errors.Is(err, ErrProofInvalid) {
			return RegisterResult{}, ErrProofInvalid
		}
		return RegisterResult{}, fmt.Errorf("%w: %v", ErrProofUnavailable, err)
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if !validRegistrationProof(proof, input.VerificationChannel, destination, now) {
		return RegisterResult{}, ErrProofInvalid
	}
	requestDigest, err := service.requestDigest(input, proof.EvidenceID)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("digest account registration request: %w", err)
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
		Email: input.Email, Phone: input.Phone, TermsVersion: input.TermsVersion,
		VerificationChannel: input.VerificationChannel, IdempotencyKey: input.IdempotencyKey,
		RequestID: input.RequestID, RequestDigest: requestDigest, SubjectDigest: subjectDigest,
		CreatedAt: now,
	})
	if err != nil {
		return RegisterResult{}, err
	}
	return RegisterResult{Accepted: true, Replayed: stored.Replayed}, nil
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
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Phone = strings.TrimSpace(input.Phone)
	input.TermsVersion = strings.TrimSpace(input.TermsVersion)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.Source = strings.TrimSpace(input.Source)
	if len(input.Username) < 3 || len(input.Username) > 128 ||
		!registrationUsernamePattern.MatchString(input.Username) ||
		utf8.RuneCountInString(input.DisplayName) < 1 || utf8.RuneCountInString(input.DisplayName) > 128 ||
		strings.IndexFunc(input.DisplayName, unicode.IsControl) >= 0 ||
		!input.TermsAccepted || !registrationMetadataPattern.MatchString(input.TermsVersion) ||
		!registrationMetadataPattern.MatchString(input.IdempotencyKey) ||
		!registrationMetadataPattern.MatchString(input.RequestID) ||
		len(input.ProofReference) < 22 || len(input.ProofReference) > 4096 ||
		!registrationProofPattern.MatchString(input.ProofReference) || strings.TrimSpace(input.ProofReference) != input.ProofReference ||
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

func (service *Service) requestDigest(input RegisterInput, proofEvidenceID uuid.UUID) ([32]byte, error) {
	request, err := json.Marshal(struct {
		Username            string `json:"username"`
		Password            string `json:"password"`
		DisplayName         string `json:"display_name"`
		Email               string `json:"email"`
		Phone               string `json:"phone"`
		TermsVersion        string `json:"terms_version"`
		VerificationChannel string `json:"verification_channel"`
		ProofEvidenceID     string `json:"proof_evidence_id"`
	}{
		input.Username, input.Password, input.DisplayName, input.Email, input.Phone,
		input.TermsVersion, input.VerificationChannel, proofEvidenceID.String(),
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
