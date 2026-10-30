package accountregistration

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

var registrationTestNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

type registrationStoreStub struct {
	byKey     map[string]RegistrationRecord
	calls     []RegistrationRecord
	duplicate bool
	err       error
}

func (store *registrationStoreStub) Register(_ context.Context, record RegistrationRecord) (StoreResult, error) {
	store.calls = append(store.calls, record)
	if store.err != nil {
		return StoreResult{}, store.err
	}
	if previous, exists := store.byKey[record.IdempotencyKey]; exists {
		if subtle.ConstantTimeCompare(previous.RequestDigest[:], record.RequestDigest[:]) != 1 {
			return StoreResult{}, ErrIdempotencyConflict
		}
		return StoreResult{Replayed: true}, nil
	}
	store.byKey[record.IdempotencyKey] = record
	return StoreResult{}, nil
}

type registrationLimiterStub struct {
	allowed bool
	err     error
	calls   []RateLimitRequest
}

func (limiter *registrationLimiterStub) Allow(_ context.Context, request RateLimitRequest) (bool, error) {
	limiter.calls = append(limiter.calls, request)
	return limiter.allowed, limiter.err
}

type registrationProofStub struct {
	configured bool
	result     RegistrationProof
	err        error
	calls      []RegistrationProofRequest
}

type registrationPolicyStub struct {
	settings systemusersettings.PublicSettings
	err      error
	calls    []uuid.UUID
}

func (policy *registrationPolicyStub) GetPublic(_ context.Context, scopeID uuid.UUID) (systemusersettings.PublicSettings, error) {
	policy.calls = append(policy.calls, scopeID)
	return policy.settings, policy.err
}

func (proofs *registrationProofStub) VerifyAndConsume(
	_ context.Context,
	request RegistrationProofRequest,
) (RegistrationProof, error) {
	proofs.calls = append(proofs.calls, request)
	if proofs.err != nil {
		return RegistrationProof{}, proofs.err
	}
	if proofs.configured {
		return proofs.result, nil
	}
	return RegistrationProof{
		EvidenceID: uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		Channel:    request.Channel, Destination: request.Destination,
		HumanVerifiedAt:   registrationTestNow.Add(-time.Minute),
		ContactVerifiedAt: registrationTestNow.Add(-30 * time.Second),
		ExpiresAt:         registrationTestNow.Add(5 * time.Minute),
	}, nil
}

func newRegistrationTestService(
	t *testing.T,
	store Registrar,
	limiter RateLimiter,
	proofs ProofAuthority,
	keyByte byte,
) *Service {
	t.Helper()
	service, err := NewService(store, limiter, ServiceConfig{
		DigestKey: bytes.Repeat([]byte{keyByte}, 32), ProofAuthority: proofs,
		Clock: func() time.Time { return registrationTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newRegistrationPolicyTestService(
	t *testing.T,
	store Registrar,
	limiter RateLimiter,
	proofs ProofAuthority,
	policy PublicSettingsReader,
) *Service {
	t.Helper()
	service := newRegistrationTestService(t, store, limiter, proofs, 0x71)
	service.policy = policy
	return service
}

func TestIAM02RegisterAppliesPublicSystemUserPolicyBeforeSideEffects(t *testing.T) {
	scopeID := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	input := validRegistrationInput()
	input.ScopeID = scopeID
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	limiter := &registrationLimiterStub{allowed: true}
	proofs := &registrationProofStub{}
	policy := &registrationPolicyStub{settings: systemusersettings.PublicSettings{RegistrationEnabled: false}}
	service := newRegistrationPolicyTestService(t, store, limiter, proofs, policy)
	if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("disabled registration error = %v", err)
	}
	if len(limiter.calls) != 0 || len(proofs.calls) != 0 || len(store.calls) != 0 || len(policy.calls) != 1 || policy.calls[0] != scopeID {
		t.Fatalf("policy/side effects = policy=%d limiter=%d proofs=%d store=%d", len(policy.calls), len(limiter.calls), len(proofs.calls), len(store.calls))
	}

	policy.settings = systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true}
	input.Email = ""
	if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("required email error = %v", err)
	}
	if len(limiter.calls) != 0 || len(store.calls) != 0 {
		t.Fatal("required contact reached registration side effects")
	}

	policy.settings = systemusersettings.PublicSettings{RegistrationEnabled: true, PhoneRequired: true}
	input.Email = "alice@example.com"
	input.Phone = ""
	if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("required phone error = %v", err)
	}
	if len(limiter.calls) != 0 || len(store.calls) != 0 {
		t.Fatal("required phone reached registration side effects")
	}
}

func TestIAM02RegisterFailsClosedWhenPublicPolicyUnavailable(t *testing.T) {
	input := validRegistrationInput()
	input.ScopeID = uuid.MustParse("77777777-7777-4777-8777-777777777777")
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	policy := &registrationPolicyStub{err: errors.New("settings unavailable")}
	service := newRegistrationPolicyTestService(t, store, &registrationLimiterStub{allowed: true}, &registrationProofStub{}, policy)
	if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrRegistrationPolicyUnavailable) {
		t.Fatalf("policy error = %v", err)
	}
	if len(store.calls) != 0 {
		t.Fatal("policy failure reached registration store")
	}
}

func TestIAM02RegisterNormalizesHashesLimitsAndReplays(t *testing.T) {
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	limiter := &registrationLimiterStub{allowed: true}
	proofs := &registrationProofStub{}
	service := newRegistrationTestService(t, store, limiter, proofs, 0x31)
	input := RegisterInput{
		Username: "  Alice.Example  ", Password: "Correct-horse-battery-staple",
		DisplayName: "  Alice Example  ", Email: "  ALICE@EXAMPLE.COM  ", Phone: "  +8613800138000  ",
		TermsAccepted: true, TermsVersion: "terms-2026-08", VerificationChannel: VerificationEmail,
		IdempotencyKey: "registration-1", RequestID: "request-1", Source: "  203.0.113.9  ",
		ProofReference: "proof-reference-registration-1",
	}
	result, err := service.Register(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || result.Replayed {
		t.Fatalf("first result = %+v", result)
	}
	if len(store.calls) != 1 || len(limiter.calls) != 1 {
		t.Fatalf("calls store/limiter = %d/%d", len(store.calls), len(limiter.calls))
	}
	record := store.calls[0]
	if record.Username != "alice.example" || record.DisplayName != "Alice Example" ||
		record.Email != "alice@example.com" || record.Phone != "+8613800138000" ||
		record.TermsVersion != input.TermsVersion || record.VerificationChannel != VerificationEmail {
		t.Fatalf("normalized record = %+v", record)
	}
	if !identity.VerifyPassword(record.PasswordHash, input.Password) || record.PasswordHash == input.Password {
		t.Fatal("registration password was not persisted as the existing Argon2id format")
	}
	if limiter.calls[0].Source != "203.0.113.9" || limiter.calls[0].SubjectDigest != record.SubjectDigest ||
		limiter.calls[0].IdempotencyKey != input.IdempotencyKey {
		t.Fatalf("rate limit request = %+v record_subject=%x", limiter.calls[0], record.SubjectDigest)
	}
	if len(proofs.calls) != 1 || proofs.calls[0].Reference != input.ProofReference ||
		proofs.calls[0].Channel != VerificationEmail || proofs.calls[0].Destination != "alice@example.com" ||
		proofs.calls[0].Source != "203.0.113.9" || proofs.calls[0].IdempotencyKey != input.IdempotencyKey {
		t.Fatalf("proof request = %+v", proofs.calls)
	}
	if bytes.Contains(record.RequestDigest[:], []byte(input.Password)) || bytes.Contains(record.SubjectDigest[:], []byte(record.Email)) {
		t.Fatal("registration digests contain raw secret or subject bytes")
	}

	replay := input
	replay.Username = "ALICE.EXAMPLE"
	replay.DisplayName = "Alice Example"
	replay.Email = "alice@example.com"
	replay.Phone = "+8613800138000"
	replay.Source = "198.51.100.8"
	replayed, err := service.Register(t.Context(), replay)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Accepted || !replayed.Replayed {
		t.Fatalf("replay result = %+v", replayed)
	}
	if store.calls[0].RequestDigest != store.calls[1].RequestDigest ||
		store.calls[0].SubjectDigest != store.calls[1].SubjectDigest {
		t.Fatal("normalized replay produced unstable digests")
	}

	conflict := input
	conflict.Password = "Different-horse-battery-staple"
	if _, err := service.Register(t.Context(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("different password replay error = %v", err)
	}
}

func TestIAM02RegisterDuplicateIsSamePublicAcknowledgement(t *testing.T) {
	createdStore := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	duplicateStore := &registrationStoreStub{byKey: make(map[string]RegistrationRecord), duplicate: true}
	created := newRegistrationTestService(t, createdStore, &registrationLimiterStub{allowed: true}, &registrationProofStub{}, 0x41)
	duplicate := newRegistrationTestService(t, duplicateStore, &registrationLimiterStub{allowed: true}, &registrationProofStub{}, 0x41)
	input := validRegistrationInput()
	createdResult, createdErr := created.Register(t.Context(), input)
	duplicateResult, duplicateErr := duplicate.Register(t.Context(), input)
	if createdErr != nil || duplicateErr != nil || createdResult != duplicateResult ||
		createdResult != (RegisterResult{Accepted: true}) {
		t.Fatalf("created=%+v/%v duplicate=%+v/%v", createdResult, createdErr, duplicateResult, duplicateErr)
	}
}

func TestIAM02RegisterRateLimitAndDependencyFailuresStopBeforeStore(t *testing.T) {
	input := validRegistrationInput()
	for name, test := range map[string]struct {
		limiter *registrationLimiterStub
		want    error
	}{
		"denied": {limiter: &registrationLimiterStub{}, want: ErrRateLimited},
		"error":  {limiter: &registrationLimiterStub{err: errors.New("limiter unavailable")}, want: ErrRateLimitUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
			service := newRegistrationTestService(t, store, test.limiter, &registrationProofStub{}, 0x51)
			if _, err := service.Register(t.Context(), input); !errors.Is(err, test.want) {
				t.Fatalf("Register error = %v, want %v", err, test.want)
			}
			if len(store.calls) != 0 {
				t.Fatal("rate-limited registration reached the transactional store")
			}
		})
	}
}

func TestIAM02RegisterRejectsInvalidInputs(t *testing.T) {
	tests := map[string]func(*RegisterInput){
		"username":     func(input *RegisterInput) { input.Username = "bad user" },
		"password":     func(input *RegisterInput) { input.Password = "short" },
		"display_name": func(input *RegisterInput) { input.DisplayName = " " },
		"email":        func(input *RegisterInput) { input.Email = "not-an-email" },
		"phone":        func(input *RegisterInput) { input.Phone = "123" },
		"destination":  func(input *RegisterInput) { input.Email, input.Phone = "", "" },
		"channel":      func(input *RegisterInput) { input.VerificationChannel = VerificationSMS; input.Phone = "" },
		"terms":        func(input *RegisterInput) { input.TermsAccepted = false },
		"terms_version": func(input *RegisterInput) {
			input.TermsVersion = ""
		},
		"idempotency": func(input *RegisterInput) { input.IdempotencyKey = "contains spaces" },
		"request_id":  func(input *RegisterInput) { input.RequestID = "" },
		"source":      func(input *RegisterInput) { input.Source = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := validRegistrationInput()
			mutate(&input)
			store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
			service := newRegistrationTestService(t, store, &registrationLimiterStub{allowed: true}, &registrationProofStub{}, 0x61)
			if _, err := service.Register(t.Context(), input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("Register error = %v", err)
			}
			if len(store.calls) != 0 {
				t.Fatal("invalid registration reached store")
			}
		})
	}
}

func validRegistrationInput() RegisterInput {
	return RegisterInput{
		Username: "alice", Password: "Correct-horse-battery-staple", DisplayName: "Alice",
		Email: "alice@example.com", TermsAccepted: true, TermsVersion: "terms-2026-08",
		VerificationChannel: VerificationEmail, IdempotencyKey: "registration-valid",
		RequestID: "request-valid", Source: "203.0.113.10", ProofReference: "proof-reference-valid-registration",
	}
}
