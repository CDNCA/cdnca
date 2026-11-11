package accountregistration

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

type builtInStoreStub struct {
	registrationStoreStub
	completed map[string][32]byte
}

func (store *builtInStoreStub) CompletedRegistration(_ context.Context, key string, digest [32]byte) (bool, error) {
	previous, found := store.completed[key]
	if !found {
		return false, nil
	}
	if previous != digest {
		return false, ErrIdempotencyConflict
	}
	return true, nil
}

type captchaStub struct {
	err   error
	calls []identity.LoginCaptchaProof
}

func (captcha *captchaStub) ConsumeCaptcha(_ context.Context, proof identity.LoginCaptchaProof, _ string) error {
	captcha.calls = append(captcha.calls, proof)
	return captcha.err
}

func builtInInput() BuiltInInput {
	return BuiltInInput{
		RegisterInput: RegisterInput{
			Username: " Builtin-Alice ", Password: "Correct-horse-battery-staple", DisplayName: "Alice",
			Email: " Builtin-Alice@Example.com ", TermsAccepted: true, TermsVersion: "terms-2026-08",
			IdempotencyKey: "registration-builtin-1", RequestID: "request-builtin-1", Source: "203.0.113.9",
		},
		Captcha: identity.LoginCaptchaProof{ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Answer: "AB2CD"},
	}
}

func newBuiltIn(t *testing.T, settings systemusersettings.PublicSettings) (*BuiltInService, *builtInStoreStub, *captchaStub) {
	t.Helper()
	store := &builtInStoreStub{registrationStoreStub: registrationStoreStub{byKey: map[string]RegistrationRecord{}}}
	captcha := &captchaStub{}
	service, err := NewBuiltInService(store, &registrationPolicyStub{settings: settings}, captcha, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return service, store, captcha
}

// builtin registration: a fresh install (no Turnstile runtime) with 开放注册 on
// registers with the built-in CAPTCHA, stores normalized identities, and
// spends the CAPTCHA once.
func TestBuiltInRegistrationCreatesNormalizedOwnerWithCaptcha(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	result, err := service.Register(context.Background(), builtInInput())
	if err != nil || !result.Accepted || result.Replayed {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if len(captcha.calls) != 1 || len(store.calls) != 1 {
		t.Fatalf("captcha=%d store=%d", len(captcha.calls), len(store.calls))
	}
	record := store.calls[0]
	if record.Username != "builtin-alice" || record.Email != "builtin-alice@example.com" ||
		record.VerificationChannel != VerificationEmail || record.PasswordHash == "" ||
		record.PasswordHash == "Correct-horse-battery-staple" {
		t.Fatalf("record=%#v", record)
	}
	if !identity.VerifyPassword(record.PasswordHash, "Correct-horse-battery-staple") {
		t.Fatal("stored hash does not verify")
	}
}

func TestBuiltInRegistrationRefusals(t *testing.T) {
	cases := []struct {
		name     string
		settings systemusersettings.PublicSettings
		mutate   func(*BuiltInInput)
		captcha  error
		want     error
	}{
		{"closed", systemusersettings.PublicSettings{}, nil, nil, ErrRegistrationDisabled},
		{"verified email required", systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true}, nil, nil, ErrContactVerificationUnavailable},
		{"phone required", systemusersettings.PublicSettings{RegistrationEnabled: true, PhoneRequired: true}, nil, nil, ErrInvalidInput},
		{"no captcha", systemusersettings.PublicSettings{RegistrationEnabled: true}, func(input *BuiltInInput) { input.Captcha = identity.LoginCaptchaProof{} }, nil, ErrCaptchaInvalid},
		{"wrong captcha", systemusersettings.PublicSettings{RegistrationEnabled: true}, nil, identity.ErrLoginCaptchaInvalid, ErrCaptchaInvalid},
		{"weak password", systemusersettings.PublicSettings{RegistrationEnabled: true}, func(input *BuiltInInput) { input.Password = "short" }, nil, ErrInvalidInput},
		{"terms", systemusersettings.PublicSettings{RegistrationEnabled: true}, func(input *BuiltInInput) { input.TermsAccepted = false }, nil, ErrInvalidInput},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			service, store, captcha := newBuiltIn(t, item.settings)
			captcha.err = item.captcha
			input := builtInInput()
			if item.mutate != nil {
				item.mutate(&input)
			}
			if _, err := service.Register(context.Background(), input); !errors.Is(err, item.want) {
				t.Fatalf("err=%v want %v", err, item.want)
			}
			if len(store.calls) != 0 {
				t.Fatalf("refused registration reached the store")
			}
		})
	}
}

// An exact retry of a completed registration replays without a new CAPTCHA;
// the same key with other details is a conflict.
func TestBuiltInRegistrationReplay(t *testing.T) {
	service, store, captcha := newBuiltIn(t, systemusersettings.PublicSettings{RegistrationEnabled: true})
	if _, err := service.Register(context.Background(), builtInInput()); err != nil {
		t.Fatal(err)
	}
	store.completed = map[string][32]byte{store.calls[0].IdempotencyKey: store.calls[0].RequestDigest}
	result, err := service.Register(context.Background(), builtInInput())
	if err != nil || !result.Replayed || len(captcha.calls) != 1 || len(store.calls) != 1 {
		t.Fatalf("replay result=%#v err=%v captcha=%d store=%d", result, err, len(captcha.calls), len(store.calls))
	}
	other := builtInInput()
	other.DisplayName = "Mallory"
	if _, err := service.Register(context.Background(), other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("err=%v", err)
	}
}
