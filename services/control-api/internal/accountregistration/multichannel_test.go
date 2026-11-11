package accountregistration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// one verified proof per required channel; all must pass.

const (
	testEmailReference = "email-proof-reference-000000000000000000000"
	testSMSReference   = "sms-proof-reference-00000000000000000000000"
)

// channelProofStub rejects the channels listed in reject.
type channelProofStub struct {
	registrationProofStub
	reject map[string]bool
}

func (proofs *channelProofStub) VerifyAndConsume(ctx context.Context, request RegistrationProofRequest) (RegistrationProof, error) {
	if proofs.reject[request.Channel] {
		proofs.calls = append(proofs.calls, request)
		return RegistrationProof{}, ErrProofInvalid
	}
	return proofs.registrationProofStub.VerifyAndConsume(ctx, request)
}

func policyFor(email, sms bool) systemusersettings.PublicSettings {
	return systemusersettings.PublicSettings{RegistrationEnabled: true,
		EmailRequired: email, EmailVerificationRequired: email, PhoneRequired: sms, PhoneVerificationRequired: sms}
}

func TestRequiredProofChannels(t *testing.T) {
	for _, item := range []struct {
		email, sms bool
		want       string
	}{{false, false, ""}, {true, false, "email"}, {false, true, "sms"}, {true, true, "email,sms"}} {
		got := ""
		for index, channel := range RequiredProofChannels(policyFor(item.email, item.sms)) {
			if index > 0 {
				got += ","
			}
			got += channel
		}
		if got != item.want {
			t.Fatalf("email=%v sms=%v: %q want %q", item.email, item.sms, got, item.want)
		}
	}
}

func multiInput(references map[string]string) RegisterInput {
	input := validRegistrationInput()
	input.Phone = "+8613812345678"
	input.ProofReference = ""
	input.ProofReferences = references
	input.ScopeID = uuid.MustParse("33333333-3333-4333-8333-333333333333")
	return input
}

func TestRegisterBothChannelsRequireBothProofs(t *testing.T) {
	both := map[string]string{VerificationEmail: testEmailReference, VerificationSMS: testSMSReference}
	cases := []struct {
		name       string
		email, sms bool
		references map[string]string
		reject     map[string]bool
		want       error
		consumed   int
	}{
		{"email only", true, false, map[string]string{VerificationEmail: testEmailReference}, nil, nil, 1},
		{"sms only", false, true, map[string]string{VerificationSMS: testSMSReference}, nil, nil, 1},
		{"both", true, true, both, nil, nil, 2},
		{"both, sms proof missing", true, true, map[string]string{VerificationEmail: testEmailReference}, nil, ErrProofInvalid, 1},
		{"both, email proof missing", true, true, map[string]string{VerificationSMS: testSMSReference}, nil, ErrProofInvalid, 0},
		{"both, sms proof rejected", true, true, both, map[string]bool{VerificationSMS: true}, ErrProofInvalid, 2},
		{"email required, only sms proved", true, false, map[string]string{VerificationSMS: testSMSReference}, nil, ErrProofInvalid, 0},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			store := &registrationStoreStub{byKey: map[string]RegistrationRecord{}}
			proofs := &channelProofStub{reject: item.reject}
			service := newRegistrationPolicyTestService(t, store, &registrationLimiterStub{allowed: true}, proofs,
				&registrationPolicyStub{settings: policyFor(item.email, item.sms)})
			_, err := service.Register(context.Background(), multiInput(item.references))
			if !errors.Is(err, item.want) {
				t.Fatalf("err=%v want %v", err, item.want)
			}
			if len(proofs.calls) != item.consumed {
				t.Fatalf("proof calls=%d want %d", len(proofs.calls), item.consumed)
			}
			if item.want != nil && len(store.calls) != 0 {
				t.Fatal("refused registration reached the store")
			}
			if item.want == nil && len(store.calls) != 1 {
				t.Fatalf("store calls=%d", len(store.calls))
			}
		})
	}
}

func newBuiltInWithProofs(t *testing.T, settings systemusersettings.PublicSettings, proofs ProofAuthority) (*BuiltInService, *builtInStoreStub, *captchaStub) {
	t.Helper()
	service, store, captcha := newBuiltIn(t, settings)
	service.now = func() time.Time { return registrationTestNow }
	if proofs != nil {
		service.EnableContactVerification(proofs)
	}
	return service, store, captcha
}

func TestBuiltInRegistrationWithContactVerification(t *testing.T) {
	both := map[string]string{VerificationEmail: testEmailReference, VerificationSMS: testSMSReference}
	cases := []struct {
		name       string
		email, sms bool
		references map[string]string
		reject     map[string]bool
		want       error
	}{
		{"email", true, false, map[string]string{VerificationEmail: testEmailReference}, nil, nil},
		{"sms", false, true, map[string]string{VerificationSMS: testSMSReference}, nil, nil},
		{"both", true, true, both, nil, nil},
		{"both, one missing", true, true, map[string]string{VerificationEmail: testEmailReference}, nil, ErrProofInvalid},
		{"both, email rejected", true, true, both, map[string]bool{VerificationEmail: true}, ErrProofInvalid},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			service, store, captcha := newBuiltInWithProofs(t, policyFor(item.email, item.sms), &channelProofStub{reject: item.reject})
			input := builtInInput()
			input.Phone = "+8613812345678"
			input.ProofReferences = item.references
			// The human check was spent sending the code: no CAPTCHA here.
			input.Captcha = identity.LoginCaptchaProof{}
			_, err := service.Register(context.Background(), input)
			if !errors.Is(err, item.want) {
				t.Fatalf("err=%v want %v", err, item.want)
			}
			if len(captcha.calls) != 0 {
				t.Fatalf("captcha spent %d times", len(captcha.calls))
			}
			if (item.want == nil) != (len(store.calls) == 1) {
				t.Fatalf("store calls=%d", len(store.calls))
			}
		})
	}
}

// Without the contact verification runtime a verification policy is refused
// before anything is spent; without a policy the CAPTCHA is still required.
func TestBuiltInRegistrationVerificationUnavailable(t *testing.T) {
	service, store, captcha := newBuiltInWithProofs(t, policyFor(false, true), nil)
	input := builtInInput()
	input.Phone = "+8613812345678"
	if _, err := service.Register(context.Background(), input); !errors.Is(err, ErrContactVerificationUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if len(captcha.calls) != 0 || len(store.calls) != 0 || service.ContactVerificationAvailable() {
		t.Fatal("unavailable verification spent something")
	}
	open, _, _ := newBuiltInWithProofs(t, systemusersettings.PublicSettings{RegistrationEnabled: true}, &channelProofStub{})
	input = builtInInput()
	input.Captcha = identity.LoginCaptchaProof{}
	if _, err := open.Register(context.Background(), input); !errors.Is(err, ErrCaptchaInvalid) {
		t.Fatalf("no-verification policy without CAPTCHA: %v", err)
	}
}
