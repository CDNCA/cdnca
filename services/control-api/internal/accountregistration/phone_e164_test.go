package accountregistration

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// FX38: a phone typed without the country code is stored as E.164 so the
// unique index sees it as the same number as "+86…".
func TestRegisterNormalizesPhoneToE164(t *testing.T) {
	input := RegisterInput{Username: "bob", Password: "Correct-horse-battery-staple", DisplayName: "Bob",
		Phone: " 138-0013-8000 ", TermsAccepted: true, TermsVersion: "terms-1", VerificationChannel: VerificationSMS,
		IdempotencyKey: "registration-1", RequestID: "request-1", Source: "203.0.113.9",
		ProofReference: "proof-reference-registration-1"}
	if err := normalizeRegistrationInput(&input, ""); err != nil || input.Phone != "+8613800138000" {
		t.Fatalf("phone = %q, %v", input.Phone, err)
	}
}

// FX38: registration completes a bare phone with the platform default code.
func TestRegisterUsesPlatformDefaultCountryCode(t *testing.T) {
	input := validRegistrationInput()
	input.ScopeID = uuid.MustParse("66666666-6666-4666-8666-666666666667")
	input.Phone = "415 555 0100"
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	policy := &registrationPolicyStub{settings: systemusersettings.PublicSettings{RegistrationEnabled: true, DefaultPhoneCountryCode: "1"}}
	service := newRegistrationPolicyTestService(t, store, &registrationLimiterStub{allowed: true}, &registrationProofStub{}, policy)
	if _, err := service.Register(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if len(store.calls) != 1 || store.calls[0].Phone != "+14155550100" {
		t.Fatalf("stored phone = %+v", store.calls)
	}
}
