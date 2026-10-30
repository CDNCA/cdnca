package accountregistration

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestIAM02RegistrationProofIsMandatoryAndFailClosed(t *testing.T) {
	store := &registrationStoreStub{byKey: make(map[string]RegistrationRecord)}
	limiter := &registrationLimiterStub{allowed: true}
	if _, err := NewService(store, limiter, ServiceConfig{DigestKey: make([]byte, 32)}); !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewService without proof authority error = %v", err)
	}

	input := validRegistrationInput()
	for name, proof := range map[string]*registrationProofStub{
		"invalid":     {err: ErrProofInvalid},
		"unavailable": {err: errors.New("proof backend unavailable")},
		"mismatch": {configured: true, result: RegistrationProof{
			EvidenceID: registrationProofID(), Channel: VerificationEmail, Destination: "other@example.com",
			HumanVerifiedAt: registrationTestNow.Add(-1), ContactVerifiedAt: registrationTestNow.Add(-1),
			ExpiresAt: registrationTestNow.Add(1),
		}},
		"expired": {configured: true, result: RegistrationProof{
			EvidenceID: registrationProofID(), Channel: VerificationEmail, Destination: input.Email,
			HumanVerifiedAt: registrationTestNow.Add(-2), ContactVerifiedAt: registrationTestNow.Add(-2),
			ExpiresAt: registrationTestNow.Add(-1),
		}},
		"client_boolean_only": {configured: true},
	} {
		t.Run(name, func(t *testing.T) {
			store.calls = nil
			service := newRegistrationTestService(t, store, limiter, proof, 0x71)
			_, err := service.Register(t.Context(), input)
			want := ErrProofInvalid
			if name == "unavailable" {
				want = ErrProofUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatalf("Register error = %v, want %v", err, want)
			}
			if len(store.calls) != 0 {
				t.Fatal("unverified registration reached the transactional store")
			}
		})
	}
}

func registrationProofID() uuid.UUID {
	return uuid.MustParse("55555555-5555-4555-8555-555555555555")
}
