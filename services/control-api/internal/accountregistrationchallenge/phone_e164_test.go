package accountregistrationchallenge

import (
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/google/uuid"
)

// FX38: the SMS destination and the bound subject use the E.164 phone.
func TestNormalizeCreateInputUsesE164Phone(t *testing.T) {
	input := CreateInput{ScopeID: uuid.New(), Username: "owner_1", Email: "owner@example.com", Phone: "13812345678",
		Channel: accountregistration.VerificationSMS, Source: "2001:db8::1", HumanToken: strings.Repeat("a", 32),
		IdempotencyKey: "challenge-1", RequestID: "request-1"}
	normalized, err := normalizeCreateInput(input, challengeTestKey, "")
	if err != nil || normalized.Phone != "+8613812345678" || normalized.Destination != "+8613812345678" {
		t.Fatalf("normalized = %+v, %v", normalized, err)
	}
	prefixed := input
	prefixed.Phone = "+86 138 1234 5678"
	again, err := normalizeCreateInput(prefixed, challengeTestKey, "")
	if err != nil || again.SubjectDigest != normalized.SubjectDigest {
		t.Fatalf("same phone in another format changed the subject: %v", err)
	}
}

func TestNormalizeEmailVerificationWithoutPhone(t *testing.T) {
	input := CreateInput{ScopeID: uuid.New(), Username: "owner_1", Email: "owner@example.test",
		Channel: accountregistration.VerificationEmail, Source: "2001:db8::1", HumanToken: strings.Repeat("a", 32),
		IdempotencyKey: "challenge-1", RequestID: "request-1"}
	created, err := normalizeCreateInput(input, challengeTestKey, "")
	if err != nil || created.Phone != "" || created.Destination != input.Email {
		t.Fatalf("email challenge with optional phone: destination = %q, error = %v", created.Destination, err)
	}
	verification := VerifyInput{ScopeID: input.ScopeID, ChallengeID: uuid.New(), Username: input.Username,
		Email: input.Email, Channel: input.Channel, Source: input.Source, OTP: "123456",
		IdempotencyKey: "verify-1", RequestID: "request-2"}
	verified, err := normalizeVerifyInput(verification, challengeTestKey, "")
	if err != nil || verified.SubjectDigest != created.SubjectDigest {
		t.Fatalf("email verification did not bind the same subject: %v", err)
	}

	input.Channel = accountregistration.VerificationSMS
	if _, err := normalizeCreateInput(input, challengeTestKey, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("SMS challenge without phone: %v", err)
	}
	verification.Channel = accountregistration.VerificationSMS
	if _, err := normalizeVerifyInput(verification, challengeTestKey, ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("SMS verification without phone: %v", err)
	}
}
