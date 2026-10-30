package accountregistrationchallenge

import (
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
