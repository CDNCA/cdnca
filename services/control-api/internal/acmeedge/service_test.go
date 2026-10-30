package acmeedge

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type countingCipher struct {
	calls int
}

func TestNormalizePublishRequestAllowsTargetInheritanceOnlyForCleanup(t *testing.T) {
	now := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	request := PublishRequest{
		Mode: ModeCleanup, TenantScopeID: uuid.New(), SiteID: uuid.New(), ExpectedRevision: 1,
		MaxAttempts: 3, Deadline: now.Add(time.Minute), IdempotencyKey: "cleanup-inherit",
		RequestID: uuid.NewString(),
	}
	normalized, err := normalizePublishRequest(request, now)
	if err != nil || len(normalized.NodeIDs) != 0 || normalized.TargetSnapshot != nil {
		t.Fatalf("cleanup normalization = %+v, %v", normalized, err)
	}
	request.Mode = ModeApply
	request.ExpectedRevision = 0
	if _, err := normalizePublishRequest(request, now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("targetless apply error = %v", err)
	}
}

func (cipher *countingCipher) Seal(context.Context, SealRequest) (SealResult, error) {
	cipher.calls++
	return SealResult{KeyID: "test-key", Nonce: make([]byte, 12), Ciphertext: []byte("sealed")}, nil
}

func TestSealChallengesRejectsInvalidHTTP01MaterialBeforeCipher(t *testing.T) {
	validToken := "Abcdefghijklmnopqrstuv"
	validThumbprint := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	tests := []struct {
		name   string
		domain string
		token  string
		value  string
	}{
		{name: "invalid_domain", domain: "bad_domain.example", token: validToken, value: validToken + "." + validThumbprint},
		{name: "short_token", domain: "valid.example", token: "short", value: "short." + validThumbprint},
		{name: "mismatched_token", domain: "valid.example", token: validToken, value: "different-token-value." + validThumbprint},
		{name: "short_thumbprint", domain: "valid.example", token: validToken, value: validToken + ".short"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cipher := &countingCipher{}
			service := &Service{cipher: cipher}
			_, err := service.sealChallenges(t.Context(), uuid.New(), uuid.New(), []challengeSecret{{
				Reference: ChallengeReference{OperationID: uuid.NewString(), AttemptID: uuid.New()},
				Domain:    test.domain, Token: test.token, Value: test.value,
			}})
			if !errors.Is(err, ErrChallengeIneligible) || cipher.calls != 0 {
				t.Fatalf("error=%v cipher_calls=%d", err, cipher.calls)
			}
		})
	}
}
