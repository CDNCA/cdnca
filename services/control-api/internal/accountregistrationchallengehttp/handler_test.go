package accountregistrationchallengehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/google/uuid"
)

type challengeServiceStub struct {
	createInput accountregistrationchallenge.CreateInput
	verifyInput accountregistrationchallenge.VerifyInput
	challengeID uuid.UUID
	reference   string
}

func (stub *challengeServiceStub) Create(_ context.Context, input accountregistrationchallenge.CreateInput) (accountregistrationchallenge.CreateResult, error) {
	stub.createInput = input
	return accountregistrationchallenge.CreateResult{ChallengeID: stub.challengeID, ExpiresAt: handlerTestNow.Add(10 * time.Minute)}, nil
}

func (stub *challengeServiceStub) Verify(_ context.Context, input accountregistrationchallenge.VerifyInput) (accountregistrationchallenge.VerifyResult, error) {
	stub.verifyInput = input
	return accountregistrationchallenge.VerifyResult{Reference: stub.reference, ExpiresAt: handlerTestNow.Add(10 * time.Minute)}, nil
}

var handlerTestNow = time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)

func TestChallengeAndVerifyRoutesNeverEchoSecrets(t *testing.T) {
	t.Parallel()

	challengeID := uuid.MustParse("01987f47-3000-7000-8000-000000000001")
	reference := strings.Repeat("A", accountregistrationproof.ReferenceEncodedLength)
	service := &challengeServiceStub{challengeID: challengeID, reference: reference}
	handler, err := NewHandler(service, TrustedContextResolverFunc(func(*http.Request) (TrustedContext, error) {
		return TrustedContext{ScopeID: uuid.New(), SourceIP: "192.0.2.11"}, nil
	}), Config{Timeout: time.Second, MaxRequestBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}

	createBody := `{"username":"owner","email":"owner@example.com","phone":"+8613812345678","verification_channel":"email","human_token":"` + strings.Repeat("t", 32) + `"}`
	create := httptest.NewRequest(http.MethodPost, ChallengePath, strings.NewReader(createBody))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "challenge-1")
	create.Header.Set("X-Request-ID", "request-1")
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusAccepted || strings.Contains(createResponse.Body.String(), strings.Repeat("t", 32)) ||
		strings.Contains(createResponse.Body.String(), "owner@example.com") {
		t.Fatalf("create response = %d %s", createResponse.Code, createResponse.Body.String())
	}

	verifyBody := `{"challenge_id":"` + challengeID.String() + `","username":"owner","email":"owner@example.com","phone":"+8613812345678","verification_channel":"email","otp":"123456"}`
	verify := httptest.NewRequest(http.MethodPost, VerificationPath, strings.NewReader(verifyBody))
	verify.Header.Set("Content-Type", "application/json")
	verify.Header.Set("Idempotency-Key", "verify-1")
	verify.Header.Set("X-Request-ID", "request-2")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verify)
	if verifyResponse.Code != http.StatusNoContent || strings.Contains(verifyResponse.Body.String(), "123456") ||
		strings.Contains(verifyResponse.Body.String(), reference) {
		t.Fatalf("verify response = %d %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	cookies := verifyResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != accountregistrationproof.CookieName || !cookies[0].Secure ||
		!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("proof cookies = %#v", cookies)
	}
}
