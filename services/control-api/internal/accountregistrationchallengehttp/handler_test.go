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
	"github.com/cdnca/cdnca/services/control-api/internal/refusalreason"
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
	return accountregistrationchallenge.CreateResult{ChallengeID: stub.challengeID, ExpiresAt: handlerTestNow.Add(10 * time.Minute),
		Binding: "challenge-binding"}, nil
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
	// the code is bound to the browser by an HttpOnly cookie
	// sent back only to the verification route
	binding := createResponse.Result().Cookies()
	if len(binding) != 1 || binding[0].Name != BindingCookieName("email", challengeID) || binding[0].Value != "challenge-binding" ||
		binding[0].Path != VerificationPath || !binding[0].HttpOnly || !binding[0].Secure || binding[0].SameSite != http.SameSiteStrictMode ||
		strings.Contains(createResponse.Body.String(), "challenge-binding") {
		t.Fatalf("binding cookies = %#v", binding)
	}

	verifyBody := `{"challenge_id":"` + challengeID.String() + `","username":"owner","email":"owner@example.com","phone":"+8613812345678","verification_channel":"email","otp":"123456"}`
	verify := httptest.NewRequest(http.MethodPost, VerificationPath, strings.NewReader(verifyBody))
	verify.Header.Set("Content-Type", "application/json")
	verify.Header.Set("Idempotency-Key", "verify-1")
	verify.Header.Set("X-Request-ID", "request-2")
	// another challenge's cookie (another tab) is not read
	verify.AddCookie(&http.Cookie{Name: BindingCookieName("sms", challengeID), Value: "wrong-channel"})
	verify.AddCookie(&http.Cookie{Name: BindingCookieName("email", uuid.New()), Value: "other-tab"})
	verify.AddCookie(&http.Cookie{Name: BindingCookieName("email", challengeID), Value: "challenge-binding"})
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verify)
	if verifyResponse.Code != http.StatusNoContent || strings.Contains(verifyResponse.Body.String(), "123456") ||
		strings.Contains(verifyResponse.Body.String(), reference) {
		t.Fatalf("verify response = %d %s", verifyResponse.Code, verifyResponse.Body.String())
	}
	if service.verifyInput.Binding != "challenge-binding" {
		t.Fatalf("verify binding = %q", service.verifyInput.Binding)
	}
	cookies := verifyResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != accountregistrationproof.ChannelCookieName("email", challengeID) || !cookies[0].Secure ||
		!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/" {
		t.Fatalf("proof cookies = %#v", cookies)
	}
}

type failingChallengeService struct{ err error }

func (service failingChallengeService) Create(context.Context, accountregistrationchallenge.CreateInput) (accountregistrationchallenge.CreateResult, error) {
	return accountregistrationchallenge.CreateResult{}, service.err
}

func (service failingChallengeService) Verify(context.Context, accountregistrationchallenge.VerifyInput) (accountregistrationchallenge.VerifyResult, error) {
	return accountregistrationchallenge.VerifyResult{}, service.err
}

// A failed image CAPTCHA / Turnstile check and invalid details are told
// apart, so the page does not blame the CAPTCHA for a bad username or email.
func TestChallengeErrorsSeparateHumanCheckFromDetails(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		err  error
		code string
	}{
		{accountregistrationchallenge.ErrHumanInvalid, "account_registration_human_invalid"},
		{accountregistrationchallenge.ErrInvalidInput, "account_registration_challenge_invalid"},
		{accountregistrationchallenge.ErrOTPInvalid, "account_registration_challenge_invalid"},
	} {
		handler, err := NewHandler(failingChallengeService{err: test.err}, TrustedContextResolverFunc(func(*http.Request) (TrustedContext, error) {
			return TrustedContext{ScopeID: uuid.New(), SourceIP: "192.0.2.11"}, nil
		}), Config{})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, ChallengePath, strings.NewReader(
			`{"username":"owner","email":"owner@example.com","phone":"","verification_channel":"email","human_token":"`+strings.Repeat("t", 32)+`"}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "challenge-1")
		request.Header.Set("X-Request-ID", "request-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnprocessableEntity || !strings.Contains(response.Body.String(), `"code":"`+test.code+`"`) {
			t.Fatalf("%v: %d %s", test.err, response.Code, response.Body.String())
		}
	}
}

// Problem 28: why the CAPTCHA was refused is recorded for the refusal log
// only; the response is the same generic account_registration_human_invalid.
func TestHumanInvalidReasonGoesToLogOnly(t *testing.T) {
	t.Parallel()

	for _, reason := range []string{
		"captcha_not_found", "captcha_consumed", "captcha_expired", "captcha_binding_mismatch", "captcha_binding_superseded",
		"captcha_answer_mismatch", "captcha_malformed", "human_rejected_replay", "human_token_reused",
	} {
		err := refusalreason.Wrap(accountregistrationchallenge.ErrHumanInvalid, reason)
		handler, buildErr := NewHandler(failingChallengeService{err: err}, TrustedContextResolverFunc(func(*http.Request) (TrustedContext, error) {
			return TrustedContext{ScopeID: uuid.New(), SourceIP: "192.0.2.11"}, nil
		}), Config{})
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		request := httptest.NewRequest(http.MethodPost, ChallengePath, strings.NewReader(
			`{"username":"owner","email":"","phone":"+8613812345678","verification_channel":"sms","human_token":"captcha:22222222-2222-4222-8222-222222222222:AB2CD"}`))
		request = request.WithContext(refusalreason.WithRecorder(request.Context()))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "challenge-1")
		request.Header.Set("X-Request-ID", "request-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := `{"error":{"code":"account_registration_human_invalid","request_id":"request-1"}}` + "\n"
		if response.Code != http.StatusUnprocessableEntity || response.Body.String() != want {
			t.Fatalf("%s: %d %q", reason, response.Code, response.Body.String())
		}
		if got := refusalreason.Recorded(request.Context()); got != reason {
			t.Fatalf("recorded %q, want %q", got, reason)
		}
	}
}
