package accountloginchallengehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

type fakeLoginService struct {
	methods      accountloginchallenge.Methods
	createResult accountloginchallenge.CreateResult
	verifyResult accountloginchallenge.VerifyResult
	err          error
	createInput  accountloginchallenge.CreateInput
	verifyInput  accountloginchallenge.VerifyInput
}

func (fake *fakeLoginService) Methods(context.Context, uuid.UUID) (accountloginchallenge.Methods, error) {
	return fake.methods, fake.err
}

func (fake *fakeLoginService) Create(_ context.Context, input accountloginchallenge.CreateInput) (accountloginchallenge.CreateResult, error) {
	fake.createInput = input
	return fake.createResult, fake.err
}

func (fake *fakeLoginService) Verify(_ context.Context, input accountloginchallenge.VerifyInput) (accountloginchallenge.VerifyResult, error) {
	fake.verifyInput = input
	return fake.verifyResult, fake.err
}

func TestHandlerPublishesConfiguredLoginMethods(t *testing.T) {
	t.Parallel()

	fake := &fakeLoginService{methods: accountloginchallenge.Methods{
		RegistrationEnabled: true,
		EmailEnabled:        true, SMSEnabled: false, EmailAntiAbuseMode: "none", SMSAntiAbuseMode: "native",
	}}
	handler := newTestHandler(t, fake)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, MethodsPath, nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data["registration_enabled"] != true ||
		payload.Data["email_enabled"] != true || payload.Data["sms_enabled"] != false ||
		payload.Data["email_anti_abuse_mode"] != "none" || payload.Data["sms_anti_abuse_mode"] != "native" ||
		payload.Data["captcha_provider"] != "" || payload.Data["captcha_app_id"] != "" {
		t.Fatalf("payload=%v", payload.Data)
	}
}

func TestHandlerPublishesExternalCaptchaWidgetConfig(t *testing.T) {
	t.Parallel()

	fake := &fakeLoginService{methods: accountloginchallenge.Methods{
		EmailEnabled: true, SMSEnabled: true, EmailAntiAbuseMode: "none", SMSAntiAbuseMode: "tencent",
		CaptchaProvider: "tencent", CaptchaAppID: "190000001",
	}}
	response := httptest.NewRecorder()
	newTestHandler(t, fake).ServeHTTP(response, httptest.NewRequest(http.MethodGet, MethodsPath, nil))
	var payload struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || payload.Data["captcha_provider"] != "tencent" || payload.Data["captcha_app_id"] != "190000001" {
		t.Fatalf("status=%d payload=%v", response.Code, payload.Data)
	}
}

func TestHandlerCreatesGenericLoginChallengeWithStrictMetadata(t *testing.T) {
	t.Parallel()

	challengeID := uuid.New()
	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	fake := &fakeLoginService{createResult: accountloginchallenge.CreateResult{ChallengeID: challengeID, ExpiresAt: expiresAt}}
	handler := newTestHandler(t, fake)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, ChallengePath, strings.NewReader(`{"identifier":"OWNER@example.com","channel":"email","human_token":""}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "login-create-1")
	request.Header.Set("X-Request-ID", "login-request-1")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"accepted":true`) ||
		!strings.Contains(response.Body.String(), challengeID.String()) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.createInput.ScopeID == uuid.Nil || fake.createInput.Source != "192.0.2.44" ||
		fake.createInput.IdempotencyKey != "login-create-1" || fake.createInput.RequestID != "login-request-1" {
		t.Fatalf("create input=%+v", fake.createInput)
	}
}

func TestHandlerVerificationCreatesSessionCookies(t *testing.T) {
	t.Parallel()

	challengeID, userID, scopeID := uuid.New(), uuid.New(), uuid.New()
	fake := &fakeLoginService{verifyResult: accountloginchallenge.VerifyResult{Auth: identity.AuthResult{
		AccessToken: "access-token", ExpiresAt: time.Now().Add(time.Hour), RefreshToken: "refresh-token",
		RefreshExpiresAt: time.Now().Add(24 * time.Hour), Principal: identity.Principal{UserID: userID, ScopeID: scopeID},
	}}}
	handler := newTestHandler(t, fake)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, VerificationPath, strings.NewReader(`{"challenge_id":"`+challengeID.String()+`","identifier":"owner@example.com","channel":"email","otp":"123456"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "login-verify-1")
	request.Header.Set("X-Request-ID", "login-request-2")
	request.Header.Set("User-Agent", "login-test")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"access_token":"access-token"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != refreshCookie || cookies[0].Value != "refresh-token" || !cookies[0].HttpOnly ||
		cookies[1].Name != "cdnca_impersonation" || cookies[1].MaxAge != -1 {
		t.Fatalf("cookies=%+v", cookies)
	}
	if fake.verifyInput.ChallengeID != challengeID || fake.verifyInput.OTP != "123456" || fake.verifyInput.UserAgent != "login-test" {
		t.Fatalf("verify input=%+v", fake.verifyInput)
	}
}

func TestHandlerRejectsDuplicateJSONAndMapsRateLimit(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		fake       *fakeLoginService
		body       string
		wantStatus int
		wantCode   string
	}{
		"duplicate":  {fake: &fakeLoginService{}, body: `{"identifier":"a@example.com","identifier":"b@example.com","channel":"email","human_token":""}`, wantStatus: http.StatusUnprocessableEntity, wantCode: "account_login_invalid_request"},
		"rate limit": {fake: &fakeLoginService{err: accountloginchallenge.ErrRateLimited}, body: `{"identifier":"a@example.com","channel":"email","human_token":""}`, wantStatus: http.StatusTooManyRequests, wantCode: "account_login_rate_limited"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			handler := newTestHandler(t, test.fake)
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, ChallengePath, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "login-create-1")
			request.Header.Set("X-Request-ID", "login-request-1")
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantCode) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if errors.Is(test.fake.err, accountloginchallenge.ErrRateLimited) && response.Header().Get("Retry-After") == "" {
				t.Fatal("rate limit response omitted Retry-After")
			}
		})
	}
}

func newTestHandler(t *testing.T, service Service) *Handler {
	t.Helper()
	handler, err := NewHandler(service, TrustedContextResolverFunc(func(*http.Request) (TrustedContext, error) {
		return TrustedContext{ScopeID: uuid.New(), SourceIP: "192.0.2.44"}, nil
	}), Config{CookieSecure: true, RetryAfter: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
