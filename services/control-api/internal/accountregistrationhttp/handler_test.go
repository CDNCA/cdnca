package accountregistrationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/passwordpolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/google/uuid"
)

type registrationApplicationStub struct {
	result accountregistration.RegisterResult
	err    error
	calls  []accountregistration.RegisterInput
}

func (application *registrationApplicationStub) Register(
	_ context.Context,
	input accountregistration.RegisterInput,
) (accountregistration.RegisterResult, error) {
	application.calls = append(application.calls, input)
	return application.result, application.err
}

type registrationSourceStub struct {
	address netip.Addr
	err     error
	calls   int
}

type registrationScopeStub struct {
	scopeID uuid.UUID
	err     error
	calls   int
}

func (scope *registrationScopeStub) ResolveScope(*http.Request) (uuid.UUID, error) {
	scope.calls++
	return scope.scopeID, scope.err
}

func (source *registrationSourceStub) ResolveSourceIP(*http.Request) (netip.Addr, error) {
	source.calls++
	return source.address, source.err
}

type registrationProofReferenceStub struct {
	reference string
	err       error
	calls     int
}

func (proofs *registrationProofReferenceStub) ResolveProofReference(*http.Request) (string, error) {
	proofs.calls++
	return proofs.reference, proofs.err
}

func TestIAM02RegistrationHTTPUniformAcceptedContract(t *testing.T) {
	application := &registrationApplicationStub{result: accountregistration.RegisterResult{Accepted: true, Replayed: true}}
	source := &registrationSourceStub{address: netip.MustParseAddr("::ffff:203.0.113.8")}
	proofs := &registrationProofReferenceStub{reference: "server-proof-reference-registration"}
	handler := newRegistrationHTTPTestHandler(t, application, source, proofs, nil)
	request := registrationHTTPRequest(validRegistrationHTTPBody())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || response.Body.String() != "{\"accepted\":true,\"replayed\":true}\n" {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") != "request-registration-1" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %#v", response.Header())
	}
	if len(application.calls) != 1 || source.calls != 1 || proofs.calls != 1 {
		t.Fatalf("calls application/source/proof = %d/%d/%d", len(application.calls), source.calls, proofs.calls)
	}
	input := application.calls[0]
	if input.Username != "Alice" || input.Password != "Correct-horse-battery-staple" ||
		input.DisplayName != "Alice Example" || input.Email != "alice@example.com" ||
		input.Phone != "+8613800138000" || !input.TermsAccepted || input.TermsVersion != "terms-2026-08" ||
		input.VerificationChannel != accountregistration.VerificationEmail ||
		input.IdempotencyKey != "registration-http-1" || input.RequestID != "request-registration-1" ||
		input.Source != "203.0.113.8" || input.ProofReference != proofs.reference {
		t.Fatalf("application input = %+v", input)
	}
}

func TestIAM02RegistrationHTTPResolvesScopeForPolicyGatedApplication(t *testing.T) {
	application := &registrationApplicationStub{result: accountregistration.RegisterResult{Accepted: true}}
	scopeID := uuid.MustParse("88888888-8888-4888-8888-888888888888")
	scope := &registrationScopeStub{scopeID: scopeID}
	handler, err := NewHandler(application,
		&registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")},
		&registrationProofReferenceStub{reference: "server-proof-reference-registration"},
		Config{TermsVersion: "terms-2026-08", ScopeResolver: scope, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, registrationHTTPRequest(validRegistrationHTTPBody()))
	if response.Code != http.StatusAccepted || scope.calls != 1 || len(application.calls) != 1 || application.calls[0].ScopeID != scopeID {
		t.Fatalf("response=%d scopeCalls=%d application=%+v", response.Code, scope.calls, application.calls)
	}
}

func TestIAM02RegistrationHTTPFailsClosedWhenScopeResolutionUnavailable(t *testing.T) {
	application := &registrationApplicationStub{result: accountregistration.RegisterResult{Accepted: true}}
	scope := &registrationScopeStub{err: errors.New("scope unavailable")}
	handler, err := NewHandler(application,
		&registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")},
		&registrationProofReferenceStub{reference: "server-proof-reference-registration"},
		Config{TermsVersion: "terms-2026-08", ScopeResolver: scope, Logger: slog.Default()})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, registrationHTTPRequest(validRegistrationHTTPBody()))
	assertRegistrationHTTPError(t, response, http.StatusServiceUnavailable, "account_registration_unavailable")
	if len(application.calls) != 0 {
		t.Fatal("scope resolution failure reached application")
	}
}

func TestIAM02RegistrationHTTPStrictRequestBoundary(t *testing.T) {
	tests := map[string]struct {
		method      string
		path        string
		contentType []string
		requestID   []string
		idempotency []string
		body        string
		wantStatus  int
		wantCode    string
	}{
		"wrong path":            {path: "/v1/auth/other", wantStatus: 404, wantCode: "account_registration_invalid_input"},
		"wrong method":          {method: http.MethodGet, wantStatus: 405, wantCode: "account_registration_invalid_input"},
		"query":                 {path: registrationPath + "?debug=1", wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"content type":          {contentType: []string{"application/json; charset=utf-8"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"duplicate content":     {contentType: []string{"application/json", "application/json"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"request id":            {requestID: []string{"bad request id"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"duplicate request":     {requestID: []string{"request-registration-1", "request-registration-2"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"idempotency":           {idempotency: []string{"bad key"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"duplicate idempotency": {idempotency: []string{"registration-http-1", "registration-http-2"}, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"unknown field":         {body: strings.Replace(validRegistrationHTTPBody(), `"phone":"+8613800138000"`, `"phone":"+8613800138000","extra":true`, 1), wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"duplicate key":         {body: strings.Replace(validRegistrationHTTPBody(), `"username":"Alice"`, `"username":"Alice","username":"Bob"`, 1), wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"trailing value":        {body: validRegistrationHTTPBody() + `{}`, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"oversized":             {body: `{"username":"` + strings.Repeat("a", 2048) + `"}`, wantStatus: 422, wantCode: "account_registration_invalid_input"},
		"terms false":           {body: strings.Replace(validRegistrationHTTPBody(), `"terms_accepted":true`, `"terms_accepted":false`, 1), wantStatus: 422, wantCode: "account_registration_terms_required"},
		"terms stale":           {body: strings.Replace(validRegistrationHTTPBody(), "terms-2026-08", "terms-2025-01", 1), wantStatus: 422, wantCode: "account_registration_terms_required"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			application := &registrationApplicationStub{result: accountregistration.RegisterResult{Accepted: true}}
			handler := newRegistrationHTTPTestHandler(t, application,
				&registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")},
				&registrationProofReferenceStub{reference: "server-proof-reference-registration"}, nil)
			method := test.method
			if method == "" {
				method = http.MethodPost
			}
			path := test.path
			if path == "" {
				path = registrationPath
			}
			body := test.body
			if body == "" {
				body = validRegistrationHTTPBody()
			}
			request := httptest.NewRequest(method, path, strings.NewReader(body))
			contentTypes := test.contentType
			if contentTypes == nil {
				contentTypes = []string{"application/json"}
			}
			for _, value := range contentTypes {
				request.Header.Add("Content-Type", value)
			}
			requestIDs := test.requestID
			if requestIDs == nil {
				requestIDs = []string{"request-registration-1"}
			}
			for _, value := range requestIDs {
				request.Header.Add("X-Request-ID", value)
			}
			keys := test.idempotency
			if keys == nil {
				keys = []string{"registration-http-1"}
			}
			for _, value := range keys {
				request.Header.Add("Idempotency-Key", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertRegistrationHTTPError(t, response, test.wantStatus, test.wantCode)
			if len(application.calls) != 0 {
				t.Fatal("invalid request reached registration application")
			}
		})
	}
}

func TestIAM02RegistrationHTTPStableServiceErrors(t *testing.T) {
	tests := map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"invalid":      {accountregistration.ErrInvalidInput, 422, "account_registration_invalid_input"},
		"password":     {fmt.Errorf("%w: %w", accountregistration.ErrInvalidInput, passwordpolicy.Check("abcdefgh")), 422, "password_policy_unmet"},
		"proof":        {accountregistration.ErrProofInvalid, 422, "account_registration_invalid_input"},
		"rate":         {accountregistration.ErrRateLimited, 429, "account_registration_rate_limited"},
		"conflict":     {accountregistration.ErrIdempotencyConflict, 409, "account_registration_idempotency_conflict"},
		"proof down":   {accountregistration.ErrProofUnavailable, 503, "account_registration_unavailable"},
		"limiter down": {accountregistration.ErrRateLimitUnavailable, 503, "account_registration_unavailable"},
		"store down":   {errors.New("database unavailable"), 503, "account_registration_unavailable"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			application := &registrationApplicationStub{err: test.err}
			handler := newRegistrationHTTPTestHandler(t, application,
				&registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")},
				&registrationProofReferenceStub{reference: "server-proof-reference-registration"}, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, registrationHTTPRequest(validRegistrationHTTPBody()))
			assertRegistrationHTTPError(t, response, test.wantStatus, test.wantCode)
			if test.wantStatus == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "60" {
				t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
			}
		})
	}
}

func TestIAM02RegistrationHTTPDependenciesFailClosedWithoutSensitiveLogs(t *testing.T) {
	for name, test := range map[string]struct {
		source *registrationSourceStub
		proofs *registrationProofReferenceStub
	}{
		"source": {source: &registrationSourceStub{err: errors.New("spoofed source")}, proofs: &registrationProofReferenceStub{reference: "server-proof-reference-registration"}},
		"proof":  {source: &registrationSourceStub{address: netip.MustParseAddr("203.0.113.8")}, proofs: &registrationProofReferenceStub{err: errors.New("challenge unavailable")}},
	} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			application := &registrationApplicationStub{}
			handler := newRegistrationHTTPTestHandler(t, application, test.source, test.proofs, logger)
			body := validRegistrationHTTPBody()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, registrationHTTPRequest(body))
			assertRegistrationHTTPError(t, response, 503, "account_registration_unavailable")
			combined := logs.String() + response.Body.String()
			for _, secret := range []string{"Correct-horse-battery-staple", "alice@example.com", "+8613800138000", "server-proof-reference-registration"} {
				if strings.Contains(combined, secret) {
					t.Fatalf("sensitive value leaked: %q in %q", secret, combined)
				}
			}
			if len(application.calls) != 0 {
				t.Fatal("failed dependency reached registration application")
			}
		})
	}
}

func newRegistrationHTTPTestHandler(
	t *testing.T,
	application RegistrationApplication,
	source SourceIPResolver,
	proofs ProofReferenceResolver,
	logger *slog.Logger,
) *Handler {
	t.Helper()
	handler, err := NewHandler(application, source, proofs, Config{
		TermsVersion: "terms-2026-08", MaxRequestBytes: 1024,
		RetryAfter: time.Minute, Timeout: time.Second, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func registrationHTTPRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, registrationPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "request-registration-1")
	request.Header.Set("Idempotency-Key", "registration-http-1")
	return request
}

func validRegistrationHTTPBody() string {
	return `{"username":"Alice","password":"Correct-horse-battery-staple","display_name":"Alice Example","email":"alice@example.com","phone":"+8613800138000","terms_accepted":true,"terms_version":"terms-2026-08","verification_channel":"email"}`
}

func assertRegistrationHTTPError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	if response.Code != status || envelope.Error.Code != code || envelope.Error.RequestID == "" ||
		response.Header().Get("X-Request-ID") != envelope.Error.RequestID {
		t.Fatalf("response = %d %q", response.Code, response.Body.String())
	}
}
