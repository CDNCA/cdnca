package accountrecoveryhttp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/google/uuid"
)

var (
	handlerTestKey = bytes.Repeat([]byte{0x61}, 32)
	handlerTestNow = time.Date(2026, 7, 23, 4, 0, 0, 0, time.UTC)
)

type fakeRecoveryService struct {
	requestResult accountrecovery.RequestResult
	requestErr    error
	resetResult   accountrecovery.ResetResult
	resetErr      error
	requestInput  accountrecovery.RequestInput
	resetInput    accountrecovery.ResetInput
	requestCalls  int
	resetCalls    int
	waitForCancel bool
}

func (service *fakeRecoveryService) Request(
	ctx context.Context,
	input accountrecovery.RequestInput,
) (accountrecovery.RequestResult, error) {
	service.requestCalls++
	service.requestInput = input
	if service.waitForCancel {
		<-ctx.Done()
		return accountrecovery.RequestResult{}, ctx.Err()
	}
	return service.requestResult, service.requestErr
}

func (service *fakeRecoveryService) Reset(
	ctx context.Context,
	input accountrecovery.ResetInput,
) (accountrecovery.ResetResult, error) {
	service.resetCalls++
	service.resetInput = input
	if service.waitForCancel {
		<-ctx.Done()
		return accountrecovery.ResetResult{}, ctx.Err()
	}
	return service.resetResult, service.resetErr
}

func TestRequestUsesTrustedScopeAndHasEnumerationSafeResponse(t *testing.T) {
	service := &fakeRecoveryService{requestResult: accountrecovery.RequestResult{AcceptedAt: handlerTestNow}}
	trusted := testTrustedContext()
	handler := testHandler(t, service, trusted, Config{})

	var firstBody string
	for index, auth := range []string{"", "Bearer public-token", "ApiKey public-key"} {
		request := jsonRequest(t, requestPath, `{"username":"  Recover@Example.Test  "}`, "same-request")
		if auth != "" {
			request.Header.Set("Authorization", auth)
			request.Header.Set("X-API-Key", "ignored-key")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("auth %q status=%d body=%s", auth, response.Code, response.Body.String())
		}
		if index == 0 {
			firstBody = response.Body.String()
		} else if response.Body.String() != firstBody {
			t.Fatalf("auth changed response: first=%s current=%s", firstBody, response.Body.String())
		}
		assertSecurityHeaders(t, response, trusted.RequestID)
	}
	if service.requestInput.TenantID != trusted.TenantID || service.requestInput.ScopeID != trusted.ScopeID ||
		service.requestInput.Username != "Recover@Example.Test" ||
		service.requestInput.Context.SourceIP != "198.51.100.10" {
		t.Fatalf("request input = %+v", service.requestInput)
	}
	for _, forbidden := range []string{"tenant_id", "scope_id", "token", "exists", "disabled", "delivery"} {
		if strings.Contains(firstBody, forbidden) {
			t.Fatalf("request response leaked %q: %s", forbidden, firstBody)
		}
	}
}

func TestConfirmationUsesSignedScopeAndIgnoresTrustedScopeAndAuth(t *testing.T) {
	tenantID, scopeID := uuid.New(), uuid.New()
	token := testToken(0x41)
	recoveryContext := testRecoveryContext(t, handlerTestKey, tenantID, scopeID, token, handlerTestNow.Add(time.Minute))
	service := &fakeRecoveryService{resetResult: accountrecovery.ResetResult{
		CompletedAt: handlerTestNow, Replayed: true,
	}}
	trusted := testTrustedContext()
	handler := testHandler(t, service, trusted, Config{})
	request := jsonRequest(t, confirmationPath, confirmationJSON(token, recoveryContext), "confirm-request")
	request.Header.Set("Authorization", "Bearer ignored")
	request.Header.Set("X-API-Key", "ignored")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
		response.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatalf("confirmation response status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
	}
	if service.resetInput.TenantID != tenantID || service.resetInput.ScopeID != scopeID ||
		service.resetInput.TenantID == trusted.TenantID || service.resetInput.Token != token {
		t.Fatalf("reset input scope/token = %+v", service.resetInput)
	}
	assertSecurityHeaders(t, response, trusted.RequestID)
}

func TestHandlerRejectsStrictInputBeforeCallingService(t *testing.T) {
	trusted := testTrustedContext()
	tenantID, scopeID := uuid.New(), uuid.New()
	token := testToken(0x42)
	recoveryContext := testRecoveryContext(t, handlerTestKey, tenantID, scopeID, token, handlerTestNow.Add(time.Minute))
	tamperedRecoveryContext := tamperRecoveryContext(t, recoveryContext)
	tests := []struct {
		name        string
		path        string
		body        string
		contentType string
		key         string
		mutate      func(*http.Request)
		code        string
	}{
		{name: "unknown field", path: requestPath, body: `{"username":"user","tenant_id":"forbidden"}`, key: "strict-1", code: "account_recovery_invalid_request"},
		{name: "duplicate field", path: requestPath, body: `{"username":"first","username":"second"}`, key: "strict-duplicate", code: "account_recovery_invalid_request"},
		{name: "trailing JSON", path: requestPath, body: `{"username":"user"}{}`, key: "strict-2", code: "account_recovery_invalid_request"},
		{name: "content type parameter", path: requestPath, body: `{"username":"user"}`, contentType: "application/json; charset=utf-8", key: "strict-3", code: "account_recovery_invalid_request"},
		{name: "empty username", path: requestPath, body: `{"username":"  "}`, key: "strict-4", code: "account_recovery_invalid_request"},
		{name: "query forbidden", path: requestPath + "?tenant_id=" + uuid.NewString(), body: `{"username":"user"}`, key: "strict-5", code: "account_recovery_invalid_request"},
		{name: "missing key", path: requestPath, body: `{"username":"user"}`, code: "account_recovery_invalid_request"},
		{name: "duplicate key", path: requestPath, body: `{"username":"user"}`, key: "strict-7", mutate: func(request *http.Request) { request.Header.Add("Idempotency-Key", "other") }, code: "account_recovery_invalid_request"},
		{name: "password mismatch", path: confirmationPath, body: strings.Replace(confirmationJSON(token, recoveryContext), `"confirm_password":"Changed-password-1234"`, `"confirm_password":"Different-password-1234"`, 1), key: "strict-8", code: "account_recovery_invalid_request"},
		{name: "short password", path: confirmationPath, body: strings.ReplaceAll(confirmationJSON(token, recoveryContext), "Changed-password-1234", "short"), key: "strict-9", code: "password_policy_unmet"},
		{name: "cross token", path: confirmationPath, body: confirmationJSON(testToken(0x43), recoveryContext), key: "strict-10", code: "account_recovery_invalid_token"},
		{name: "tampered context", path: confirmationPath, body: confirmationJSON(token, tamperedRecoveryContext), key: "strict-11", code: "account_recovery_invalid_token"},
		{name: "oversized", path: requestPath, body: `{"username":"` + strings.Repeat("x", 2048) + `"}`, key: "strict-12", code: "account_recovery_invalid_request"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeRecoveryService{}
			handler := testHandler(t, service, trusted, Config{MaxRequestBytes: 1024})
			request := jsonRequest(t, test.path, test.body, test.key)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.mutate != nil {
				test.mutate(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code < 400 || responseCode(t, response) != test.code {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if service.requestCalls != 0 || service.resetCalls != 0 {
				t.Fatalf("service calls request/reset=%d/%d", service.requestCalls, service.resetCalls)
			}
		})
	}

	expired := testRecoveryContext(t, handlerTestKey, tenantID, scopeID, token, handlerTestNow)
	service := &fakeRecoveryService{}
	handler := testHandler(t, service, trusted, Config{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jsonRequest(t, confirmationPath, confirmationJSON(token, expired), "strict-expired"))
	if response.Code != http.StatusBadRequest || responseCode(t, response) != "account_recovery_invalid_token" || service.resetCalls != 0 {
		t.Fatalf("expired response status=%d body=%s calls=%d", response.Code, response.Body.String(), service.resetCalls)
	}
}

func TestHandlerMapsStableErrorsWithoutLeakingCauses(t *testing.T) {
	tenantID, scopeID := uuid.New(), uuid.New()
	token := testToken(0x44)
	recoveryContext := testRecoveryContext(t, handlerTestKey, tenantID, scopeID, token, handlerTestNow.Add(time.Minute))
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "rate", err: accountrecovery.ErrRateLimited, status: 429, code: "account_recovery_rate_limited"},
		{name: "invalid token", err: accountrecovery.ErrInvalidToken, status: 400, code: "account_recovery_invalid_token"},
		{name: "password policy", err: accountrecovery.ErrPasswordPolicy, status: 422, code: "password_policy_unmet"},
		{name: "password reused", err: accountrecovery.ErrPasswordReused, status: 422, code: "account_recovery_password_reused"},
		{name: "principal changed", err: accountrecovery.ErrPrincipalChanged, status: 409, code: "account_recovery_principal_changed"},
		{name: "idempotency", err: accountrecovery.ErrIdempotencyConflict, status: 409, code: "account_recovery_idempotency_conflict"},
		{name: "cancelled", err: context.Canceled, status: 408, code: "account_recovery_request_cancelled"},
		{name: "timeout", err: context.DeadlineExceeded, status: 504, code: "account_recovery_timeout"},
		{name: "dispatch", err: accountrecovery.ErrDispatchUnavailable, status: 503, code: "account_recovery_unavailable"},
		{name: "scope", err: accountrecovery.ErrScopeMismatch, status: 503, code: "account_recovery_unavailable"},
		{name: "dependency", err: errors.New("dial failed password=secret"), status: 503, code: "account_recovery_unavailable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeRecoveryService{resetErr: test.err}
			handler := testHandler(t, service, testTrustedContext(), Config{})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, jsonRequest(t, confirmationPath,
				confirmationJSON(token, recoveryContext), "map-"+strings.ReplaceAll(test.name, " ", "-")))
			if response.Code != test.status || responseCode(t, response) != test.code {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if test.status == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "900" {
				t.Fatalf("Retry-After=%q", response.Header().Get("Retry-After"))
			}
			if strings.Contains(response.Body.String(), test.err.Error()) || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("response leaked cause: %s", response.Body.String())
			}
		})
	}
}

func TestHandlerRoutesMetadataAndTimeout(t *testing.T) {
	trusted := testTrustedContext()
	service := &fakeRecoveryService{}
	handler := testHandler(t, service, trusted, Config{})

	request := jsonRequest(t, "/v1/account-recovery/unknown", `{}`, "route")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || responseCode(t, response) != "account_recovery_route_not_found" {
		t.Fatalf("route response status=%d body=%s", response.Code, response.Body.String())
	}
	request = jsonRequest(t, requestPath, `{"username":"user"}`, "method")
	request.Method = http.MethodGet
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("method response status=%d headers=%v", response.Code, response.Header())
	}

	resolverError, err := NewHandler(service, func(*http.Request) (TrustedContext, error) {
		return TrustedContext{}, errors.New("resolver secret")
	}, testConfig(Config{}))
	if err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	resolverError.ServeHTTP(response, jsonRequest(t, requestPath, `{"username":"user"}`, "metadata"))
	if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "account_recovery_unavailable" ||
		strings.Contains(response.Body.String(), "resolver") {
		t.Fatalf("resolver response status=%d body=%s", response.Code, response.Body.String())
	}

	timeoutService := &fakeRecoveryService{waitForCancel: true}
	timeoutHandler := testHandler(t, timeoutService, trusted, Config{Timeout: time.Millisecond})
	response = httptest.NewRecorder()
	timeoutHandler.ServeHTTP(response, jsonRequest(t, requestPath, `{"username":"user"}`, "timeout"))
	if response.Code != http.StatusGatewayTimeout || responseCode(t, response) != "account_recovery_timeout" {
		t.Fatalf("timeout response status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestNewHandlerRejectsInvalidConfiguration(t *testing.T) {
	service := &fakeRecoveryService{}
	resolve := func(*http.Request) (TrustedContext, error) { return testTrustedContext(), nil }
	tests := []struct {
		name    string
		service RecoveryService
		resolve ResolveTrustedContext
		config  Config
	}{
		{name: "nil service", resolve: resolve, config: testConfig(Config{})},
		{name: "nil resolver", service: service, config: testConfig(Config{})},
		{name: "short key", service: service, resolve: resolve, config: Config{DigestKey: handlerTestKey[:31]}},
		{name: "timeout", service: service, resolve: resolve, config: testConfig(Config{Timeout: 31 * time.Second})},
		{name: "negative retry", service: service, resolve: resolve, config: testConfig(Config{RetryAfter: -time.Second})},
		{name: "long retry", service: service, resolve: resolve, config: testConfig(Config{RetryAfter: 24*time.Hour + time.Second})},
		{name: "request size", service: service, resolve: resolve, config: testConfig(Config{MaxRequestBytes: 512})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewHandler(test.service, test.resolve, test.config); err == nil {
				t.Fatal("expected invalid configuration error")
			}
		})
	}
}

func testHandler(t *testing.T, service RecoveryService, trusted TrustedContext, overrides Config) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(*http.Request) (TrustedContext, error) {
		return trusted, nil
	}, testConfig(overrides))
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testConfig(overrides Config) Config {
	if overrides.DigestKey == nil {
		overrides.DigestKey = handlerTestKey
	}
	if overrides.Clock == nil {
		overrides.Clock = func() time.Time { return handlerTestNow }
	}
	if overrides.Logger == nil {
		overrides.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return overrides
}

func testTrustedContext() TrustedContext {
	return TrustedContext{
		TenantID: uuid.New(), ScopeID: uuid.New(), RequestID: "recovery-request-id",
		TraceID: "0123456789abcdef0123456789abcdef", SourceIP: "198.51.100.10",
	}
}

func jsonRequest(t *testing.T, path, body, key string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	return request
}

func confirmationJSON(token, recoveryContext string) string {
	encoded, _ := json.Marshal(map[string]string{
		"token": token, "recovery_context": recoveryContext,
		"new_password": "Changed-password-1234", "confirm_password": "Changed-password-1234",
	})
	return string(encoded)
}

func responseCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
	return envelope.Error.Code
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder, requestID string) {
	t.Helper()
	if response.Header().Get("X-Request-ID") != requestID ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" ||
		response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers = %v", response.Header())
	}
}

func testToken(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}

func tamperRecoveryContext(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		t.Fatalf("decode recovery context: %v", err)
	}
	raw[len(raw)-1] ^= 1
	return base64.RawURLEncoding.EncodeToString(raw)
}

func testRecoveryContext(
	t *testing.T,
	key []byte,
	tenantID, scopeID uuid.UUID,
	token string,
	expiresAt time.Time,
) string {
	t.Helper()
	payload := make([]byte, 89)
	payload[0] = 1
	copy(payload[1:17], tenantID[:])
	copy(payload[17:33], scopeID[:])
	challengeID := uuid.New()
	copy(payload[33:49], challengeID[:])
	binary.BigEndian.PutUint64(payload[49:57], uint64(expiresAt.UnixMicro()))
	tokenDigest := testDomainDigest(key, "cdnca/account-recovery/token/v1", []byte(token))
	copy(payload[57:89], tokenDigest[:])
	signature := testDomainDigest(key, "cdnca/account-recovery/recovery-context/v1", payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, signature[:]...))
}

func testDomainDigest(key []byte, domain string, value []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}
