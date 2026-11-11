package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
)

type builtInRegistrationStub struct {
	open   bool
	err    error
	inputs []accountregistration.BuiltInInput
}

func (stub *builtInRegistrationStub) Available(context.Context) (bool, error) { return stub.open, nil }

func (stub *builtInRegistrationStub) Register(_ context.Context, input accountregistration.BuiltInInput) (accountregistration.RegisterResult, error) {
	stub.inputs = append(stub.inputs, input)
	if stub.err != nil {
		return accountregistration.RegisterResult{}, stub.err
	}
	return accountregistration.RegisterResult{Accepted: true}, nil
}

func loginMethods(t *testing.T, api http.Handler) map[string]any {
	t.Helper()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/auth/login-methods", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Data
}

// builtin registration: a fresh install has no Turnstile registration runtime, so the
// sign-up link used to stay hidden and /register could never succeed. With
// 开放注册 on the built-in CAPTCHA registration is advertised and mounted.
func TestFreshInstallAdvertisesBuiltInRegistration(t *testing.T) {
	stub := &builtInRegistrationStub{open: true}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), BuiltInRegistration: stub}).Handler()
	data := loginMethods(t, api)
	if data["registration_enabled"] != true || data["registration_mode"] != "builtin" || data["email_enabled"] != false {
		t.Fatalf("login methods=%v", data)
	}
	stub.open = false
	if data := loginMethods(t, api); data["registration_enabled"] != false {
		t.Fatalf("closed switch still advertises registration: %v", data)
	}
}

func TestBuiltInRegisterRoute(t *testing.T) {
	stub := &builtInRegistrationStub{open: true}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), BuiltInRegistration: stub}).Handler()
	post := func(body string, key string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		request.RemoteAddr = "203.0.113.9:4000"
		response := httptest.NewRecorder()
		api.ServeHTTP(response, request)
		return response
	}
	valid := `{"username":"builtin registration-a","password":"Correct-horse-1","display_name":"A","email":"a@example.com","phone":"",` +
		`"terms_accepted":true,"terms_version":"terms-2026-08","verification_channel":"email",` +
		`"captcha":{"id":"22222222-2222-4222-8222-222222222222","answer":"AB2CD"}}`
	if response := post(valid, "registration-key-1"); response.Code != http.StatusAccepted ||
		!strings.Contains(response.Body.String(), `"accepted":true`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body)
	}
	if len(stub.inputs) != 1 || stub.inputs[0].Captcha.Answer != "AB2CD" || stub.inputs[0].Source != "203.0.113.9" ||
		stub.inputs[0].IdempotencyKey != "registration-key-1" {
		t.Fatalf("inputs=%#v", stub.inputs)
	}
	// no CAPTCHA reaches the service, which requires it
	// only when no verification is required (ErrCaptchaInvalid below).
	if response := post(strings.Replace(valid, `,"captcha":{"id":"22222222-2222-4222-8222-222222222222","answer":"AB2CD"}`, "", 1), "registration-key-2"); response.Code != http.StatusAccepted ||
		len(stub.inputs) != 2 || stub.inputs[1].Captcha.Answer != "" {
		t.Fatalf("missing captcha: status=%d body=%s", response.Code, response.Body)
	}
	for _, item := range []struct {
		err    error
		status int
		code   string
	}{
		{accountregistration.ErrCaptchaInvalid, http.StatusUnprocessableEntity, "account_registration_captcha_invalid"},
		{accountregistration.ErrProofInvalid, http.StatusUnprocessableEntity, "account_registration_verification_required"},
		{accountregistration.ErrRegistrationDisabled, http.StatusForbidden, "account_registration_disabled"},
		{accountregistration.ErrContactVerificationUnavailable, http.StatusServiceUnavailable, "account_registration_verification_unavailable"},
		{accountregistration.ErrIdempotencyConflict, http.StatusConflict, "account_registration_idempotency_conflict"},
	} {
		stub.err = item.err
		if response := post(valid, "registration-key-3"); response.Code != item.status || !strings.Contains(response.Body.String(), item.code) {
			t.Fatalf("%v: status=%d body=%s", item.err, response.Code, response.Body)
		}
	}
}

// With the Turnstile runtime mounted the built-in route is not used.
func TestBuiltInRegistrationYieldsToMountedRuntime(t *testing.T) {
	stub := &builtInRegistrationStub{open: true}
	called := false
	probe := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called = true
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), BuiltInRegistration: stub,
		AccountRegistrationHandlerFactory: func() (http.Handler, error) { return probe, nil }}).Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader("{}"))
	response := httptest.NewRecorder()
	api.ServeHTTP(response, request)
	if !called || len(stub.inputs) != 0 {
		t.Fatalf("called=%v builtin=%d", called, len(stub.inputs))
	}
}

type registrationConfigStub struct{ config RegistrationConfig }

func (stub registrationConfigStub) RegistrationConfig(context.Context) (RegistrationConfig, error) {
	return stub.config, nil
}

// the public registration config is always mounted; with
// no source it reports registration closed.
func TestRegistrationConfigEndpoint(t *testing.T) {
	read := func(api http.Handler) map[string]any {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/auth/registration-config", nil))
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d body=%s", response.Code, response.Body)
		}
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Data
	}
	closed := read(New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler())
	if closed["registration_enabled"] != false || closed["mode"] != "closed" {
		t.Fatalf("closed=%v", closed)
	}
	open := read(New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), RegistrationConfig: registrationConfigStub{RegistrationConfig{
		RegistrationEnabled: true, Mode: "builtin", HumanCheck: "builtin_captcha", Ready: true,
		Email: RegistrationChannel{Required: true, Available: true}, SMS: RegistrationChannel{Required: true, Available: false},
	}}}).Handler())
	email, sms := open["email"].(map[string]any), open["sms"].(map[string]any)
	if open["mode"] != "builtin" || email["required"] != true || sms["available"] != false {
		t.Fatalf("open=%v", open)
	}
	if recovery := open["recovery"].(map[string]any); recovery["channels"] == nil {
		t.Fatalf("recovery channels must be a list: %v", recovery)
	}
}
