package mfahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/mfa"
	"github.com/google/uuid"
)

const testTraceparent = "00-abcdefabcdefabcdefabcdefabcdefab-abcdefabcdefabcd-01"

type serviceStub struct {
	status   func(context.Context, mfa.Actor) (mfa.StatusResult, error)
	begin    func(context.Context, mfa.Actor, mfa.EnrollmentRequest) (mfa.EnrollmentResult, error)
	activate func(context.Context, mfa.Actor, mfa.ActivationRequest) (mfa.ActivationResult, error)
	create   func(context.Context, mfa.Actor, mfa.StepUpRequest) (mfa.StepUpResult, error)
	disable  func(context.Context, mfa.Actor, mfa.DeactivateRequest) error
	reset    func(context.Context, mfa.Actor, mfa.DeactivateRequest) error
}

func (stub *serviceStub) Status(ctx context.Context, actor mfa.Actor) (mfa.StatusResult, error) {
	if stub.status == nil {
		return mfa.StatusResult{}, mfa.ErrUnavailable
	}
	return stub.status(ctx, actor)
}

func (stub *serviceStub) BeginEnrollment(ctx context.Context, actor mfa.Actor,
	request mfa.EnrollmentRequest,
) (mfa.EnrollmentResult, error) {
	if stub.begin == nil {
		return mfa.EnrollmentResult{}, mfa.ErrUnavailable
	}
	return stub.begin(ctx, actor, request)
}

func (stub *serviceStub) Activate(ctx context.Context, actor mfa.Actor,
	request mfa.ActivationRequest,
) (mfa.ActivationResult, error) {
	if stub.activate == nil {
		return mfa.ActivationResult{}, mfa.ErrUnavailable
	}
	return stub.activate(ctx, actor, request)
}

func (stub *serviceStub) CreateStepUp(ctx context.Context, actor mfa.Actor,
	request mfa.StepUpRequest,
) (mfa.StepUpResult, error) {
	if stub.create == nil {
		return mfa.StepUpResult{}, mfa.ErrUnavailable
	}
	return stub.create(ctx, actor, request)
}

func (stub *serviceStub) Disable(ctx context.Context, actor mfa.Actor,
	request mfa.DeactivateRequest,
) error {
	if stub.disable == nil {
		return mfa.ErrUnavailable
	}
	return stub.disable(ctx, actor, request)
}

func (stub *serviceStub) Reset(ctx context.Context, actor mfa.Actor,
	request mfa.DeactivateRequest,
) error {
	if stub.reset == nil {
		return mfa.ErrUnavailable
	}
	return stub.reset(ctx, actor, request)
}

func TestHandlerFrozenRoutesAndOneTimeFields(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	credentialID, proofID, tenantID := uuid.New(), uuid.New(), uuid.New()
	actor, session := testActorAndSession()
	var beginCalls, activationCalls, proofCalls atomic.Int32
	stub := &serviceStub{
		begin: func(_ context.Context, actual mfa.Actor,
			request mfa.EnrollmentRequest,
		) (mfa.EnrollmentResult, error) {
			assertActorAndMetadata(t, actual, actor, request.IdempotencyKey, request.Context)
			if request.AccountLabel != "ops@example.test" {
				t.Fatalf("account label = %q", request.AccountLabel)
			}
			replayed := beginCalls.Add(1) > 1
			return mfa.EnrollmentResult{CredentialID: credentialID, Secret: "SECRET-ONCE",
				ProvisioningURI: "otpauth://totp/private", ExpiresAt: now.Add(time.Minute),
				Replayed: replayed}, nil
		},
		activate: func(_ context.Context, actual mfa.Actor,
			request mfa.ActivationRequest,
		) (mfa.ActivationResult, error) {
			assertActorAndMetadata(t, actual, actor, request.IdempotencyKey, request.Context)
			if request.CredentialID != credentialID || request.Code != "123456" {
				t.Fatal("activation request binding mismatch")
			}
			replayed := activationCalls.Add(1) > 1
			return mfa.ActivationResult{CredentialID: credentialID,
				RecoveryCodes: []string{"RECOVERY-SECRET"}, ActivatedAt: now, Replayed: replayed}, nil
		},
		create: func(_ context.Context, actual mfa.Actor,
			request mfa.StepUpRequest,
		) (mfa.StepUpResult, error) {
			assertActorAndMetadata(t, actual, actor, request.IdempotencyKey, request.Context)
			if request.TenantID != tenantID || request.Audience != "rbac" || request.Action != "role.assign" ||
				request.Authentication != (mfa.Authentication{Method: mfa.MethodRecoveryCode, Code: "ABCD"}) ||
				request.TTL != 45*time.Second || request.MaxUses != 2 {
				t.Fatal("step-up request binding mismatch")
			}
			replayed := proofCalls.Add(1) > 1
			return mfa.StepUpResult{ProofID: proofID, Token: "PROOF-TOKEN-ONCE",
				Method: mfa.MethodRecoveryCode, IssuedAt: now, ExpiresAt: now.Add(45 * time.Second),
				MaxUses: 2, Replayed: replayed}, nil
		},
		disable: func(_ context.Context, actual mfa.Actor, request mfa.DeactivateRequest) error {
			assertActorAndMetadata(t, actual, actor, request.IdempotencyKey, request.Context)
			if request.Authentication != (mfa.Authentication{Method: mfa.MethodTOTP, Code: "123456"}) ||
				request.Reason != "new phone" {
				t.Fatal("disable request binding mismatch")
			}
			return nil
		},
		reset: func(_ context.Context, actual mfa.Actor, request mfa.DeactivateRequest) error {
			assertActorAndMetadata(t, actual, actor, request.IdempotencyKey, request.Context)
			if request.Authentication.Method != mfa.MethodRecoveryCode || request.Reason != "lost device" {
				t.Fatal("reset request binding mismatch")
			}
			return nil
		},
	}
	handler := testHandler(t, stub, session)

	beginBody := `{"account_label":"ops@example.test"}`
	firstEnrollment := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments", beginBody, nil)
	assertStatus(t, firstEnrollment, http.StatusCreated)
	assertJSONField(t, firstEnrollment, "secret", true)
	assertJSONField(t, firstEnrollment, "provisioning_uri", true)
	replayedEnrollment := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments", beginBody, nil)
	assertStatus(t, replayedEnrollment, http.StatusOK)
	assertJSONField(t, replayedEnrollment, "secret", false)
	assertJSONField(t, replayedEnrollment, "provisioning_uri", false)

	activationPath := apiPrefix + "/enrollments/" + credentialID.String() + "/activate"
	firstActivation := serve(t, handler, http.MethodPost, activationPath, `{"code":"123456"}`, nil)
	assertStatus(t, firstActivation, http.StatusCreated)
	assertJSONField(t, firstActivation, "recovery_codes", true)
	replayedActivation := serve(t, handler, http.MethodPost, activationPath, `{"code":"123456"}`, nil)
	assertStatus(t, replayedActivation, http.StatusOK)
	assertJSONField(t, replayedActivation, "recovery_codes", false)

	proofBody := `{"tenant_id":"` + tenantID.String() + `","audience":"rbac","action":"role.assign",` +
		`"authentication":{"method":"recovery_code","code":"ABCD"},"ttl_seconds":45,"max_uses":2}`
	firstProof := serve(t, handler, http.MethodPost, apiPrefix+"/step-up-proofs", proofBody, nil)
	assertStatus(t, firstProof, http.StatusCreated)
	assertJSONField(t, firstProof, "token", true)
	replayedProof := serve(t, handler, http.MethodPost, apiPrefix+"/step-up-proofs", proofBody, nil)
	assertStatus(t, replayedProof, http.StatusOK)
	assertJSONField(t, replayedProof, "token", false)

	disable := serve(t, handler, http.MethodPost, apiPrefix+"/disable",
		`{"authentication":{"method":"totp","code":"123456"},"reason":"new phone"}`, nil)
	assertNoContent(t, disable)
	disableReplay := serve(t, handler, http.MethodPost, apiPrefix+"/disable",
		`{"authentication":{"method":"totp","code":"123456"},"reason":"new phone"}`, nil)
	assertNoContent(t, disableReplay)
	reset := serve(t, handler, http.MethodPost, apiPrefix+"/reset",
		`{"authentication":{"method":"recovery_code","code":"ABCD"},"reason":"lost device"}`, nil)
	assertNoContent(t, reset)
	resetReplay := serve(t, handler, http.MethodPost, apiPrefix+"/reset",
		`{"authentication":{"method":"recovery_code","code":"ABCD"},"reason":"lost device"}`, nil)
	assertNoContent(t, resetReplay)
}

func TestHandlerStatusOmitsInactiveAndStateInapplicableFields(t *testing.T) {
	actor, session := testActorAndSession()
	credentialID := uuid.New()
	expiresAt := time.Date(2026, 7, 28, 12, 10, 0, 0, time.UTC)
	tests := []struct {
		name       string
		result     mfa.StatusResult
		wantFields []string
		omitFields []string
	}{
		{"inactive", mfa.StatusResult{Status: mfa.StatusInactive, CredentialID: credentialID,
			Method: mfa.MethodTOTP, EnrollmentExpiresAt: &expiresAt},
			[]string{"status"}, []string{"credential_id", "method", "enrollment_expires_at"}},
		{"pending", mfa.StatusResult{Status: mfa.StatusPending, CredentialID: credentialID,
			Method: mfa.MethodTOTP, EnrollmentExpiresAt: &expiresAt},
			[]string{"status", "credential_id", "method", "enrollment_expires_at"}, nil},
		{"active", mfa.StatusResult{Status: mfa.StatusActive, CredentialID: credentialID,
			Method: mfa.MethodTOTP, EnrollmentExpiresAt: &expiresAt},
			[]string{"status", "credential_id", "method"}, []string{"enrollment_expires_at"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testHandler(t, &serviceStub{status: func(_ context.Context,
				actual mfa.Actor,
			) (mfa.StatusResult, error) {
				if actual != actor {
					t.Fatalf("actor=%#v want=%#v", actual, actor)
				}
				return test.result, nil
			}}, session)
			response := serve(t, handler, http.MethodGet, apiPrefix, "", func(request *http.Request) {
				request.Header.Del("Idempotency-Key")
				request.Header.Del("Content-Type")
			})
			assertStatus(t, response, http.StatusOK)
			for _, field := range test.wantFields {
				assertJSONField(t, response, field, true)
			}
			for _, field := range test.omitFields {
				assertJSONField(t, response, field, false)
			}
		})
	}
}

func TestHandlerStatusRequiresNoBodyQueryOrContentHeaders(t *testing.T) {
	handler := testHandler(t, &serviceStub{status: func(context.Context,
		mfa.Actor,
	) (mfa.StatusResult, error) {
		return mfa.StatusResult{Status: mfa.StatusInactive}, nil
	}}, testSession())
	tests := map[string]func(*http.Request){
		"body":  func(*http.Request) {},
		"query": func(request *http.Request) { request.URL.RawQuery = "state=active" },
		"content type": func(request *http.Request) {
			request.Body = http.NoBody
			request.ContentLength = 0
		},
		"content encoding": func(request *http.Request) {
			request.Body = http.NoBody
			request.ContentLength = 0
			request.Header.Del("Content-Type")
			request.Header.Set("Content-Encoding", "identity")
		},
		"transfer encoding": func(request *http.Request) {
			request.Body = http.NoBody
			request.ContentLength = -1
			request.TransferEncoding = []string{"chunked"}
			request.Header.Del("Content-Type")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := serve(t, handler, http.MethodGet, apiPrefix, "x", func(request *http.Request) {
				request.Header.Del("Idempotency-Key")
				if name != "content type" {
					request.Header.Del("Content-Type")
				}
				mutate(request)
			})
			assertAPIError(t, response, http.StatusBadRequest, "mfa_invalid_request")
		})
	}
}

func TestHandlerRoutesMethodsAndCanonicalPath(t *testing.T) {
	handler := testHandler(t, &serviceStub{}, testSession())
	credentialID := uuid.NewString()
	paths := []string{
		apiPrefix + "/enrollments", apiPrefix + "/enrollments/" + credentialID + "/activate",
		apiPrefix + "/step-up-proofs", apiPrefix + "/disable", apiPrefix + "/reset",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			route, found := resolveRoute(path)
			if !found || route.kind == "" {
				t.Fatalf("route not resolved: %s", path)
			}
			response := serve(t, handler, http.MethodGet, path, "", nil)
			assertAPIError(t, response, http.StatusMethodNotAllowed, "mfa_method_not_allowed")
			if response.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("Allow = %q", response.Header().Get("Allow"))
			}
		})
	}
	statusWrongMethod := serve(t, handler, http.MethodPost, apiPrefix, `{}`, nil)
	assertAPIError(t, statusWrongMethod, http.StatusMethodNotAllowed, "mfa_method_not_allowed")
	if statusWrongMethod.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("status Allow=%q", statusWrongMethod.Header().Get("Allow"))
	}
	for _, path := range []string{
		apiPrefix + "/", apiPrefix + "/enrollments/", apiPrefix + "/consume",
		apiPrefix + "/step-up-proofs/consume", apiPrefix + "/enrollments/" +
			strings.ToUpper(credentialID) + "/activate",
	} {
		t.Run("not-found-"+path, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, path, `{}`, nil)
			assertAPIError(t, response, http.StatusNotFound, "mfa_route_not_found")
		})
	}
}

func TestHandlerStrictRequestBoundary(t *testing.T) {
	handler := testHandler(t, &serviceStub{}, testSession())
	path := apiPrefix + "/enrollments"
	tests := []struct {
		name   string
		body   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{"unknown json", `{"account_label":"a","secret":"client"}`, nil, 400, "mfa_invalid_request"},
		{"duplicate json", `{"account_label":"a","account_label":"b"}`, nil, 400, "mfa_invalid_request"},
		{"multiple json", `{"account_label":"a"}{"account_label":"b"}`, nil, 400, "mfa_invalid_request"},
		{"empty body", ``, nil, 400, "mfa_invalid_request"},
		{"invalid utf8", "{\"account_label\":\"\xff\"}", nil, 400, "mfa_invalid_request"},
		{"unpaired high surrogate", `{"account_label":"\ud800"}`, nil, 400, "mfa_invalid_request"},
		{"unpaired low surrogate", `{"account_label":"\udc00"}`, nil, 400, "mfa_invalid_request"},
		{"content type parameter", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, 400, "mfa_invalid_request"},
		{"duplicate content type", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400, "mfa_invalid_request"},
		{"content encoding", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400, "mfa_invalid_request"},
		{"query", `{"account_label":"a"}`, func(r *http.Request) { r.URL.RawQuery = "x=1" }, 400, "mfa_invalid_request"},
		{"raw path", `{"account_label":"a"}`, func(r *http.Request) { r.URL.RawPath = "/v1/account/mfa/%65nrollments" }, 400, "mfa_invalid_request"},
		{"fragment", `{"account_label":"a"}`, func(r *http.Request) { r.URL.Fragment = "x" }, 400, "mfa_invalid_request"},
		{"oversized path", `{"account_label":"a"}`, func(r *http.Request) { r.URL.Path = "/" + strings.Repeat("x", maximumPathBytes) }, 400, "mfa_invalid_request"},
		{"missing request id", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Del("X-Request-ID") }, 400, "mfa_invalid_request"},
		{"duplicate request id", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Add("X-Request-ID", "other") }, 400, "mfa_invalid_request"},
		{"missing idempotency", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Del("Idempotency-Key") }, 400, "mfa_invalid_request"},
		{"duplicate idempotency", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") }, 400, "mfa_invalid_request"},
		{"invalid idempotency", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Set("Idempotency-Key", "invalid:key") }, 400, "mfa_invalid_request"},
		{"missing traceparent", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Del("Traceparent") }, 400, "mfa_invalid_request"},
		{"duplicate traceparent", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Add("Traceparent", testTraceparent) }, 400, "mfa_invalid_request"},
		{"uppercase traceparent", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Set("Traceparent", strings.ToUpper(testTraceparent)) }, 400, "mfa_invalid_request"},
		{"zero trace id", `{"account_label":"a"}`, func(r *http.Request) {
			r.Header.Set("Traceparent", "00-"+strings.Repeat("0", 32)+"-2222222222222222-01")
		}, 400, "mfa_invalid_request"},
		{"zero span id", `{"account_label":"a"}`, func(r *http.Request) {
			r.Header.Set("Traceparent", "00-11111111111111111111111111111111-"+strings.Repeat("0", 16)+"-01")
		}, 400, "mfa_invalid_request"},
		{"invalid trace flags", `{"account_label":"a"}`, func(r *http.Request) {
			r.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-03")
		}, 400, "mfa_invalid_request"},
		{"oversized headers", `{"account_label":"a"}`, func(r *http.Request) { r.Header.Set("X-Large", strings.Repeat("x", maximumHeaderBytes)) }, 400, "mfa_invalid_request"},
		{"oversized length", strings.Repeat("x", int(defaultRequestBytes+1)), nil, 413, "mfa_request_too_large"},
		{"streamed oversized", `{"account_label":"` + strings.Repeat("x", int(defaultRequestBytes)) + `"}`, func(r *http.Request) { r.ContentLength = -1 }, 413, "mfa_request_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, path, test.body, test.mutate)
			assertAPIError(t, response, test.status, test.code)
			assertSecurityHeaders(t, response)
		})
	}
	accepted := false
	unicodeHandler := testHandler(t, &serviceStub{begin: func(_ context.Context, _ mfa.Actor,
		request mfa.EnrollmentRequest,
	) (mfa.EnrollmentResult, error) {
		accepted = request.AccountLabel == string([]rune{0x1f600})
		return mfa.EnrollmentResult{CredentialID: uuid.New(), Secret: "one-time-secret",
			ProvisioningURI: "otpauth://totp/valid", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}, testSession())
	response := serve(t, unicodeHandler, http.MethodPost, path,
		`{"account_label":"\ud83d\ude00"}`, nil)
	assertStatus(t, response, http.StatusCreated)
	if !accepted {
		t.Fatal("valid surrogate pair was not decoded")
	}
}

func TestHandlerRejectsNestedDuplicateJSONFields(t *testing.T) {
	handler := testHandler(t, &serviceStub{}, testSession())
	body := `{"tenant_id":"11111111-1111-4111-8111-111111111111","audience":"rbac",` +
		`"action":"role.update","authentication":{"method":"totp","code":"123456",` +
		`"code":"654321"},"ttl_seconds":60,"max_uses":1}`
	response := serve(t, handler, http.MethodPost, apiPrefix+"/step-up-proofs", body, nil)
	assertAPIError(t, response, http.StatusBadRequest, "mfa_invalid_request")
	assertSecurityHeaders(t, response)
}

func TestHandlerRejectsNonBearerAmbiguousAndSpoofedPrincipals(t *testing.T) {
	var authCalls atomic.Int32
	handler, err := newHandler(&serviceStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		authCalls.Add(1)
		return testSession(), nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*http.Request){
		"missing":                 func(r *http.Request) { r.Header.Del("Authorization") },
		"CdncaKey scheme":         func(r *http.Request) { r.Header.Set("Authorization", "CdncaKey key.secret") },
		"lowercase bearer":        func(r *http.Request) { r.Header.Set("Authorization", "bearer token") },
		"empty bearer":            func(r *http.Request) { r.Header.Set("Authorization", "Bearer ") },
		"token whitespace":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer token two") },
		"duplicate authorization": func(r *http.Request) { r.Header.Add("Authorization", "Bearer other") },
		"combined authorization":  func(r *http.Request) { r.Header.Set("Authorization", "Bearer one,Bearer two") },
		"oversized bearer":        func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 8193)) },
		"CdncaKey header":         func(r *http.Request) { r.Header.Set("CdncaKey", "key.secret") },
	}
	for _, header := range []string{"X-Actor-ID", "X-User-ID", "X-Scope-ID", "X-Scope-Kind",
		"X-Tenant-ID", "X-Principal-ID", "X-Session-ID", "X-Role", "X-Permissions"} {
		header := header
		tests["spoof "+header] = func(r *http.Request) { r.Header.Set(header, "forged") }
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			response := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"a"}`, mutate)
			assertAPIError(t, response, http.StatusUnauthorized, "mfa_unauthenticated")
		})
	}
	if authCalls.Load() != 0 {
		t.Fatalf("invalid credential reached authenticator %d times", authCalls.Load())
	}
}

func TestHandlerActorOnlyUsesAuthenticatedSession(t *testing.T) {
	actor, session := testActorAndSession()
	called := false
	stub := &serviceStub{begin: func(_ context.Context, actual mfa.Actor,
		request mfa.EnrollmentRequest,
	) (mfa.EnrollmentResult, error) {
		called = true
		if actual != actor {
			t.Fatalf("actor = %#v, want %#v", actual, actor)
		}
		return mfa.EnrollmentResult{CredentialID: uuid.New(), Secret: "secret",
			ProvisioningURI: "otpauth://private", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	handler := testHandler(t, stub, session)
	response := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments",
		`{"account_label":"account"}`, nil)
	assertStatus(t, response, http.StatusCreated)
	if !called {
		t.Fatal("service was not called")
	}

	invalidSessions := []identity.AuthenticatedSession{
		{},
		{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}},
		{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", TenantID: pointerUUID(uuid.New())}},
		{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "system"}},
	}
	for index, invalid := range invalidSessions {
		handler := testHandler(t, stub, invalid)
		response := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments",
			`{"account_label":"account"}`, nil)
		assertAPIError(t, response, http.StatusUnauthorized, "mfa_unauthenticated")
		if index == 0 && response.Body.String() == "" {
			t.Fatal("empty error response")
		}
	}
}

func TestHandlerLiveSessionAndPrincipalRevocationFailClosed(t *testing.T) {
	serviceCalls := 0
	service := &serviceStub{status: func(context.Context, mfa.Actor) (mfa.StatusResult, error) {
		serviceCalls++
		return mfa.StatusResult{}, mfa.ErrPrincipalChanged
	}}
	invalidSession, err := newHandler(service, func(*http.Request,
		string,
	) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, invalidSession, http.MethodGet, apiPrefix, "", func(request *http.Request) {
		request.Header.Del("Idempotency-Key")
		request.Header.Del("Content-Type")
	})
	assertAPIError(t, response, http.StatusUnauthorized, "mfa_unauthenticated")
	if serviceCalls != 0 {
		t.Fatal("invalid live session reached MFA service")
	}

	revokedPrincipal := testHandler(t, service, testSession())
	response = serve(t, revokedPrincipal, http.MethodGet, apiPrefix, "", func(request *http.Request) {
		request.Header.Del("Idempotency-Key")
		request.Header.Del("Content-Type")
	})
	assertAPIError(t, response, http.StatusForbidden, "mfa_principal_changed")
	if serviceCalls != 1 {
		t.Fatalf("service calls=%d", serviceCalls)
	}
}

func TestHandlerTimeoutIncludesLiveSessionAuthentication(t *testing.T) {
	handler, err := newHandler(&serviceStub{}, func(request *http.Request,
		_ string,
	) (identity.AuthenticatedSession, error) {
		<-request.Context().Done()
		return identity.AuthenticatedSession{}, request.Context().Err()
	}, HandlerConfig{CommandTimeout: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, handler, http.MethodGet, apiPrefix, "", func(request *http.Request) {
		request.Header.Del("Idempotency-Key")
		request.Header.Del("Content-Type")
	})
	assertAPIError(t, response, http.StatusGatewayTimeout, "mfa_request_timeout")
}

func TestHandlerResponseLimitFailsClosedWithoutPartialSecret(t *testing.T) {
	service := &serviceStub{begin: func(context.Context, mfa.Actor,
		mfa.EnrollmentRequest,
	) (mfa.EnrollmentResult, error) {
		return mfa.EnrollmentResult{CredentialID: uuid.New(), Secret: strings.Repeat("s", 1024),
			ProvisioningURI: "otpauth://private", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	handler, err := newHandler(service, func(*http.Request,
		string,
	) (identity.AuthenticatedSession, error) {
		return testSession(), nil
	}, HandlerConfig{MaxResponseBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	response := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments",
		`{"account_label":"a"}`, nil)
	assertAPIError(t, response, http.StatusServiceUnavailable, "mfa_response_too_large")
	if strings.Contains(response.Body.String(), strings.Repeat("s", 16)) {
		t.Fatal("oversized response leaked secret")
	}
}

func TestHandlerUnknownCommitRetryReturnsSafeReplay(t *testing.T) {
	credentialID := uuid.New()
	now := time.Now().UTC()
	var calls atomic.Int32
	stub := &serviceStub{begin: func(context.Context, mfa.Actor,
		mfa.EnrollmentRequest,
	) (mfa.EnrollmentResult, error) {
		if calls.Add(1) == 1 {
			return mfa.EnrollmentResult{}, errors.New("commit outcome unknown SECRET CIPHERTEXT KEY")
		}
		return mfa.EnrollmentResult{CredentialID: credentialID, Secret: "SHOULD-NOT-REPLAY",
			ProvisioningURI: "otpauth://SHOULD-NOT-REPLAY", ExpiresAt: now, Replayed: true}, nil
	}}
	handler := testHandler(t, stub, testSession())
	first := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"a"}`, nil)
	assertAPIError(t, first, http.StatusServiceUnavailable, "mfa_unavailable")
	for _, secret := range []string{"SECRET", "CIPHERTEXT", "KEY", "commit outcome unknown"} {
		if strings.Contains(first.Body.String(), secret) {
			t.Fatalf("error leaked marker %q", secret)
		}
	}
	second := serve(t, handler, http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"a"}`, nil)
	assertStatus(t, second, http.StatusOK)
	assertJSONField(t, second, "secret", false)
	assertJSONField(t, second, "provisioning_uri", false)
	if strings.Contains(second.Body.String(), "SHOULD-NOT-REPLAY") {
		t.Fatal("replay leaked one-time value")
	}
}

func TestHandlerConcurrentRequestsAreRaceSafe(t *testing.T) {
	var calls atomic.Int32
	stub := &serviceStub{begin: func(context.Context, mfa.Actor,
		mfa.EnrollmentRequest,
	) (mfa.EnrollmentResult, error) {
		calls.Add(1)
		return mfa.EnrollmentResult{CredentialID: uuid.New(), Secret: "secret",
			ProvisioningURI: "otpauth://private", ExpiresAt: time.Now().Add(time.Minute)}, nil
	}}
	handler := testHandler(t, stub, testSession())
	const count = 32
	done := make(chan error, count)
	for index := range count {
		go func(index int) {
			request := validRequest(http.MethodPost, apiPrefix+"/enrollments", `{"account_label":"a"}`)
			request.Header.Set("X-Request-ID", "request-concurrent-"+strconv.Itoa(index))
			request.Header.Set("Idempotency-Key", "concurrent-"+strconv.Itoa(index))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusCreated {
				done <- errors.New(response.Body.String())
				return
			}
			done <- nil
		}(index)
	}
	for range count {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != count {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestPublicErrorMapping(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{mfa.ErrInvalidInput, 400, "mfa_invalid_request"},
		{mfa.ErrInvalidSession, 401, "mfa_unauthenticated"},
		{mfa.ErrPrincipalChanged, 403, "mfa_principal_changed"},
		{mfa.ErrProofBinding, 403, "mfa_proof_binding"},
		{mfa.ErrTenantUnavailable, 403, "mfa_tenant_unavailable"},
		{mfa.ErrAlreadyEnabled, 409, "mfa_already_enabled"},
		{mfa.ErrEnrollmentPending, 409, "mfa_enrollment_pending"},
		{mfa.ErrAlreadyActive, 409, "mfa_already_active"},
		{mfa.ErrIdempotencyConflict, 409, "mfa_idempotency_conflict"},
		{mfa.ErrCodeReplayed, 409, "mfa_code_replayed"},
		{mfa.ErrRecoveryCodeUsed, 409, "mfa_recovery_code_used"},
		{mfa.ErrProofConsumed, 409, "mfa_proof_consumed"},
		{mfa.ErrEnrollmentExpired, 410, "mfa_enrollment_expired"},
		{mfa.ErrProofExpired, 410, "mfa_proof_expired"},
		{mfa.ErrNotActive, 412, "mfa_not_active"},
		{mfa.ErrInvalidCode, 422, "mfa_invalid_code"},
		{mfa.ErrInvalidProof, 422, "mfa_invalid_proof"},
		{mfa.ErrEncryptionUnavailable, 503, "mfa_encryption_unavailable"},
		{mfa.ErrUnavailable, 503, "mfa_unavailable"},
		{context.Canceled, 408, "mfa_request_canceled"},
		{context.DeadlineExceeded, 504, "mfa_request_timeout"},
	}
	for _, test := range tests {
		status, code, message := publicError(test.err)
		if status != test.status || code != test.code || message == "" {
			t.Fatalf("publicError(%v) = %d %q %q", test.err, status, code, message)
		}
	}
}

func TestGenericHandlerConstructorFailsClosed(t *testing.T) {
	handler, err := NewHandler(nil, nil, HandlerConfig{})
	if handler != nil || !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewHandler = (%T,%v)", handler, err)
	}
	var typedNil *serviceStub
	handler, err = newHandler(typedNil, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return testSession(), nil
	}, HandlerConfig{})
	if handler != nil || !errors.Is(err, ErrInvalidService) {
		t.Fatalf("newHandler(typed nil) = (%T,%v)", handler, err)
	}
}

func testHandler(t *testing.T, service mfaService, session identity.AuthenticatedSession) *Handler {
	t.Helper()
	handler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return session, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testActorAndSession() (mfa.Actor, identity.AuthenticatedSession) {
	tenantID := uuid.New()
	session := identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", TenantID: &tenantID,
	}}
	return mfa.Actor{UserID: session.Principal.UserID, ScopeID: session.Principal.ScopeID,
		SessionID: session.SessionID}, session
}

func testSession() identity.AuthenticatedSession {
	_, session := testActorAndSession()
	return session
}

func pointerUUID(value uuid.UUID) *uuid.UUID { return &value }

func validRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer formal-session-token")
	request.Header.Set("X-Request-ID", "request-1")
	request.Header.Set("Idempotency-Key", "idempotency-1")
	request.Header.Set("Traceparent", testTraceparent)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func serve(t *testing.T, handler http.Handler, method, path, body string,
	mutate func(*http.Request),
) *httptest.ResponseRecorder {
	t.Helper()
	request := validRequest(method, path, body)
	if mutate != nil {
		mutate(request)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func assertActorAndMetadata(t *testing.T, actual, expected mfa.Actor, key string,
	metadata mfa.RequestContext,
) {
	t.Helper()
	if actual != expected || key != "idempotency-1" || metadata.RequestID != "request-1" ||
		metadata.TraceID != "abcdefabcdefabcdefabcdefabcdefab" {
		t.Fatalf("actor=%#v key=%q metadata=%#v", actual, key, metadata)
	}
}

func assertStatus(t *testing.T, response *httptest.ResponseRecorder, status int) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d", response.Code, status)
	}
	assertSecurityHeaders(t, response)
}

func assertNoContent(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	assertStatus(t, response, http.StatusNoContent)
	if response.Body.Len() != 0 || response.Header().Get("Content-Type") != "" {
		t.Fatalf("204 response body_bytes=%d content-type-present=%t", response.Body.Len(),
			response.Header().Get("Content-Type") != "")
	}
}

func assertJSONField(t *testing.T, response *httptest.ResponseRecorder, field string, want bool) {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(response.Body.Bytes())).Decode(&object); err != nil {
		t.Fatal(err)
	}
	_, found := object[field]
	if found != want {
		t.Fatalf("field %q found=%t want=%t", field, found, want)
	}
}

func assertAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d", response.Code, status)
	}
	var envelope errorEnvelope
	if err := json.NewDecoder(bytes.NewReader(response.Body.Bytes())).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.Message == "" || envelope.Error.RequestID == "" ||
		response.Header().Get("X-Request-ID") != envelope.Error.RequestID {
		t.Fatalf("error=%#v headers=%v", envelope.Error, response.Header())
	}
}

func assertSecurityHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	wants := map[string]string{
		"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
		"Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'",
		"X-Frame-Options": "DENY", "X-Request-ID": response.Header().Get("X-Request-ID"),
	}
	for name, want := range wants {
		if got := response.Header().Get(name); got == "" || got != want {
			t.Fatalf("%s=%q want=%q", name, got, want)
		}
	}
}
