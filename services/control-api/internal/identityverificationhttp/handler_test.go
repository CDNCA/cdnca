package identityverificationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/identityverification"
	"github.com/google/uuid"
)

func TestHandlerCreateRejectsClientFingerprintAndReturnsSafeSuccess(t *testing.T) {
	actor := testActor()
	coreCalls := 0
	core := &coreStub{create: func(context.Context, identityverification.Actor,
		identityverification.CreateDraftRequest,
	) (identityverification.Case, error) {
		coreCalls++
		return testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1), nil
	}}
	resolver := resolverStub{resolve: func(context.Context, identityverification.Actor,
		EvidenceReference,
	) (ResolvedEvidence, error) {
		return ResolvedEvidence{Kind: identityverification.KindPersonalInitial}, nil
	}}
	handler := testHandler(t, testService(t, core, &readerStub{}, resolver), actor)

	bad := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases",
		strings.NewReader(`{"kind":"personal_initial","evidence_token":"`+strings.Repeat("a", 32)+`","subject_fingerprint":"client"}`))
	setWriteHeaders(bad, "create-bad", 0)
	bad.Header.Set("Content-Type", "application/json")
	setTestAuthorization(bad)
	badRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badRecorder, bad)
	assertAPIError(t, badRecorder, http.StatusBadRequest, "identity_verification_invalid_request")
	if coreCalls != 0 {
		t.Fatalf("client fingerprint reached core")
	}

	good := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases",
		strings.NewReader(`{"kind":"personal_initial","evidence_token":"`+strings.Repeat("a", 32)+`"}`))
	setWriteHeaders(good, "create-good", 0)
	good.Header.Set("Content-Type", "application/json")
	setTestAuthorization(good)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, good)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("ETag") != `"1"` || coreCalls != 1 {
		t.Fatalf("create response = %d %s calls=%d", recorder.Code, recorder.Body.String(), coreCalls)
	}
	if strings.Contains(recorder.Body.String(), "fingerprint") || strings.Contains(recorder.Body.String(), "object_reference") {
		t.Fatalf("create response leaked sensitive contract: %s", recorder.Body.String())
	}
}

func TestHandlerStrictHeadersQueryBodyAndReviewerExpireBoundary(t *testing.T) {
	actor := testActor()
	service := testService(t, &coreStub{}, &readerStub{}, resolverStub{})
	handler := testHandler(t, service, actor)
	caseID := uuid.NewString()

	tests := []struct {
		name    string
		request *http.Request
		status  int
	}{
		{"unknown query", httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+caseID+"?tenant_id="+uuid.NewString(), nil), http.StatusBadRequest},
		{"body on get", httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+caseID, strings.NewReader("x")), http.StatusBadRequest},
		{"noncanonical UUID", httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+strings.ToUpper(caseID), nil), http.StatusNotFound},
		{"reviewer expire absent", httptest.NewRequest(http.MethodPost, apiPrefix+"/reviewer/cases/"+caseID+"/expire", nil), http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setTestAuthorization(test.request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, test.request)
			if recorder.Code != test.status {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}

	duplicate := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases",
		strings.NewReader(`{"kind":"personal_initial","evidence_token":"`+strings.Repeat("d", 32)+`"}`))
	duplicate.Header["X-Request-Id"] = []string{"one", "two"}
	duplicate.Header.Set("Idempotency-Key", "duplicate")
	duplicate.Header.Set("Content-Type", "application/json")
	setTestAuthorization(duplicate)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, duplicate)
	assertAPIError(t, recorder, http.StatusBadRequest, "identity_verification_invalid_request")
}

func TestHandlerRejectsExplicitEmptyWriteHeaders(t *testing.T) {
	handler := testHandler(t, testService(t, &coreStub{}, &readerStub{}, resolverStub{}), testActor())
	for _, name := range []string{"X-Request-ID", "Idempotency-Key", "Content-Type"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases",
				strings.NewReader(`{"kind":"personal_initial","evidence_token":"`+strings.Repeat("e", 32)+`"}`))
			setWriteHeaders(request, "empty-header", 0)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(name, "")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertAPIError(t, recorder, http.StatusBadRequest, "identity_verification_invalid_request")
		})
	}
}

func TestHandlerMapsDomainErrorsWithoutRawSQLOrPII(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	core := &coreStub{get: func(context.Context, identityverification.Actor, uuid.UUID) (identityverification.Case, error) {
		return identityverification.Case{}, errors.New("pq: identity_verification_cases document_number=secret-123")
	}}
	handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
	request := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+caseID.String(), nil)
	setTestAuthorization(request)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assertAPIError(t, recorder, http.StatusServiceUnavailable, "identity_verification_unavailable")
	for _, prohibited := range []string{"pq:", "identity_verification_cases", "document_number", "secret-123"} {
		if strings.Contains(recorder.Body.String(), prohibited) {
			t.Fatalf("error leaked %q: %s", prohibited, recorder.Body.String())
		}
	}
}

func TestHandlerContextCancellationIsStable(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	core := &coreStub{get: func(ctx context.Context, _ identityverification.Actor,
		_ uuid.UUID,
	) (identityverification.Case, error) {
		return identityverification.Case{}, ctx.Err()
	}}
	handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+caseID.String(), nil).WithContext(ctx)
	setTestAuthorization(request)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assertAPIError(t, recorder, http.StatusRequestTimeout, "identity_verification_request_canceled")
}

func TestHandlerMutationRequiresCanonicalIdempotencyRequestAndRevision(t *testing.T) {
	actor := testActor()
	caseID := uuid.New()
	core := &coreStub{mutation: func(operation string, _ context.Context, actual identityverification.Actor,
		request identityverification.MutationRequest,
	) (identityverification.Case, error) {
		if operation != "submit" || actual != actor || request.CaseID != caseID || request.ExpectedRevision != 7 ||
			request.IdempotencyKey != "submit-7" || request.RequestID != "request-7" {
			t.Fatalf("mutation = %s %#v %#v", operation, actual, request)
		}
		return testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusSubmitted, 8), nil
	}}
	handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
	request := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases/"+caseID.String()+"/submit", nil)
	request.Header.Set("X-Request-ID", "request-7")
	request.Header.Set("Idempotency-Key", "submit-7")
	request.Header.Set("If-Match", `"7"`)
	setTestAuthorization(request)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("ETag") != `"8"` {
		t.Fatalf("submit response = %d %s", recorder.Code, recorder.Body.String())
	}

	bad := httptest.NewRequest(http.MethodPost, apiPrefix+"/cases/"+caseID.String()+"/submit", nil)
	bad.Header.Set("X-Request-ID", "request-7")
	bad.Header.Set("Idempotency-Key", "submit-7")
	bad.Header.Set("If-Match", `W/"7"`)
	setTestAuthorization(bad)
	badRecorder := httptest.NewRecorder()
	handler.ServeHTTP(badRecorder, bad)
	assertAPIError(t, badRecorder, http.StatusBadRequest, "identity_verification_invalid_request")
}

func TestHandlerUsesOnlyServerAuthenticatedTenantPrincipal(t *testing.T) {
	actor := testActor()
	coreCalls := 0
	core := &coreStub{get: func(_ context.Context, actual identityverification.Actor,
		_ uuid.UUID,
	) (identityverification.Case, error) {
		coreCalls++
		if actual != actor {
			t.Fatalf("actor = %#v, want %#v", actual, actor)
		}
		return testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusDraft, 1), nil
	}}
	service := testService(t, core, &readerStub{}, resolverStub{})
	handler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: actor.SessionID(), Principal: identity.Principal{
			UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: "tenant",
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+uuid.NewString(), nil)
	request.Header.Set("X-User-ID", uuid.NewString())
	request.Header.Set("X-Scope-ID", uuid.NewString())
	request.Header.Set("X-Tenant-ID", uuid.NewString())
	setTestAuthorization(request)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || coreCalls != 0 {
		t.Fatalf("response = %d %s calls=%d", recorder.Code, recorder.Body.String(), coreCalls)
	}
	clean := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+uuid.NewString(), nil)
	setTestAuthorization(clean)
	cleanRecorder := httptest.NewRecorder()
	handler.ServeHTTP(cleanRecorder, clean)
	if cleanRecorder.Code != http.StatusOK || coreCalls != 1 {
		t.Fatalf("clean response = %d %s calls=%d", cleanRecorder.Code, cleanRecorder.Body.String(), coreCalls)
	}

	platformHandler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: actor.SessionID(), Principal: identity.Principal{
			UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: "platform",
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	platformRecorder := httptest.NewRecorder()
	platformRequest := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+uuid.NewString(), nil)
	setTestAuthorization(platformRequest)
	platformHandler.ServeHTTP(platformRecorder, platformRequest)
	assertAPIError(t, platformRecorder, http.StatusUnauthorized, "identity_verification_unauthenticated")
	if coreCalls != 1 {
		t.Fatalf("invalid principal reached core: calls=%d", coreCalls)
	}
}

func TestHandlerRequiresCanonicalBearerSession(t *testing.T) {
	actor := testActor()
	calls := 0
	service := testService(t, &coreStub{}, &readerStub{}, resolverStub{})
	handler, err := newHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		calls++
		return identity.AuthenticatedSession{SessionID: actor.SessionID(), Principal: identity.Principal{
			UserID: actor.UserID, ScopeID: actor.ScopeID, ScopeKind: actor.ScopeKind,
		}}, nil
	}, HandlerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]string{
		"missing": nil, "duplicate": {"Bearer one", "Bearer two"}, "api_key": {"ApiKey opaque"},
		"lowercase": {"bearer opaque"}, "empty": {"Bearer "}, "whitespace": {"Bearer one two"},
	}
	for name, authorization := range values {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, apiPrefix+"/cases/"+uuid.NewString(), nil)
			for _, value := range authorization {
				request.Header.Add("Authorization", value)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertAPIError(t, recorder, http.StatusUnauthorized, "identity_verification_unauthenticated")
		})
	}
	if calls != 0 {
		t.Fatalf("invalid Authorization reached authenticator %d times", calls)
	}
}

func TestGenericHandlerConstructorFailsClosed(t *testing.T) {
	service := testService(t, &coreStub{}, &readerStub{}, resolverStub{})
	handler, err := NewHandler(service, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, nil
	}, HandlerConfig{})
	if handler != nil || !errors.Is(err, ErrInvalidService) {
		t.Fatalf("NewHandler() = (%T,%v), want nil ErrInvalidService", handler, err)
	}
}

func TestHandlerRoutesMatchIdentityVerificationFragment(t *testing.T) {
	caseID := uuid.New()
	tests := []struct {
		path    string
		method  string
		kind    routeKind
		command bool
	}{
		{apiPrefix + "/cases", http.MethodPost, routeCreate, true},
		{apiPrefix + "/cases/" + caseID.String(), http.MethodGet, routeGetSelf, false},
		{apiPrefix + "/cases/" + caseID.String() + "/submit", http.MethodPost, routeSubmit, true},
		{apiPrefix + "/cases/" + caseID.String() + "/withdraw", http.MethodPost, routeWithdraw, true},
		{apiPrefix + "/cases/" + caseID.String() + "/expire", http.MethodPost, routeExpireSelf, true},
		{apiPrefix + "/reviewer/cases", http.MethodGet, routeListReviewer, false},
		{apiPrefix + "/reviewer/cases/" + caseID.String(), http.MethodGet, routeGetReviewer, false},
		{apiPrefix + "/reviewer/cases/" + caseID.String() + "/claim", http.MethodPost, routeClaim, true},
		{apiPrefix + "/reviewer/cases/" + caseID.String() + "/decision", http.MethodPost, routeDecision, true},
	}
	for _, test := range tests {
		route, ok := resolveRoute(test.path)
		if !ok || route.kind != test.kind || route.method != test.method || route.command != test.command ||
			(strings.Contains(test.path, "/"+caseID.String()) && route.caseID != caseID) {
			t.Fatalf("route %s = %#v, matched=%t", test.path, route, ok)
		}
	}
	if _, ok := resolveRoute(apiPrefix + "/reviewer/cases/" + caseID.String() + "/expire"); ok {
		t.Fatal("reviewer expire route must not exist")
	}
	if route, ok := resolveRoute(apiPrefix + "/status"); !ok || route.kind != routeSelfStatus ||
		route.method != http.MethodGet || route.command {
		t.Fatalf("status route = %#v matched=%t", route, ok)
	}
	if _, ok := resolveRoute(apiPrefix + "/status/"); ok {
		t.Fatal("status route must not accept a trailing slash")
	}
}

func TestHandlerSelfStatusDerivesBadgeWithoutSensitiveFacts(t *testing.T) {
	actor := testActor()
	verifiedAt := time.Date(2034, 7, 20, 8, 0, 0, 0, time.UTC)
	withReason := func(status, reason string) *identityverification.Case {
		item := testCase(actor, identityverification.KindPersonalInitial, status, 3)
		item.DecisionReasonCode = reason
		item.SubjectFingerprintHint = "fingerprint-hint-secret"
		item.OrganizationName = "organization-secret"
		return &item
	}
	tests := []struct {
		name    string
		current identityverification.SelfStatus
		status  string
	}{
		{"no case", identityverification.SelfStatus{}, SelfStatusUnverified},
		{"draft", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusDraft, "")}, SelfStatusUnverified},
		{"withdrawn", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusWithdrawn, "")}, SelfStatusUnverified},
		{"expired", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusExpired, "")}, SelfStatusUnverified},
		{"submitted", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusSubmitted, "")}, SelfStatusPending},
		{"reviewing", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusReviewing, "")}, SelfStatusPending},
		{"rejected", identityverification.SelfStatus{LatestCase: withReason(identityverification.StatusRejected,
			identityverification.ReasonEvidenceUnreadable)}, SelfStatusRejected},
		{"approved", identityverification.SelfStatus{PersonVerified: true, VerifiedAt: &verifiedAt,
			LatestCase: withReason(identityverification.StatusApproved, identityverification.ReasonEvidenceVerified)}, SelfStatusVerified},
		{"verified then rejected reverification", identityverification.SelfStatus{PersonVerified: true, VerifiedAt: &verifiedAt,
			LatestCase: withReason(identityverification.StatusRejected, identityverification.ReasonIdentityMismatch)}, SelfStatusVerified},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			core := &coreStub{status: func(_ context.Context, got identityverification.Actor) (identityverification.SelfStatus, error) {
				if got.UserID != actor.UserID || got.ScopeID != actor.ScopeID {
					t.Fatalf("status actor = %#v", got)
				}
				return test.current, nil
			}}
			handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
			request := httptest.NewRequest(http.MethodGet, apiPrefix+"/status", nil)
			setTestAuthorization(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status response = %d %s", recorder.Code, recorder.Body.String())
			}
			var view map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &view); err != nil {
				t.Fatal(err)
			}
			if view["status"] != test.status {
				t.Fatalf("status = %v, want %s (%s)", view["status"], test.status, recorder.Body.String())
			}
			body := recorder.Body.String()
			for _, forbidden := range []string{"secret", "fingerprint", "materials", "organization", "reviewer", "applicant", "tenant"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("status response leaked %q: %s", forbidden, body)
				}
			}
			if test.current.LatestCase == nil {
				if _, ok := view["latest_case"]; ok {
					t.Fatalf("latest_case present without a case: %s", body)
				}
				return
			}
			latest, _ := view["latest_case"].(map[string]any)
			if latest["id"] != test.current.LatestCase.ID.String() || latest["status"] != test.current.LatestCase.Status {
				t.Fatalf("latest_case = %#v", latest)
			}
		})
	}
}

func TestHandlerSelfStatusRejectsForeignOrInconsistentFactsAndStrictRequests(t *testing.T) {
	actor := testActor()
	foreign := testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusSubmitted, 1)
	foreign.ApplicantUserID = uuid.New()
	otherScope := testCase(actor, identityverification.KindPersonalInitial, identityverification.StatusSubmitted, 1)
	otherScope.TenantScopeID = uuid.New()
	for name, current := range map[string]identityverification.SelfStatus{
		"foreign applicant":     {LatestCase: &foreign},
		"foreign scope":         {LatestCase: &otherScope},
		"verified without time": {PersonVerified: true},
		"time without verified": {VerifiedAt: &foreign.CreatedAt},
	} {
		t.Run(name, func(t *testing.T) {
			core := &coreStub{status: func(context.Context, identityverification.Actor) (identityverification.SelfStatus, error) {
				return current, nil
			}}
			handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
			request := httptest.NewRequest(http.MethodGet, apiPrefix+"/status", nil)
			setTestAuthorization(request)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertAPIError(t, recorder, http.StatusServiceUnavailable, "identity_verification_unavailable")
		})
	}

	calls := 0
	core := &coreStub{status: func(context.Context, identityverification.Actor) (identityverification.SelfStatus, error) {
		calls++
		return identityverification.SelfStatus{}, identityverification.ErrPermissionDenied
	}}
	handler := testHandler(t, testService(t, core, &readerStub{}, resolverStub{}), actor)
	denied := httptest.NewRequest(http.MethodGet, apiPrefix+"/status", nil)
	setTestAuthorization(denied)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, denied)
	assertAPIError(t, recorder, http.StatusForbidden, "identity_verification_permission_denied")

	for name, request := range map[string]*http.Request{
		"query":  httptest.NewRequest(http.MethodGet, apiPrefix+"/status?user_id="+uuid.NewString(), nil),
		"body":   httptest.NewRequest(http.MethodGet, apiPrefix+"/status", strings.NewReader("x")),
		"method": httptest.NewRequest(http.MethodPost, apiPrefix+"/status", nil),
	} {
		setTestAuthorization(request)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		want := http.StatusBadRequest
		if name == "method" {
			want = http.StatusMethodNotAllowed
		}
		if recorder.Code != want {
			t.Fatalf("%s status = %d %s", name, recorder.Code, recorder.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("strict request rejections reached core: calls=%d", calls)
	}
}

func setWriteHeaders(request *http.Request, key string, revision int64) {
	setTestAuthorization(request)
	request.Header.Set("X-Request-ID", "request-"+key)
	request.Header.Set("Idempotency-Key", key)
	if revision > 0 {
		request.Header.Set("If-Match", `"`+strconv.FormatInt(revision, 10)+`"`)
	}
}

func assertAPIError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, status, recorder.Body.String())
	}
	var envelope errorEnvelope
	if err := json.NewDecoder(bytes.NewReader(recorder.Body.Bytes())).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%#v", envelope.Error)
	}
}
