package dnscredentialrewraphttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHandlerSubmitsBoundBatchAndReturnsOnlySafeProgress(t *testing.T) {
	owner := testOwner()
	domain := &stubDomain{submitJob: Job{
		ID: uuid.MustParse("33333333-3333-3333-3333-333333333333"), State: JobCompleted,
		Requested: 1, Completed: 1, Succeeded: 1, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		Items: []ItemProgress{{
			ProviderID:       uuid.MustParse("44444444-4444-4444-4444-444444444444"),
			ExpectedRevision: 7, Status: ItemCompleted, Revision: 8, CredentialVersion: 3,
		}},
	}}
	handler := newTestHandler(t, owner, domain)
	request := httptest.NewRequest(http.MethodPost, CollectionRoute, strings.NewReader(`{
		"items":[{"provider_id":"44444444-4444-4444-4444-444444444444","expected_revision":7}]
	}`))
	request.Header.Set("Authorization", "Bearer live-platform-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "rotate-2026-08")
	request.Header.Set("X-Request-ID", "request-rewrap-1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if domain.submit.Owner != owner || domain.submit.IdempotencyKey != "rotate-2026-08" ||
		domain.submit.RequestID != "request-rewrap-1" || len(domain.submit.Items) != 1 ||
		domain.submit.Items[0].ExpectedRevision != 7 {
		t.Fatalf("submit=%+v", domain.submit)
	}
	body := response.Body.String()
	if !strings.Contains(body, `"status":"completed"`) || strings.Contains(body, `"state"`) ||
		!strings.Contains(body, `"updated_at"`) {
		t.Fatalf("response contract drift: %s", body)
	}
	for _, forbidden := range []string{"ciphertext", "key_id", "credential_key", "secret", "credentials"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatalf("response leaked forbidden field %q: %s", forbidden, body)
		}
	}
	var envelope jobEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil ||
		envelope.Job.ID != domain.submitJob.ID || envelope.Job.Items[0].Status != ItemCompleted {
		t.Fatalf("response=%+v error=%v", envelope, err)
	}
}

func TestHandlerRequiresExactSessionHeadersAndRejectsImpersonation(t *testing.T) {
	owner := testOwner()
	tests := []struct {
		name   string
		mutate func(*http.Request)
		status int
		code   string
	}{
		{name: "missing bearer", mutate: func(request *http.Request) { request.Header.Del("Authorization") },
			status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{name: "api key", mutate: func(request *http.Request) { request.Header.Set("X-API-Key", "not-allowed") },
			status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{name: "workload", mutate: func(request *http.Request) { request.Header.Set("X-Workload-Identity", "spiffe://worker") },
			status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{name: "asserted actor", mutate: func(request *http.Request) { request.Header.Set("X-Actor-User-ID", uuid.NewString()) },
			status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{name: "missing request id", mutate: func(request *http.Request) { request.Header.Del("X-Request-ID") },
			status: http.StatusBadRequest, code: CodeInvalidRequest},
		{name: "missing idempotency", mutate: func(request *http.Request) { request.Header.Del("Idempotency-Key") },
			status: http.StatusBadRequest, code: CodeInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			domain := &stubDomain{}
			handler := newTestHandler(t, owner, domain)
			request := validSubmitHTTPRequest()
			test.mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || errorCode(t, response) != test.code {
				t.Fatalf("status=%d code=%q body=%s", response.Code, errorCode(t, response), response.Body.String())
			}
			if domain.submitCalls != 0 {
				t.Fatalf("unauthorized request reached domain: %+v", domain.submit)
			}
		})
	}
}

func TestHandlerRejectsInvalidBatchBeforeDomain(t *testing.T) {
	providerID := "44444444-4444-4444-4444-444444444444"
	tests := []string{
		`{"items":[]}`,
		`{"items":[{"provider_id":"not-a-uuid","expected_revision":1}]}`,
		`{"items":[{"provider_id":"` + providerID + `","expected_revision":0}]}`,
		`{"items":[{"provider_id":"` + providerID + `","expected_revision":1},{"provider_id":"` + providerID + `","expected_revision":1}]}`,
		`{"items":[{"provider_id":"` + providerID + `","expected_revision":1}],"unexpected":true}`,
	}
	for index, body := range tests {
		domain := &stubDomain{}
		handler := newTestHandler(t, testOwner(), domain)
		request := validSubmitHTTPRequest()
		request.Body = ioNopCloser{Reader: strings.NewReader(body)}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || errorCode(t, response) != CodeInvalidRequest || domain.submitCalls != 0 {
			t.Fatalf("case=%d status=%d body=%s calls=%d", index, response.Code, response.Body.String(), domain.submitCalls)
		}
	}
}

func TestHandlerGetsJobOnlyThroughCurrentAuthorizedSession(t *testing.T) {
	owner := testOwner()
	jobID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	domain := &stubDomain{getJob: Job{
		ID: jobID, State: JobProcessing, Items: []ItemProgress{}, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}}
	handler := newTestHandler(t, owner, domain)
	request := httptest.NewRequest(http.MethodGet, CollectionRoute+"/"+jobID.String(), nil)
	request.Header.Set("Authorization", "Bearer live-platform-session")
	request.Header.Set("X-Request-ID", "request-get-1")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || domain.get.Owner != owner || domain.get.JobID != jobID {
		t.Fatalf("status=%d get=%+v body=%s", response.Code, domain.get, response.Body.String())
	}

	domain.getErr = ErrJobNotFound
	other := owner
	other.SessionID = uuid.New()
	handler = newTestHandler(t, other, domain)
	request = httptest.NewRequest(http.MethodGet, CollectionRoute+"/"+jobID.String(), nil)
	request.Header.Set("Authorization", "Bearer another-live-platform-session")
	request.Header.Set("X-Request-ID", "request-get-2")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || errorCode(t, response) != CodeJobNotFound {
		t.Fatalf("cross-session status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerMapsAuthenticationPermissionAndDependencyErrors(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{err: ErrUnauthenticated, status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{err: ErrPermissionDenied, status: http.StatusForbidden, code: CodePermissionDenied},
		{err: ErrUnavailable, status: http.StatusServiceUnavailable, code: CodeUnavailable},
	}
	for _, test := range tests {
		handler, err := NewHandler(Dependencies{
			Authorizer: authorizerFunc(func(context.Context, string) (Owner, error) { return Owner{}, test.err }),
			Domain:     &stubDomain{},
		}, Config{})
		if err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, validSubmitHTTPRequest())
		if response.Code != test.status || errorCode(t, response) != test.code {
			t.Fatalf("error=%v status=%d body=%s", test.err, response.Code, response.Body.String())
		}
	}
}

type stubDomain struct {
	submit       SubmitRequest
	submitJob    Job
	submitReplay bool
	submitErr    error
	submitCalls  int
	get          GetRequest
	getJob       Job
	getErr       error
}

func (domain *stubDomain) Submit(_ context.Context, request SubmitRequest) (Job, bool, error) {
	domain.submit, domain.submitCalls = request, domain.submitCalls+1
	return domain.submitJob, domain.submitReplay, domain.submitErr
}

func (domain *stubDomain) Get(_ context.Context, request GetRequest) (Job, error) {
	domain.get = request
	return domain.getJob, domain.getErr
}

type authorizerFunc func(context.Context, string) (Owner, error)

func (function authorizerFunc) Authorize(ctx context.Context, raw string) (Owner, error) {
	return function(ctx, raw)
}

func newTestHandler(t *testing.T, owner Owner, domain Domain) *Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{
		Authorizer: authorizerFunc(func(_ context.Context, raw string) (Owner, error) {
			if raw == "" {
				return Owner{}, ErrUnauthenticated
			}
			return owner, nil
		}),
		Domain: domain,
	}, Config{QueryTimeout: time.Second, CommandTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func testOwner() Owner {
	return Owner{
		UserID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		ScopeID:   uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		SessionID: uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
	}
}

func validSubmitHTTPRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, CollectionRoute, strings.NewReader(`{
		"items":[{"provider_id":"44444444-4444-4444-4444-444444444444","expected_revision":7}]
	}`))
	request.Header.Set("Authorization", "Bearer live-platform-session")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "rotate-2026-08")
	request.Header.Set("X-Request-ID", "request-rewrap-1")
	return request
}

func errorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, response.Body.String())
	}
	return envelope.Error.Code
}

type ioNopCloser struct{ *strings.Reader }

func (ioNopCloser) Close() error { return nil }

var _ = errors.Is
