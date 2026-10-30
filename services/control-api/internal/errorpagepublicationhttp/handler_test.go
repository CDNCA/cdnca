package errorpagepublicationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/errorpagecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const testToken = "site13-session-token"

func TestSITE13PublishAndImmutableReadback(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := fixture.publishRequest(fixture.body)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	var published publicationView
	decodeResponse(t, response, &published)
	assertPublicationView(t, published, fixture.result)
	if response.Header().Get("Location") != fixture.collectionPath+"/"+fixture.result.PublicationID.String() ||
		response.Header().Get("ETag") != `"sha256-`+hex.EncodeToString(fixture.result.ArtifactSHA256[:])+`"` {
		t.Fatalf("publish headers=%v", response.Header())
	}
	if fixture.publisher.calls != 1 || fixture.authenticator.calls != 1 || fixture.scopes.calls != 1 {
		t.Fatalf("publish calls publisher=%d auth=%d scopes=%d", fixture.publisher.calls, fixture.authenticator.calls, fixture.scopes.calls)
	}
	captured := fixture.publisher.request
	if captured.TenantID != fixture.tenantID || captured.ConfigurationScopeID != fixture.scopeID ||
		captured.ExpectedSourceRevision != fixture.result.SourceRevision || captured.Actor.UserID != fixture.userID ||
		captured.Actor.ScopeID != fixture.actorScopeID || captured.Actor.ScopeKind != edgepublish.ScopeKindPlatform ||
		captured.Actor.SessionID != fixture.sessionID ||
		captured.IdempotencyKey != fixture.idempotencyKey || captured.RequestID != fixture.requestID.String() ||
		captured.CorrelationID != fixture.correlationID.String() || captured.Traceparent != fixture.traceparent ||
		captured.TaskID == nil || *captured.TaskID != "task-site13" || captured.MaxAttempts != 3 ||
		!captured.Deadline.Equal(fixture.deadline) || len(captured.NodeIDs) != 1 || captured.NodeIDs[0] != fixture.nodeID ||
		captured.HealthCheck.ActivationTimeout != 30*time.Second || captured.HealthCheck.ObservationWindow != 5*time.Second ||
		captured.HealthCheck.RequiredConsecutiveSuccesses != 2 {
		t.Fatalf("captured publish=%+v", captured)
	}

	read := httptest.NewRequest(http.MethodGet, fixture.collectionPath+"/"+fixture.result.PublicationID.String(), nil)
	read.Header.Set("Authorization", "Bearer "+testToken)
	read.Header.Set("X-Request-ID", uuid.NewString())
	readResponse := httptest.NewRecorder()
	fixture.handler.ServeHTTP(readResponse, read)
	if readResponse.Code != http.StatusOK {
		t.Fatalf("read status=%d body=%s", readResponse.Code, readResponse.Body.String())
	}
	var readback publicationView
	decodeResponse(t, readResponse, &readback)
	assertPublicationView(t, readback, fixture.result)
	if fixture.reader.calls != 1 || fixture.authenticator.calls != 2 || fixture.scopes.calls != 2 {
		t.Fatalf("read calls reader=%d auth=%d scopes=%d", fixture.reader.calls, fixture.authenticator.calls, fixture.scopes.calls)
	}
	if fixture.reader.request.TenantID != fixture.tenantID || fixture.reader.request.TenantScopeID != fixture.scopeID ||
		fixture.reader.request.PublicationID != fixture.result.PublicationID || fixture.reader.request.Session.SessionID != fixture.sessionID ||
		fixture.reader.request.RawToken != testToken {
		t.Fatalf("captured read=%+v", fixture.reader.request)
	}
}

func TestSITE13RejectsUnsafePublishInputsBeforeDomain(t *testing.T) {
	fixture := newHandlerFixture(t)
	tests := map[string]func(*http.Request){
		"query":                   func(request *http.Request) { request.URL.RawQuery = "tenant_scope_id=" + uuid.NewString() },
		"missing authorization":   func(request *http.Request) { request.Header.Del("Authorization") },
		"duplicate authorization": func(request *http.Request) { request.Header.Add("Authorization", "Bearer other") },
		"stale body revision": func(request *http.Request) {
			request.Body = ioBody(strings.Replace(fixture.body, `"target"`, `"expected_source_revision":7,"target"`, 1))
		},
		"weak if match":      func(request *http.Request) { request.Header.Set("If-Match", "7") },
		"duplicate if match": func(request *http.Request) { request.Header.Add("If-Match", `"7"`) },
		"missing idempotency": func(request *http.Request) {
			request.Header.Del("Idempotency-Key")
		},
		"duplicate node": func(request *http.Request) {
			request.Body = ioBody(strings.Replace(fixture.body, `"node_ids":["`+fixture.nodeID.String()+`"]`,
				`"node_ids":["`+fixture.nodeID.String()+`","`+fixture.nodeID.String()+`"]`, 1))
		},
		"non canonical scope": func(request *http.Request) {
			request.URL.Path = strings.Replace(request.URL.Path, fixture.scopeID.String(), strings.ToUpper(fixture.scopeID.String()), 1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			before := fixture.publisher.calls
			request := fixture.publishRequest(fixture.body)
			mutate(request)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest && !strings.Contains(name, "authorization") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(name, "authorization") && response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if fixture.publisher.calls != before {
				t.Fatal("unsafe request reached publisher")
			}
		})
	}
}

func TestSITE13RejectsMismatchedDomainIdentity(t *testing.T) {
	fixture := newHandlerFixture(t)
	tests := map[string]func(*edgepublish.ErrorPagePublishResult){
		"tenant":          func(result *edgepublish.ErrorPagePublishResult) { result.Binding.TenantID = uuid.NewString() },
		"scope":           func(result *edgepublish.ErrorPagePublishResult) { result.ConfigurationScopeID = uuid.New() },
		"publication":     func(result *edgepublish.ErrorPagePublishResult) { result.PublicationID = uuid.Nil },
		"source revision": func(result *edgepublish.ErrorPagePublishResult) { result.SourceRevision++ },
		"artifact digest": func(result *edgepublish.ErrorPagePublishResult) { result.ArtifactSHA256 = [32]byte{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := fixture.result
			mutate(&result)
			fixture.publisher.result = result
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
			assertErrorCode(t, response, http.StatusBadGateway, "error_page_publication_invalid_response")
		})
	}
}

func TestSITE13TenantSessionCannotIssuePlatformPublication(t *testing.T) {
	fixture := newHandlerFixture(t)
	tenantID := fixture.tenantID
	fixture.authenticator.session.Principal = identity.Principal{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: edgepublish.ScopeKindTenant, TenantID: &tenantID,
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
	assertErrorCode(t, response, http.StatusForbidden, "error_page_publication_permission_denied")
	if fixture.publisher.calls != 0 || fixture.scopes.calls != 0 {
		t.Fatalf("tenant publish reached scope/publisher: scopes=%d publisher=%d", fixture.scopes.calls, fixture.publisher.calls)
	}
}

func TestSITE13UnknownPublishOutcomeCarriesExactRetryBinding(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.publisher.err = edgepublish.ErrPersistence
	request := fixture.publishRequest(fixture.body)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, request)
	assertErrorCode(t, response, http.StatusServiceUnavailable, "error_page_publication_outcome_unknown")
	if response.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", response.Header().Get("Retry-After"))
	}
	var envelope errorEnvelope
	decodeResponse(t, response, &envelope)
	digest := sha256.Sum256([]byte(fixture.body))
	if envelope.Error.Retry == nil || envelope.Error.Retry.Method != http.MethodPost ||
		envelope.Error.Retry.Path != fixture.collectionPath || envelope.Error.Retry.IfMatch != `"7"` ||
		envelope.Error.Retry.IdempotencyKey != fixture.idempotencyKey || envelope.Error.Retry.BodySHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("retry=%+v", envelope.Error.Retry)
	}
}

func TestSITE13ReadbackScopeIsolation(t *testing.T) {
	fixture := newHandlerFixture(t)
	path := fixture.collectionPath + "/" + fixture.result.PublicationID.String()
	tests := []struct {
		name   string
		scope  error
		reader error
		status int
		code   string
	}{
		{name: "cross scope", scope: edgepublish.ErrPermissionDenied, status: 403, code: "error_page_publication_permission_denied"},
		{name: "not found", reader: edgepublish.ErrNotFound, status: 404, code: "error_page_publication_not_found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture.scopes.err, fixture.reader.err = test.scope, test.reader
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+testToken)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, request)
			assertErrorCode(t, response, test.status, test.code)
		})
	}
}

func TestSITE13OpenAPIFragmentContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-error-page-publications.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"/v1/tenant-scopes/{tenant_scope_id}/error-page-publications:",
		"/v1/tenant-scopes/{tenant_scope_id}/error-page-publications/{publication_id}:",
		"operationId: publishErrorPageConfiguration", "operationId: getErrorPagePublication",
		"name: If-Match", "name: Idempotency-Key", "edge_publications.manage", "edge_publications.read",
		"error_page_publication_outcome_unknown", "unchanged body, If-Match, path, and Idempotency-Key",
		"tenant_scope_id", "publication_id", "source_revision", "rollout_id", "error_page_publication_revision",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("OpenAPI missing %q", required)
		}
	}
	if strings.Contains(strings.ToLower(text), "private_key") || strings.Contains(strings.ToLower(text), "raw_token") {
		t.Fatal("OpenAPI exposes secret material")
	}
}

type handlerFixture struct {
	handler                                                    *Handler
	publisher                                                  *publisherStub
	reader                                                     *readerStub
	authenticator                                              *authenticatorStub
	scopes                                                     *scopeResolverStub
	tenantID, scopeID, actorScopeID, userID, sessionID, nodeID uuid.UUID
	requestID, correlationID                                   uuid.UUID
	result                                                     edgepublish.ErrorPagePublishResult
	deadline                                                   time.Time
	collectionPath, idempotencyKey, traceparent                string
	body                                                       string
}

func newHandlerFixture(t *testing.T) handlerFixture {
	t.Helper()
	tenantID, scopeID, actorScopeID, userID, sessionID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requestID, correlationID := uuid.New(), uuid.New()
	deadline := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	digest := sha256.Sum256([]byte("site13-artifact"))
	result := edgepublish.ErrorPagePublishResult{
		PublishResult: edgepublish.PublishResult{
			PublicationID: uuid.New(), ConfigurationScopeID: scopeID, SourceRevision: 7,
			ConfigVersionID: uuid.New(), RolloutID: uuid.New(), CanonicalSnapshotSHA256: digest,
			ArtifactSHA256: digest, TargetKind: edgepublish.TargetKindExplicit,
			TargetSnapshotSHA256: sha256.Sum256([]byte("site13-target")), NodeCount: 1,
			CreatedAt: time.Date(2026, 8, 8, 12, 0, 0, 123000000, time.UTC),
		},
		Binding: errorpagecontrol.ProductionSnapshotBinding{
			TenantID: tenantID.String(), ConfigurationScopeID: scopeID.String(), PublicationRevision: 13,
		},
	}
	publisher := &publisherStub{result: result}
	reader := &readerStub{result: result}
	authenticator := &authenticatorStub{session: identity.AuthenticatedSession{SessionID: sessionID, Principal: identity.Principal{
		UserID: userID, ScopeID: actorScopeID, ScopeKind: edgepublish.ScopeKindPlatform,
	}}}
	scopes := &scopeResolverStub{tenantID: tenantID}
	handler, err := newHandler(publisher, reader, authenticator, scopes)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/tenant-scopes/" + scopeID.String() + "/error-page-publications"
	body := `{"target":{"kind":"nodes","node_ids":["` + nodeID.String() + `"]},` +
		`"health_check":{"activation_timeout_ms":30000,"observation_window_ms":5000,"required_consecutive_successes":2},` +
		`"max_attempts":3,"deadline":"` + deadline.Format(time.RFC3339Nano) + `"}`
	return handlerFixture{handler: handler, publisher: publisher, reader: reader, authenticator: authenticator, scopes: scopes,
		tenantID: tenantID, scopeID: scopeID, actorScopeID: actorScopeID, userID: userID, sessionID: sessionID, nodeID: nodeID,
		requestID: requestID, correlationID: correlationID, result: result, deadline: deadline,
		collectionPath: path, idempotencyKey: "site13-publish-1", traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", body: body}
}

func (fixture handlerFixture) publishRequest(body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, fixture.collectionPath, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", fixture.idempotencyKey)
	request.Header.Set("X-Request-ID", fixture.requestID.String())
	request.Header.Set("X-Correlation-ID", fixture.correlationID.String())
	request.Header.Set("Traceparent", fixture.traceparent)
	request.Header.Set("X-Task-ID", "task-site13")
	return request
}

type publisherStub struct {
	result  edgepublish.ErrorPagePublishResult
	err     error
	request edgepublish.ErrorPagePublishRequest
	calls   int
}

func (stub *publisherStub) Publish(_ context.Context, request edgepublish.ErrorPagePublishRequest) (edgepublish.ErrorPagePublishResult, error) {
	stub.calls++
	stub.request = request
	return stub.result, stub.err
}

type readerStub struct {
	result  edgepublish.ErrorPagePublishResult
	err     error
	request publicationReadRequest
	calls   int
}

func (stub *readerStub) Get(_ context.Context, request publicationReadRequest) (edgepublish.ErrorPagePublishResult, error) {
	stub.calls++
	stub.request = request
	return stub.result, stub.err
}

type authenticatorStub struct {
	session identity.AuthenticatedSession
	err     error
	calls   int
}

func (stub *authenticatorStub) Authenticate(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
	stub.calls++
	if raw != testToken {
		return identity.AuthenticatedSession{}, edgepublish.ErrUnauthenticated
	}
	return stub.session, stub.err
}

type scopeResolverStub struct {
	tenantID uuid.UUID
	err      error
	calls    int
}

func (stub *scopeResolverStub) Resolve(_ context.Context, _ identity.Principal, _ uuid.UUID) (uuid.UUID, error) {
	stub.calls++
	return stub.tenantID, stub.err
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, output any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(response.Body.Bytes()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		t.Fatal(err)
	}
}

func assertPublicationView(t *testing.T, view publicationView, result edgepublish.ErrorPagePublishResult) {
	t.Helper()
	if view.TenantID.String() != result.Binding.TenantID || view.TenantScopeID != result.ConfigurationScopeID ||
		view.PublicationID != result.PublicationID || view.SourceRevision != result.SourceRevision ||
		view.ErrorPagePublicationRevision != result.Binding.PublicationRevision || view.ConfigVersionID != result.ConfigVersionID ||
		view.RolloutID != result.RolloutID || view.ArtifactSHA256 != hex.EncodeToString(result.ArtifactSHA256[:]) ||
		view.NodeCount != result.NodeCount || view.CreatedAt != result.CreatedAt.Format(time.RFC3339Nano) {
		t.Fatalf("view=%+v result=%+v", view, result)
	}
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body.String())
	}
	var envelope errorEnvelope
	decodeResponse(t, response, &envelope)
	if envelope.Error.Code != code || envelope.Error.RequestID == "" {
		t.Fatalf("error=%+v", envelope.Error)
	}
}

func ioBody(value string) *readCloser { return &readCloser{Reader: strings.NewReader(value)} }

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

var _ publicationPublisher = (*publisherStub)(nil)
var _ publicationReader = (*readerStub)(nil)
var _ sessionAuthenticator = (*authenticatorStub)(nil)
var _ tenantScopeResolver = (*scopeResolverStub)(nil)
