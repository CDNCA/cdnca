package originauthpublicationhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const testToken = "site09-session-token"

func TestSITE09PublishAndImmutableReadback(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status=%d body=%s", response.Code, response.Body.String())
	}
	var published publicationView
	decodeResponse(t, response, &published)
	assertPublicationView(t, published, fixture.result)
	if response.Header().Get("Location") != fixture.collectionPath+"/"+fixture.result.PublicationID.String() ||
		response.Header().Get("ETag") != `"sha256-`+hexDigest(fixture.result.ArtifactManifestSHA256)+`"` {
		t.Fatalf("publish headers=%v", response.Header())
	}
	if fixture.publisher.calls != 1 || fixture.authenticator.calls != 1 || fixture.scopes.calls != 1 {
		t.Fatalf("publish calls publisher=%d auth=%d scopes=%d", fixture.publisher.calls, fixture.authenticator.calls, fixture.scopes.calls)
	}
	captured := fixture.publisher.request
	if captured.TenantID != fixture.tenantID || captured.ConfigurationScopeID != fixture.scopeID ||
		captured.ExpectedSourceRevision != 7 || captured.Actor.UserID != fixture.userID ||
		captured.Actor.ScopeID != fixture.actorScopeID || captured.Actor.ScopeKind != edgedeployment.ScopeKindPlatform ||
		captured.Actor.SessionID != fixture.sessionID || captured.IdempotencyKey != fixture.idempotencyKey ||
		captured.RequestID != fixture.requestID.String() || captured.CorrelationID != fixture.correlationID.String() ||
		captured.Traceparent != fixture.traceparent || captured.TaskID == nil || *captured.TaskID != "task-site09" ||
		!captured.Deadline.Equal(fixture.deadline) || len(captured.NodeIDs) != 1 || captured.NodeIDs[0] != fixture.nodeID ||
		captured.HealthCheck.ActivationTimeout != 30*time.Second || captured.HealthCheck.ObservationWindow != 5*time.Second ||
		captured.HealthCheck.RequiredConsecutiveSuccesses != 2 || captured.BodySHA256 != sha256.Sum256([]byte(fixture.body)) {
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

func TestSITE09RejectsUnsafePublishInputsBeforeDomain(t *testing.T) {
	fixture := newHandlerFixture(t)
	tests := map[string]func(*http.Request){
		"query":                   func(request *http.Request) { request.URL.RawQuery = "scope=" + uuid.NewString() },
		"missing authorization":   func(request *http.Request) { request.Header.Del("Authorization") },
		"duplicate authorization": func(request *http.Request) { request.Header.Add("Authorization", "Bearer other") },
		"body revision": func(request *http.Request) {
			request.Body = ioBody(strings.Replace(fixture.body, `"node_ids"`, `"expected_source_revision":7,"node_ids"`, 1))
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
			want := http.StatusBadRequest
			if strings.Contains(name, "authorization") {
				want = http.StatusUnauthorized
			}
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
			if fixture.publisher.calls != before {
				t.Fatal("unsafe request reached publisher")
			}
		})
	}
}

func TestSITE09TenantSessionCannotIssuePlatformPublication(t *testing.T) {
	fixture := newHandlerFixture(t)
	tenantID := fixture.tenantID
	fixture.authenticator.session.Principal = identity.Principal{
		UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: edgedeployment.ScopeKindTenant, TenantID: &tenantID,
	}
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
	assertErrorCode(t, response, http.StatusForbidden, "origin_auth_edge_publication_permission_denied")
	if fixture.publisher.calls != 0 || fixture.scopes.calls != 0 {
		t.Fatalf("tenant publish reached scope/publisher: scopes=%d publisher=%d", fixture.scopes.calls, fixture.publisher.calls)
	}
}

func TestSITE09RejectsMismatchedResultIdentity(t *testing.T) {
	fixture := newHandlerFixture(t)
	tests := map[string]func(*publicationResult){
		"tenant":               func(result *publicationResult) { result.TenantID = uuid.New() },
		"scope":                func(result *publicationResult) { result.TenantScopeID = uuid.New() },
		"publication":          func(result *publicationResult) { result.PublicationID = uuid.Nil },
		"source revision":      func(result *publicationResult) { result.SourceRevision++ },
		"artifact manifest":    func(result *publicationResult) { result.ArtifactManifestSHA256 = [32]byte{} },
		"recipient binding":    func(result *publicationResult) { result.RecipientBindingSHA256 = [32]byte{} },
		"config snapshot hash": func(result *publicationResult) { result.ConfigSnapshotSHA256 = [32]byte{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := fixture.result
			mutate(&result)
			fixture.publisher.result = result
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
			assertErrorCode(t, response, http.StatusBadGateway, "origin_auth_edge_publication_invalid_response")
		})
	}
}

func TestSITE09UnknownOutcomeCarriesExactRetryBinding(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.publisher.err = errOutcomeUnknown
	response := httptest.NewRecorder()
	fixture.handler.ServeHTTP(response, fixture.publishRequest(fixture.body))
	assertErrorCode(t, response, http.StatusServiceUnavailable, "origin_auth_edge_publication_outcome_unknown")
	if response.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", response.Header().Get("Retry-After"))
	}
	var envelope errorEnvelope
	decodeResponse(t, response, &envelope)
	retry := envelope.Error.Retry
	if retry == nil || retry.Method != http.MethodPost || retry.Path != fixture.collectionPath || retry.IfMatch != `"7"` ||
		retry.IdempotencyKey != fixture.idempotencyKey || retry.BodySHA256 != hexDigest(sha256.Sum256([]byte(fixture.body))) ||
		retry.RequestID != fixture.requestID.String() || retry.CorrelationID != fixture.correlationID.String() ||
		retry.Traceparent != fixture.traceparent || retry.TaskID == nil || *retry.TaskID != "task-site09" {
		t.Fatalf("retry=%+v", retry)
	}
}

func TestSITE09ReadbackScopeIsolation(t *testing.T) {
	fixture := newHandlerFixture(t)
	path := fixture.collectionPath + "/" + fixture.result.PublicationID.String()
	tests := []struct {
		name   string
		scope  error
		reader error
		status int
		code   string
	}{
		{name: "cross scope", scope: edgedeployment.ErrPermissionDenied, status: 403, code: "origin_auth_edge_publication_permission_denied"},
		{name: "not found", reader: edgedeployment.ErrNotFound, status: 404, code: "origin_auth_edge_publication_not_found"},
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

func TestSITE09OpenAPIFragmentContract(t *testing.T) {
	source, err := os.ReadFile("../../../../api/control-origin-auth-publications.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := yaml.Unmarshal(source, &document); err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications:",
		"/v1/tenant-scopes/{tenant_scope_id}/origin-auth/edge-publications/{publication_id}:",
		"operationId: publishOriginAuthEdgeConfiguration", "operationId: getOriginAuthEdgePublication",
		"name: If-Match", "name: Idempotency-Key", "edge_publications.manage", "origin_auth.manage",
		"edge_publications.read", "origin_auth.read", "origin_auth_edge_publication_outcome_unknown",
		"unchanged body, path, If-Match, Idempotency-Key, X-Request-ID, X-Correlation-ID, Traceparent, and X-Task-ID",
		"source_publication_id", "source_revision", "config_version_id", "rollout_id",
		"config_snapshot_sha256", "artifact_manifest_sha256", "recipient_binding_sha256", "node_count",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("OpenAPI missing %q", required)
		}
	}
	for _, forbidden := range []string{"private_key", "raw_token", "public_key", "wire_bytes", "credential"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Fatalf("OpenAPI exposes forbidden material %q", forbidden)
		}
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
	result                                                     publicationResult
	deadline                                                   time.Time
	collectionPath, idempotencyKey, traceparent                string
	body                                                       string
}

func newHandlerFixture(t *testing.T) handlerFixture {
	t.Helper()
	tenantID, scopeID, actorScopeID, userID, sessionID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	requestID, correlationID := uuid.New(), uuid.New()
	deadline := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	result := publicationResult{
		TenantID: tenantID, TenantScopeID: scopeID, PublicationID: uuid.New(), SourcePublicationID: uuid.New(),
		SourceRevision: 7, ConfigVersionID: uuid.New(), RolloutID: uuid.New(),
		ConfigSnapshotSHA256:   sha256.Sum256([]byte("site09-config")),
		ArtifactManifestSHA256: sha256.Sum256([]byte("site09-artifacts")),
		RecipientBindingSHA256: sha256.Sum256([]byte("site09-recipients")),
		NodeCount:              1, CreatedAt: time.Date(2026, 8, 8, 12, 0, 0, 123000000, time.UTC),
	}
	result.PublicationID = result.RolloutID
	publisher := &publisherStub{result: result}
	reader := &readerStub{result: result}
	authenticator := &authenticatorStub{session: identity.AuthenticatedSession{SessionID: sessionID, Principal: identity.Principal{
		UserID: userID, ScopeID: actorScopeID, ScopeKind: edgedeployment.ScopeKindPlatform,
	}}}
	scopes := &scopeResolverStub{tenantID: tenantID}
	handler, err := newHandler(publisher, reader, authenticator, scopes)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/tenant-scopes/" + scopeID.String() + "/origin-auth/edge-publications"
	body := `{"node_ids":["` + nodeID.String() + `"],` +
		`"health_check":{"activation_timeout_ms":30000,"observation_window_ms":5000,"required_consecutive_successes":2},` +
		`"deadline":"` + deadline.Format(time.RFC3339Nano) + `"}`
	return handlerFixture{handler: handler, publisher: publisher, reader: reader, authenticator: authenticator, scopes: scopes,
		tenantID: tenantID, scopeID: scopeID, actorScopeID: actorScopeID, userID: userID, sessionID: sessionID, nodeID: nodeID,
		requestID: requestID, correlationID: correlationID, result: result, deadline: deadline,
		collectionPath: path, idempotencyKey: "site09-publish-1", traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", body: body}
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
	request.Header.Set("X-Task-ID", "task-site09")
	return request
}

type publisherStub struct {
	result  publicationResult
	err     error
	request publicationRequest
	calls   int
}

func (stub *publisherStub) Publish(_ context.Context, request publicationRequest) (publicationResult, error) {
	stub.calls++
	stub.request = request
	return stub.result, stub.err
}

type readerStub struct {
	result  publicationResult
	err     error
	request publicationReadRequest
	calls   int
}

func (stub *readerStub) Get(_ context.Context, request publicationReadRequest) (publicationResult, error) {
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
		return identity.AuthenticatedSession{}, edgedeployment.ErrUnauthenticated
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

func assertPublicationView(t *testing.T, view publicationView, result publicationResult) {
	t.Helper()
	if view.TenantID != result.TenantID || view.TenantScopeID != result.TenantScopeID ||
		view.PublicationID != result.PublicationID || view.SourcePublicationID != result.SourcePublicationID ||
		view.SourceRevision != result.SourceRevision || view.ConfigVersionID != result.ConfigVersionID || view.RolloutID != result.RolloutID ||
		view.ConfigSnapshotSHA256 != hexDigest(result.ConfigSnapshotSHA256) ||
		view.ArtifactManifestSHA256 != hexDigest(result.ArtifactManifestSHA256) ||
		view.RecipientBindingSHA256 != hexDigest(result.RecipientBindingSHA256) ||
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
