package sitecapturehttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/sitecapture"
	"github.com/google/uuid"
)

type serviceStub struct {
	update sitecapture.UpdateRequest
	policy sitecapture.Policy
	err    error
}

func (stub *serviceStub) Get(context.Context, sitecapture.Actor, uuid.UUID, uuid.UUID) (sitecapture.Policy, error) {
	return stub.policy, stub.err
}

func (stub *serviceStub) Update(_ context.Context, _ sitecapture.Actor, request sitecapture.UpdateRequest) (sitecapture.WriteResult, error) {
	stub.update = request
	return sitecapture.WriteResult{Policy: stub.policy, Replayed: true}, stub.err
}

func TestHandlerBindsTenantSiteCASAndStableMetadata(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	stub := &serviceStub{policy: sitecapture.Policy{ScopeID: scopeID, SiteID: siteID, Revision: 4}}
	handler, err := NewHandler(stub, AuthenticatorFunc(func(*http.Request) (sitecapture.Actor, error) {
		return sitecapture.Actor{UserID: uuid.New(), ScopeID: scopeID, SessionID: uuid.New()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"expected_revision":3,"document":{"enabled":true,"methods":["POST"],"uri_prefixes":["/api"],"request_header_allowlist":["Authorization"],"response_header_allowlist":[],"request_body_field_allowlist":[],"response_body_field_allowlist":[],"max_value_bytes":4096,"max_body_bytes":65536,"max_event_bytes":1048576}}`
	request := httptest.NewRequest(http.MethodPut, "/v1/tenant-scopes/"+scopeID.String()+"/sites/"+siteID.String()+"/telemetry-capture-policy", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "capture-3")
	request.Header.Set("X-Request-ID", "request-3")
	request.Header.Set("X-Trace-ID", "trace-3")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || response.Header().Get("X-Idempotent-Replay") != "true" {
		t.Fatalf("response=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if stub.update.ScopeID != scopeID || stub.update.SiteID != siteID || stub.update.ExpectedRevision != 3 ||
		stub.update.IdempotencyKey != "capture-3" || stub.update.RequestID != "request-3" || stub.update.TraceID != "trace-3" {
		t.Fatalf("update=%+v", stub.update)
	}
}

func TestHandlerDoesNotLeakDomainErrors(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	stub := &serviceStub{err: errors.New("database password=raw-secret")}
	handler, _ := NewHandler(stub, AuthenticatorFunc(func(*http.Request) (sitecapture.Actor, error) {
		return sitecapture.Actor{UserID: uuid.New(), ScopeID: scopeID, SessionID: uuid.New()}, nil
	}))
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+scopeID.String()+"/sites/"+siteID.String()+"/telemetry-capture-policy", nil)
	request.Header.Set("X-Request-ID", "request-4")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var payload map[string]map[string]string
	if response.Code != http.StatusServiceUnavailable || json.Unmarshal(response.Body.Bytes(), &payload) != nil ||
		payload["error"]["code"] != "site_capture_unavailable" || strings.Contains(response.Body.String(), "raw-secret") {
		t.Fatalf("response=%d %s", response.Code, response.Body.String())
	}
}

// A16: a readable site that never saved a capture policy answers 200
// unconfigured (revision 0 + default document) instead of 404; a missing or
// foreign site keeps answering 404 site_capture_not_found.
func TestHandlerAnswersUnconfiguredForSiteWithoutPolicy(t *testing.T) {
	scopeID, siteID := uuid.New(), uuid.New()
	get := func(err error) *httptest.ResponseRecorder {
		handler, _ := NewHandler(&serviceStub{err: err}, AuthenticatorFunc(func(*http.Request) (sitecapture.Actor, error) {
			return sitecapture.Actor{UserID: uuid.New(), ScopeID: scopeID, SessionID: uuid.New()}, nil
		}))
		request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+scopeID.String()+"/sites/"+siteID.String()+"/telemetry-capture-policy", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := get(sitecapture.ErrUnconfigured)
	var payload struct {
		ScopeID  string                     `json:"scope_id"`
		SiteID   string                     `json:"site_id"`
		State    string                     `json:"state"`
		Revision int64                      `json:"revision"`
		Document sitecapture.PolicyDocument `json:"document"`
	}
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"0"` || json.Unmarshal(response.Body.Bytes(), &payload) != nil ||
		payload.State != "unconfigured" || payload.Revision != 0 || payload.ScopeID != scopeID.String() || payload.SiteID != siteID.String() ||
		payload.Document.Enabled || payload.Document.MaxValueBytes != 4096 || payload.Document.Methods == nil {
		t.Fatalf("unconfigured response=%d etag=%q body=%s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	if response := get(sitecapture.ErrNotFound); response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "site_capture_not_found") {
		t.Fatalf("missing site response=%d %s", response.Code, response.Body.String())
	}
}
