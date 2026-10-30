package l4lineswitchhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitch"
	"github.com/google/uuid"
)

type fakeService struct {
	item                             l4lineswitch.Switch
	startRequest                     l4lineswitch.StartRequest
	starts, gets, latest, reconciles int
}

func (service *fakeService) Start(_ context.Context, request l4lineswitch.StartRequest) (l4lineswitch.Switch, error) {
	service.starts++
	service.startRequest = request
	return service.item, nil
}

func (service *fakeService) Get(context.Context, l4lineswitch.Actor, uuid.UUID, uuid.UUID) (l4lineswitch.Switch, error) {
	service.gets++
	return service.item, nil
}

func (service *fakeService) Latest(context.Context, l4lineswitch.Actor, uuid.UUID) (l4lineswitch.Switch, error) {
	service.latest++
	return service.item, nil
}

func (service *fakeService) Reconcile(context.Context, l4lineswitch.Actor, uuid.UUID, uuid.UUID) (l4lineswitch.Switch, error) {
	service.reconciles++
	return service.item, nil
}

func TestHandlerCreatesStrictLineSwitch(t *testing.T) {
	handler, service, actor, scopeID := handlerFixture(t)
	requestID, correlationID := uuid.New(), uuid.New()
	body := `{"expected_source_revision":19,"from":{"id":"` + service.item.From.Reference.ID.String() +
		`","revision":3,"sha256":"` + strings.Repeat("31", 32) + `"},"to":{"id":"` + service.item.To.Reference.ID.String() +
		`","revision":7,"sha256":"` + strings.Repeat("72", 32) + `"},"health":{"activation_timeout_ms":60000,` +
		`"observation_window_ms":30000,"required_consecutive_successes":3},"drain":{"health_timeout_ms":30000,` +
		`"max_drain_ms":600000},"max_attempts":3,"deadline":"2026-08-07T04:00:00Z"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", requestID.String())
	request.Header.Set("X-Correlation-ID", correlationID.String())
	request.Header.Set("Idempotency-Key", "switch-1")
	request.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"2"` || service.starts != 1 {
		t.Fatalf("status=%d ETag=%q starts=%d body=%s", response.Code, response.Header().Get("ETag"), service.starts, response.Body.String())
	}
	if service.startRequest.Actor != actor || service.startRequest.ConfigurationScopeID != scopeID ||
		service.startRequest.From != service.item.From.Reference || service.startRequest.To != service.item.To.Reference ||
		service.startRequest.RequestID != requestID || service.startRequest.CorrelationID != correlationID {
		t.Fatalf("start request = %+v", service.startRequest)
	}
	var view switchView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil || view.State != l4lineswitch.StateHealthGate ||
		view.PrepareNodeCount != 3 || view.RetiringNodeCount != 1 {
		t.Fatalf("response = %+v, error=%v", view, err)
	}
}

func TestHandlerRejectsTenantCrossScopeBeforeService(t *testing.T) {
	handler, service, _, _ := handlerFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+uuid.NewString()+"/l4-line-switches/"+service.item.ID.String(), nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || service.gets != 0 {
		t.Fatalf("status=%d gets=%d body=%s", response.Code, service.gets, response.Body.String())
	}
}

func TestHandlerRejectsDuplicateOrUnknownWriteMetadata(t *testing.T) {
	handler, service, _, scopeID := handlerFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches", strings.NewReader(`{"unknown":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("X-Request-ID", uuid.NewString())
	request.Header.Add("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.starts != 0 {
		t.Fatalf("status=%d starts=%d body=%s", response.Code, service.starts, response.Body.String())
	}
}

func TestHandlerReconcileRequiresEmptyBodyAndReturnsLatestState(t *testing.T) {
	handler, service, _, scopeID := handlerFixture(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches/"+service.item.ID.String()+"/reconcile", nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.reconciles != 1 || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("status=%d reconciles=%d ETag=%q body=%s", response.Code, service.reconciles, response.Header().Get("ETag"), response.Body.String())
	}
}

func TestHandlerReadsLatestDurableLineSwitch(t *testing.T) {
	handler, service, _, scopeID := handlerFixture(t)
	request := httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches/current", nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.latest != 1 || service.gets != 0 || response.Header().Get("ETag") != `"2"` {
		t.Fatalf("status=%d latest=%d gets=%d ETag=%q body=%s", response.Code, service.latest, service.gets,
			response.Header().Get("ETag"), response.Body.String())
	}
}

func handlerFixture(t *testing.T) (*Handler, *fakeService, l4lineswitch.Actor, uuid.UUID) {
	t.Helper()
	scopeID := uuid.New()
	actor := l4lineswitch.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant", SessionID: uuid.New(), Credential: "token"}
	from, to := snapshotRef(uuid.New(), 3, 0x31), snapshotRef(uuid.New(), 7, 0x72)
	service := &fakeService{item: l4lineswitch.Switch{
		ID: uuid.New(), ConfigurationScopeID: scopeID, ExpectedSourceRevision: 19,
		From: l4lineswitch.Snapshot{Reference: from}, To: l4lineswitch.Snapshot{Reference: to},
		PrepareNodes: []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}, RetiringNodes: []uuid.UUID{uuid.New()},
		State: l4lineswitch.StateHealthGate, StateRevision: 2, Deadline: time.Date(2026, 8, 7, 4, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, 8, 7, 3, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 7, 3, 1, 0, 0, time.UTC),
	}}
	handler, err := NewHandler(service, AuthenticatorFunc(func(*http.Request) (l4lineswitch.Actor, error) { return actor, nil }))
	if err != nil {
		t.Fatal(err)
	}
	return handler, service, actor, scopeID
}

func snapshotRef(id uuid.UUID, revision int64, fill byte) l4lineswitch.SnapshotReference {
	var digest [32]byte
	for index := range digest {
		digest[index] = fill
	}
	return l4lineswitch.SnapshotReference{ID: id, Revision: revision, SHA256: digest}
}

// FX27: a reconcile that waits for DNS reports why the old listeners stay open.
func TestHandlerReconcileReportsDNSGate(t *testing.T) {
	handler, service, _, scopeID := handlerFixture(t)
	readyAt := time.Date(2026, 8, 7, 3, 10, 0, 0, time.UTC)
	service.item.DNSGate = &l4lineswitch.DNSGateStatus{State: l4lineswitch.DNSGatePropagationWait, Owners: 2, ReadyAt: &readyAt}
	request := httptest.NewRequest(http.MethodPost, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches/"+service.item.ID.String()+"/reconcile", nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK {
		t.Fatalf("status=%d error=%v body=%s", response.Code, err, response.Body.String())
	}
	if got := string(body["dns_gate"]); got != `{"state":"propagation_wait","owners":2,"pending_owners":0,"ready_at":"2026-08-07T03:10:00Z"}` {
		t.Fatalf("dns_gate = %s", got)
	}

	service.item.DNSGate = nil
	request = httptest.NewRequest(http.MethodGet, "/v1/tenant-scopes/"+scopeID.String()+"/l4-line-switches/current", nil)
	request.Header.Set("X-Request-ID", uuid.NewString())
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "dns_gate") {
		t.Fatalf("a switch without a gate check must omit dns_gate: %s", response.Body.String())
	}
}
