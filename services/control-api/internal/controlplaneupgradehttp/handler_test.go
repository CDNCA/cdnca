package controlplaneupgradehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/controlplaneupgrade"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestHandlerAuthenticatesAndAuthorizesBeforePublishing(t *testing.T) {
	publisher := &publisherStub{receipt: controlplaneupgrade.PublicationReceipt{ReceiptID: "receipt-1", PlanID: uuid.NewString(), PublicationRevision: 1}}
	authenticate := func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	handler, err := New(Dependencies{AuthenticateSession: authenticate, Publisher: publisher,
		InternalToken: []byte("internal-token-32-bytes-long-value"), MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-plan", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || publisher.calls != 0 {
		t.Fatalf("unauthorized response=%d calls=%d", response.Code, publisher.calls)
	}
	handler.authenticate = func(*http.Request) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{
			UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{"control.upgrades.manage"}}}, nil
	}
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request.Clone(request.Context()))
	if response.Code != http.StatusForbidden || publisher.calls != 0 {
		t.Fatalf("forbidden response=%d calls=%d", response.Code, publisher.calls)
	}
}

func TestHandlerPublishesRawBundleAndProtectsInternalContracts(t *testing.T) {
	publisher := &publisherStub{receipt: controlplaneupgrade.PublicationReceipt{ReceiptID: "receipt-1", PlanID: uuid.NewString(), PublicationRevision: 1}}
	coordinator := &coordinatorStub{}
	handler, err := New(Dependencies{AuthenticateSession: platformSession, Publisher: publisher, Coordinator: coordinator,
		InternalToken: []byte("internal-token-32-bytes-long-value"), MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte(`{"signed":"bundle"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/admin/control-upgrade-plan", bytes.NewReader(bundle))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Idempotency-Key", "publish-1")
	request.Header.Set("X-Request-ID", "request-1")
	response := httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || string(publisher.request.Bundle) != string(bundle) || publisher.request.ExpectedRevision != 0 {
		t.Fatalf("publish response=%d request=%#v body=%s", response.Code, publisher.request, response.Body.String())
	}
	internal := httptest.NewRequest(http.MethodGet, "/v1/internal/control-upgrade/version", nil)
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, internal)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated internal response=%d", response.Code)
	}
	internal.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
	response = httptest.NewRecorder()
	handler.Handler().ServeHTTP(response, internal)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated internal response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestInternalStateEndpointsFailClosedWithoutCoordinator(t *testing.T) {
	handler, err := New(Dependencies{AuthenticateSession: platformSession, Publisher: &publisherStub{},
		InternalToken: []byte("internal-token-32-bytes-long-value"), MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		method string
		path   string
		body   string
	}{{http.MethodPost, "/v1/internal/control-upgrade/drain", `{"plan_id":"00000000-0000-4000-8000-000000000002"}`},
		{http.MethodPost, "/v1/internal/control-upgrade/resume", `{"plan_id":"00000000-0000-4000-8000-000000000002"}`},
		{http.MethodGet, "/v1/internal/control-upgrade/health", ""}} {
		request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
		request.Header.Set("Authorization", "Bearer internal-token-32-bytes-long-value")
		if test.body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			!strings.Contains(response.Body.String(), "control_upgrade_state_unavailable") {
			t.Errorf("%s status=%d body=%s", test.path, response.Code, response.Body.String())
		}
	}
}

func TestGateBlocksMutationsWhileDrainingButKeepsReadsAndHealth(t *testing.T) {
	coordinator := &coordinatorStub{snapshot: controlplaneupgrade.ControlSnapshot{Phase: controlplaneupgrade.ControlDraining}}
	handler, err := New(Dependencies{AuthenticateSession: platformSession, Publisher: &publisherStub{}, Coordinator: coordinator,
		InternalToken: []byte("internal-token-32-bytes-long-value"), MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	next := handler.Gate(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusNoContent) }))
	for _, test := range []struct {
		method string
		path   string
		status int
	}{{http.MethodPost, "/v1/sites", http.StatusServiceUnavailable}, {http.MethodGet, "/v1/sites", http.StatusNoContent},
		{http.MethodGet, "/health/ready", http.StatusNoContent}} {
		response := httptest.NewRecorder()
		next.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Errorf("%s %s status=%d want=%d", test.method, test.path, response.Code, test.status)
		}
	}
	if coordinator.observeCalls != 1 {
		t.Fatalf("readiness observations = %d", coordinator.observeCalls)
	}
}

func platformSession(*http.Request) (identity.AuthenticatedSession, error) {
	return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(),
		ScopeKind: "platform", Permissions: []string{"control.upgrades.manage"}}}, nil
}

type publisherStub struct {
	receipt controlplaneupgrade.PublicationReceipt
	request controlplaneupgrade.PublishRequest
	calls   int
}

func (publisher *publisherStub) Publish(_ context.Context, request controlplaneupgrade.PublishRequest) (controlplaneupgrade.PublicationReceipt, error) {
	publisher.calls++
	publisher.request = request
	return publisher.receipt, nil
}

type coordinatorStub struct {
	snapshot     controlplaneupgrade.ControlSnapshot
	observeCalls int
}

func (coordinator *coordinatorStub) BeginDrain(context.Context, string) (controlplaneupgrade.ControlSnapshot, error) {
	return coordinator.snapshot, controlplaneupgrade.ErrQuorumUnavailable
}
func (coordinator *coordinatorStub) Resume(context.Context, string) (controlplaneupgrade.ControlReceipt, error) {
	return controlplaneupgrade.ControlReceipt{}, errors.New("not implemented")
}
func (coordinator *coordinatorStub) Observe(context.Context) (controlplaneupgrade.ControlSnapshot, error) {
	coordinator.observeCalls++
	return coordinator.snapshot, nil
}
func (coordinator *coordinatorStub) Snapshot(context.Context) (controlplaneupgrade.ControlSnapshot, error) {
	return coordinator.snapshot, nil
}
func (coordinator *coordinatorStub) Facts() controlplaneupgrade.ReplicaFacts {
	return controlplaneupgrade.ReplicaFacts{ReplicaID: "control-0", Version: "1.4.0", Digest: digest("52")}
}

func digest(pair string) string {
	result := ""
	for len(result) < 64 {
		result += pair
	}
	return result[:64]
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder, destination any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), destination); err != nil {
		t.Fatal(err)
	}
}
