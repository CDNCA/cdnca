package nodeisolationhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodeisolation"
	"github.com/google/uuid"
)

type fakeService struct {
	states      []nodeisolation.State
	result      nodeisolation.Result
	err         error
	reported    nodeisolation.SyncResult
	listed      []uuid.UUID
	listCalls   int
	reportCalls int
}

func (service *fakeService) RecordSyncResult(_ context.Context, value nodeisolation.SyncResult) (nodeisolation.Result, error) {
	service.reportCalls++
	service.reported = value
	return service.result, service.err
}

func (service *fakeService) ListIsolationStates(_ context.Context, _ uuid.UUID, nodeIDs []uuid.UUID) ([]nodeisolation.State, error) {
	service.listCalls++
	service.listed = nodeIDs
	return service.states, service.err
}

type sessionAuthFunc func(*http.Request) (Principal, error)

func (function sessionAuthFunc) Authenticate(request *http.Request) (Principal, error) {
	return function(request)
}

type workloadAuthFunc func(*http.Request) (WorkloadPrincipal, error)

func (function workloadAuthFunc) Authenticate(request *http.Request) (WorkloadPrincipal, error) {
	return function(request)
}

func TestAdminListRequiresPlatformReadAndReturnsStrictIdentity(t *testing.T) {
	scopeID, nodeID, reportID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	identity := identity(1)
	service := &fakeService{states: []nodeisolation.State{{ScopeID: scopeID, NodeID: nodeID,
		Status: nodeisolation.StatusIsolated, Desired: identity, LastReportID: reportID,
		LastOutcome: nodeisolation.OutcomeUnknown, ReasonCode: nodeisolation.ReasonOutcomeUnknown,
		Revision: 2, UpdatedAt: now}}}
	handler := testHandler(t, service, Principal{SubjectID: uuid.New(), ScopeID: scopeID,
		ScopeKind: ScopeKindPlatform, SessionID: uuid.New(), Permissions: []string{PermissionRead}}, WorkloadPrincipal{})

	request := httptest.NewRequest(http.MethodGet, adminPath+"?node_id="+nodeID.String(), nil)
	request.Header.Set("X-Request-ID", "node-isolation-list-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.listCalls != 1 || len(service.listed) != 1 || service.listed[0] != nodeID {
		t.Fatalf("status=%d calls=%d nodeIDs=%v body=%s", response.Code, service.listCalls, service.listed, response.Body.String())
	}
	var body map[string][]stateDTO
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body["items"]) != 1 ||
		body["items"][0].Desired.ArtifactSHA256 != "0101010101010101010101010101010101010101010101010101010101010101" {
		t.Fatalf("response = %s, error = %v", response.Body.String(), err)
	}
}

func TestAdminListRejectsTenantOrMissingPermissionBeforeService(t *testing.T) {
	for _, principal := range []Principal{
		{SubjectID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", SessionID: uuid.New(), Permissions: []string{PermissionRead}},
		{SubjectID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindPlatform, SessionID: uuid.New()},
	} {
		service := &fakeService{}
		handler := testHandler(t, service, principal, WorkloadPrincipal{})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, adminPath, nil))
		if response.Code != http.StatusForbidden || service.listCalls != 0 {
			t.Fatalf("status=%d calls=%d", response.Code, service.listCalls)
		}
	}
}

func TestInternalReportBindsWorkloadNodeAndDecodesIdentity(t *testing.T) {
	scopeID, nodeID, reportID := uuid.New(), uuid.New(), uuid.New()
	desired := identity(2)
	service := &fakeService{result: nodeisolation.Result{State: nodeisolation.State{ScopeID: scopeID, NodeID: nodeID,
		Status: nodeisolation.StatusIsolated, Desired: desired, LastReportID: reportID,
		LastOutcome: nodeisolation.OutcomeUnknown, ReasonCode: nodeisolation.ReasonOutcomeUnknown,
		Revision: 1, UpdatedAt: time.Now().UTC()}, ReasonCode: nodeisolation.ReasonOutcomeUnknown}}
	workload := WorkloadPrincipal{WorkloadID: "edge-agent", ScopeID: scopeID, NodeID: nodeID, Permissions: []string{PermissionReport}}
	handler := testHandler(t, service, Principal{}, workload)
	body := map[string]any{"report_id": reportID.String(), "desired": map[string]any{
		"schema": 1, "config_version_id": desired.ConfigVersionID.String(),
		"artifact_sha256": "0202020202020202020202020202020202020202020202020202020202020202",
	}, "outcome": "unknown", "error_code": "gateway_receipt_timeout", "health": nil}
	encoded, _ := json.Marshal(body)
	request := httptest.NewRequest(http.MethodPost, resultPathPrefix+nodeID.String(), bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.reportCalls != 1 || service.reported.ScopeID != scopeID ||
		service.reported.NodeID != nodeID || service.reported.Desired != desired {
		t.Fatalf("status=%d calls=%d report=%#v body=%s", response.Code, service.reportCalls, service.reported, response.Body.String())
	}
}

func TestInternalReportRejectsNodeConfusionAndUnknownFields(t *testing.T) {
	scopeID, nodeID := uuid.New(), uuid.New()
	workload := WorkloadPrincipal{WorkloadID: "edge-agent", ScopeID: scopeID, NodeID: uuid.New(), Permissions: []string{PermissionReport}}
	service := &fakeService{}
	handler := testHandler(t, service, Principal{}, workload)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, resultPathPrefix+nodeID.String(), nil))
	if response.Code != http.StatusForbidden || service.reportCalls != 0 {
		t.Fatalf("node confusion status=%d calls=%d", response.Code, service.reportCalls)
	}

	workload.NodeID = nodeID
	handler = testHandler(t, service, Principal{}, workload)
	request := httptest.NewRequest(http.MethodPost, resultPathPrefix+nodeID.String(), bytes.NewBufferString(`{"unexpected":true}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.reportCalls != 0 {
		t.Fatalf("unknown field status=%d calls=%d body=%s", response.Code, service.reportCalls, response.Body.String())
	}
}

func TestUncertainDependencyUsesStable503(t *testing.T) {
	scopeID := uuid.New()
	service := &fakeService{err: nodeisolation.ErrOutcomeUncertain}
	handler := testHandler(t, service, Principal{SubjectID: uuid.New(), ScopeID: scopeID,
		ScopeKind: ScopeKindPlatform, SessionID: uuid.New(), Permissions: []string{PermissionRead}}, WorkloadPrincipal{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, adminPath, nil))
	if response.Code != http.StatusServiceUnavailable || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"node_isolation_unavailable"`)) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestAuthenticationDependencyFailureUsesStable503BeforeService(t *testing.T) {
	service := &fakeService{}
	handler, err := NewNodeIsolationHandler(Dependencies{
		Service: service,
		Sessions: sessionAuthFunc(func(*http.Request) (Principal, error) {
			return Principal{}, ErrAuthenticationUnavailable
		}),
		Workloads: workloadAuthFunc(func(*http.Request) (WorkloadPrincipal, error) {
			return WorkloadPrincipal{}, ErrAuthenticationUnavailable
		}),
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, adminPath, nil),
		httptest.NewRequest(http.MethodPost, resultPathPrefix+uuid.NewString(), nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"code":"node_isolation_unavailable"`)) {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	if service.listCalls != 0 || service.reportCalls != 0 {
		t.Fatalf("service calls list=%d report=%d", service.listCalls, service.reportCalls)
	}
}

func testHandler(t *testing.T, service Service, principal Principal, workload WorkloadPrincipal) *Handler {
	t.Helper()
	handler, err := NewNodeIsolationHandler(Dependencies{Service: service,
		Sessions: sessionAuthFunc(func(*http.Request) (Principal, error) {
			if principal.SubjectID == uuid.Nil {
				return Principal{}, errors.New("no session")
			}
			return principal, nil
		}),
		Workloads: workloadAuthFunc(func(*http.Request) (WorkloadPrincipal, error) {
			if workload.WorkloadID == "" {
				return WorkloadPrincipal{}, errors.New("no workload")
			}
			return workload, nil
		}),
	}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func identity(fill byte) nodeisolation.ConfigIdentity {
	var digest [32]byte
	for index := range digest {
		digest[index] = fill
	}
	return nodeisolation.ConfigIdentity{Schema: 1, ConfigVersionID: uuid.New(), ArtifactSHA256: digest}
}
