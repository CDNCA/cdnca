package nodeschedulerhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type staticAuthenticator struct {
	actor nodescheduler.Actor
	calls int
}

func (authenticator *staticAuthenticator) Authenticate(*http.Request) (nodescheduler.Actor, error) {
	authenticator.calls++
	return authenticator.actor, nil
}

type fakeService struct {
	putRequest       nodescheduler.PutGroupRequest
	deleteGroupID    uuid.UUID
	deleteRevision   int64
	deleteKey        string
	deleteRequestID  string
	deleteResult     nodescheduler.DeleteResult
	decisionRequest  nodescheduler.DecisionRequest
	actor            nodescheduler.Actor
	group            nodescheduler.LineGroupRevision
	decision         nodescheduler.Decision
	snapshot         nodescheduler.TargetSnapshot
	snapshotRevision int64
	snapshotErr      error
	statistics       nodescheduler.LineGroupStatistics
}

type countingDecisionService struct {
	*fakeService
	calls int
}

func (service *countingDecisionService) DecideCurrent(
	ctx context.Context,
	actor nodescheduler.Actor,
	groupID uuid.UUID,
	request nodescheduler.DecisionRequest,
) (nodescheduler.Decision, error) {
	service.calls++
	return service.fakeService.DecideCurrent(ctx, actor, groupID, request)
}

func (service *fakeService) List(_ context.Context, actor nodescheduler.Actor) ([]nodescheduler.LineGroupRevision, error) {
	service.actor = actor
	return []nodescheduler.LineGroupRevision{service.group}, nil
}
func (service *fakeService) ListStatistics(_ context.Context, actor nodescheduler.Actor, groups []nodescheduler.LineGroupRevision) (map[uuid.UUID]nodescheduler.LineGroupStatistics, error) {
	service.actor = actor
	result := make(map[uuid.UUID]nodescheduler.LineGroupStatistics, len(groups))
	for _, group := range groups {
		result[group.GroupID] = service.statistics
	}
	return result, nil
}
func (service *fakeService) PutGroup(_ context.Context, actor nodescheduler.Actor, request nodescheduler.PutGroupRequest) (nodescheduler.WriteResult, error) {
	service.actor, service.putRequest = actor, request
	return nodescheduler.WriteResult{Group: service.group}, nil
}
func (service *fakeService) DeleteGroup(_ context.Context, actor nodescheduler.Actor, groupID uuid.UUID, revision int64, key, requestID string) (nodescheduler.DeleteResult, error) {
	service.actor, service.deleteGroupID, service.deleteRevision = actor, groupID, revision
	service.deleteKey, service.deleteRequestID = key, requestID
	return service.deleteResult, nil
}
func (service *fakeService) GetCurrent(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID) (nodescheduler.LineGroupRevision, error) {
	service.actor = actor
	return service.group, nil
}
func (service *fakeService) GetRevision(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID, _ int64) (nodescheduler.LineGroupRevision, error) {
	service.actor = actor
	return service.group, nil
}
func (service *fakeService) DecideCurrent(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID, request nodescheduler.DecisionRequest) (nodescheduler.Decision, error) {
	service.actor, service.decisionRequest = actor, request
	return service.decision, nil
}
func (service *fakeService) CreateTargetSnapshotForNodes(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID, _ int64, _ []uuid.UUID, _, _ string) (nodescheduler.TargetSnapshot, error) {
	service.actor = actor
	return service.snapshot, service.snapshotErr
}
func (service *fakeService) GetTargetSnapshot(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID, revision int64) (nodescheduler.TargetSnapshot, error) {
	service.actor, service.snapshotRevision = actor, revision
	return service.snapshot, service.snapshotErr
}
func (service *fakeService) Rollback(_ context.Context, actor nodescheduler.Actor, _ uuid.UUID, _, _ int64, _, _ string) (nodescheduler.WriteResult, error) {
	service.actor = actor
	return nodescheduler.WriteResult{Group: service.group}, nil
}

func (service *fakeService) ListL2Configs(context.Context, nodescheduler.Actor) ([]nodescheduler.L2Config, error) {
	return []nodescheduler.L2Config{}, nil
}

func (service *fakeService) GetL2Config(context.Context, nodescheduler.Actor, uuid.UUID) (nodescheduler.L2Config, error) {
	return nodescheduler.L2Config{}, nodescheduler.ErrNotFound
}

func (service *fakeService) PutL2Config(context.Context, nodescheduler.Actor, nodescheduler.L2ConfigWriteRequest) (nodescheduler.L2ConfigWriteResult, error) {
	return nodescheduler.L2ConfigWriteResult{}, nil
}

func (service *fakeService) DeleteL2Config(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error) {
	return nodescheduler.L2DeleteResult{}, nil
}

func (service *fakeService) ListL2Conditions(context.Context, nodescheduler.Actor) ([]nodescheduler.L2Condition, error) {
	return []nodescheduler.L2Condition{}, nil
}

func (service *fakeService) PutL2Condition(context.Context, nodescheduler.Actor, nodescheduler.L2ConditionWriteRequest) (nodescheduler.L2ConditionWriteResult, error) {
	return nodescheduler.L2ConditionWriteResult{}, nil
}

func (service *fakeService) DeleteL2Condition(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error) {
	return nodescheduler.L2DeleteResult{}, nil
}

func (service *fakeService) ListL2Nodes(context.Context, nodescheduler.Actor, uuid.UUID) ([]nodescheduler.L2Node, error) {
	return []nodescheduler.L2Node{}, nil
}

func (service *fakeService) ListAvailableL2Nodes(context.Context, nodescheduler.Actor, uuid.UUID) ([]nodescheduler.L2NodeCandidate, error) {
	return []nodescheduler.L2NodeCandidate{}, nil
}

func (service *fakeService) AddL2Nodes(context.Context, nodescheduler.Actor, nodescheduler.L2NodeAddRequest) (nodescheduler.L2NodeAddResult, error) {
	return nodescheduler.L2NodeAddResult{}, nil
}

func (service *fakeService) PutL2Node(context.Context, nodescheduler.Actor, nodescheduler.L2NodeWriteRequest) (nodescheduler.L2NodeWriteResult, error) {
	return nodescheduler.L2NodeWriteResult{}, nil
}

func (service *fakeService) DeleteL2Node(context.Context, nodescheduler.Actor, uuid.UUID, int64, string, string) (nodescheduler.L2DeleteResult, error) {
	return nodescheduler.L2DeleteResult{}, nil
}

func TestHandlerCreateStrictHeadersAndDTO(t *testing.T) {
	scopeID, userID, groupID, endpointID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 7, 28, 0, 0, 0, 0, time.UTC)
	service := &fakeService{group: nodescheduler.LineGroupRevision{
		GroupID: groupID, TenantScopeID: scopeID, Revision: 1, Name: "华东线路",
		Policy: nodescheduler.DefaultHealthPolicy(), CreatedByUserID: userID, CreatedAt: now, SealedAt: now,
		ConfigurationDigest: make([]byte, 32), Endpoints: []nodescheduler.Endpoint{{
			ID: endpointID, NodeID: nodeID, Address: "192.0.2.10", Port: 443, Weight: 10, Enabled: true,
			Health: nodescheduler.HealthState{Status: nodescheduler.HealthUnknown, LastChangedAt: now, RowRevision: 1},
		}},
	}}
	authenticator := &staticAuthenticator{actor: nodescheduler.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "tenant"}}
	handler, err := NewHandler(service, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"华东线路","health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[{"id":"` + endpointID.String() + `","node_id":"` + nodeID.String() + `","address":"192.0.2.10","port":443,"region":"华东","carrier":"电信","priority":0,"weight":10,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Idempotency-Key", "create-east")
	request.Header.Set("X-Request-ID", "request-east")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.putRequest.ExpectedRevision != 0 || service.putRequest.Policy.ProbeInterval != 10*time.Second ||
		service.putRequest.Endpoints[0].NodeID != nodeID || service.actor.TargetScopeID != scopeID {
		t.Fatalf("put request=%#v actor=%#v", service.putRequest, service.actor)
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || decoded["replayed"] != false {
		t.Fatalf("response=%v err=%v", decoded, err)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", strings.NewReader(body[:len(body)-1]+`,"extra":true}`))
	for key, values := range request.Header {
		invalid.Header[key] = append([]string(nil), values...)
	}
	invalidResponse := httptest.NewRecorder()
	handler.ServeHTTP(invalidResponse, invalid)
	assertErrorCode(t, invalidResponse, http.StatusBadRequest, "node_scheduling_invalid_request")
}

func TestHandlerListIncludesCurrentResourceStatistics(t *testing.T) {
	scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC)
	service := &fakeService{
		group: nodescheduler.LineGroupRevision{
			GroupID: groupID, DisplayID: "1", TenantScopeID: scopeID, Revision: 1, Name: "默认线路",
			Policy: nodescheduler.DefaultHealthPolicy(), CreatedByUserID: userID, CreatedAt: now, SealedAt: now,
			ConfigurationDigest: make([]byte, 32), Endpoints: []nodescheduler.Endpoint{},
		},
		statistics: nodescheduler.LineGroupStatistics{NodeCount: 1, SiteCount: 3, ForwardCount: 1},
	}
	handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(),
		`"statistics":{"node_count":1,"site_count":3,"forward_count":1}`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerAcceptsEmptyLineGroupEndpointsForCreateAndUpdate(t *testing.T) {
	scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	body := `{"name":"空线路组","health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[]}`
	tests := []struct {
		name       string
		method     string
		path       string
		ifMatch    string
		wantStatus int
		wantGroup  uuid.UUID
	}{
		{name: "create", method: http.MethodPost, path: "/v1/node-line-groups", ifMatch: `"0"`, wantStatus: http.StatusCreated},
		{name: "update", method: http.MethodPut, path: "/v1/node-line-groups/" + groupID.String(), ifMatch: `"1"`, wantStatus: http.StatusOK, wantGroup: groupID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeService{group: nodescheduler.LineGroupRevision{
				GroupID: groupID, TenantScopeID: scopeID, Revision: 2, Name: "空线路组",
				Policy: nodescheduler.DefaultHealthPolicy(), CreatedByUserID: userID,
				CreatedAt: now, SealedAt: now, ConfigurationDigest: make([]byte, 32),
			}}
			handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
				UserID: userID, ScopeID: scopeID, ScopeKind: "tenant",
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", test.ifMatch)
			request.Header.Set("Idempotency-Key", "empty-line-group-"+test.name)
			request.Header.Set("X-Request-ID", "empty-line-group-"+test.name)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if service.putRequest.GroupID != test.wantGroup || len(service.putRequest.Endpoints) != 0 {
				t.Fatalf("put request=%#v", service.putRequest)
			}
		})
	}
}

func TestHandlerRejectsAmbiguousSingletonBeforeAuthentication(t *testing.T) {
	authenticator := &staticAuthenticator{actor: nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}}
	handler, err := NewHandler(&fakeService{}, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/node-line-groups", nil)
	request.Header.Add("Authorization", "Bearer one")
	request.Header.Add("Authorization", "Bearer two")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
	if authenticator.calls != 0 {
		t.Fatalf("authenticator calls=%d", authenticator.calls)
	}
}

func TestHandlerPlatformOwnScopeCRUDAndTenantTargetWriteDenial(t *testing.T) {
	platformScope, tenantScope, userID := uuid.New(), uuid.New(), uuid.New()
	groupID := uuid.New()
	service := &fakeService{
		group: nodescheduler.LineGroupRevision{
			GroupID: groupID, TenantScopeID: platformScope, Revision: 1, Name: "平台线路",
			Policy: nodescheduler.DefaultHealthPolicy(), CreatedByUserID: userID,
			CreatedAt:           time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
			SealedAt:            time.Date(2026, 9, 15, 0, 0, 0, 0, time.UTC),
			ConfigurationDigest: make([]byte, 32),
		},
		deleteResult: nodescheduler.DeleteResult{
			GroupID: groupID, ScopeID: platformScope, Revision: 1,
			DeletedAt: time.Date(2026, 9, 15, 0, 1, 0, 0, time.UTC),
		},
	}
	authenticator := &staticAuthenticator{actor: nodescheduler.Actor{UserID: userID, ScopeID: platformScope, ScopeKind: "platform"}}
	handler, err := NewHandler(service, authenticator)
	if err != nil {
		t.Fatal(err)
	}

	ownRead := httptest.NewRecorder()
	handler.ServeHTTP(ownRead, httptest.NewRequest(http.MethodGet, "/v1/node-line-groups", nil))
	if ownRead.Code != http.StatusOK || service.actor.TargetScopeID != platformScope {
		t.Fatalf("own read status=%d actor=%#v body=%s", ownRead.Code, service.actor, ownRead.Body.String())
	}

	read := httptest.NewRequest(http.MethodGet, "/v1/node-line-groups?target_scope_id="+tenantScope.String(), nil)
	readResponse := httptest.NewRecorder()
	handler.ServeHTTP(readResponse, read)
	if readResponse.Code != http.StatusOK || service.actor.TargetScopeID != tenantScope {
		t.Fatalf("read status=%d actor=%#v body=%s", readResponse.Code, service.actor, readResponse.Body.String())
	}

	body := `{"name":"平台线路","health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[]}`
	write := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups", bytes.NewBufferString(body))
	write.Header.Set("Content-Type", "application/json")
	write.Header.Set("If-Match", `"0"`)
	write.Header.Set("Idempotency-Key", "platform-write")
	write.Header.Set("X-Request-ID", "platform-write")
	writeResponse := httptest.NewRecorder()
	handler.ServeHTTP(writeResponse, write)
	if writeResponse.Code != http.StatusCreated || service.actor.TargetScopeID != platformScope {
		t.Fatalf("own write status=%d actor=%#v body=%s", writeResponse.Code, service.actor, writeResponse.Body.String())
	}

	deleteRequest := httptest.NewRequest(http.MethodDelete, "/v1/node-line-groups/"+groupID.String(), nil)
	deleteRequest.Header.Set("If-Match", `"1"`)
	deleteRequest.Header.Set("Idempotency-Key", "platform-delete")
	deleteRequest.Header.Set("X-Request-ID", "platform-delete")
	deleteResponse := httptest.NewRecorder()
	handler.ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusNoContent || service.deleteGroupID != groupID ||
		service.deleteRevision != 1 || service.deleteKey != "platform-delete" ||
		service.deleteRequestID != "platform-delete" || service.actor.TargetScopeID != platformScope {
		t.Fatalf("delete status=%d actor=%#v group=%s revision=%d key=%q request=%q body=%s",
			deleteResponse.Code, service.actor, service.deleteGroupID, service.deleteRevision,
			service.deleteKey, service.deleteRequestID, deleteResponse.Body.String())
	}

	targetWrite := httptest.NewRequest(http.MethodPost,
		"/v1/node-line-groups?target_scope_id="+tenantScope.String(), bytes.NewBufferString(body))
	targetWrite.Header.Set("Content-Type", "application/json")
	targetWrite.Header.Set("If-Match", `"0"`)
	targetWrite.Header.Set("Idempotency-Key", "platform-tenant-write")
	targetWrite.Header.Set("X-Request-ID", "platform-tenant-write")
	targetWriteResponse := httptest.NewRecorder()
	handler.ServeHTTP(targetWriteResponse, targetWrite)
	assertErrorCode(t, targetWriteResponse, http.StatusForbidden, "node_scheduling_platform_write_forbidden")
}

func TestHandlerDecisionReasonAndEffectiveFallback(t *testing.T) {
	scopeID, endpointID := uuid.New(), uuid.New()
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	endpoint := nodescheduler.Endpoint{ID: endpointID, NodeID: uuid.New(), Address: "192.0.2.1", Port: 443,
		Weight: 1, Enabled: true, Health: nodescheduler.HealthState{Status: nodescheduler.HealthHealthy, RowRevision: 2}}
	service := &fakeService{decision: nodescheduler.Decision{
		Endpoint: endpoint, Strategy: nodescheduler.StrategyP2CLeastLoaded,
		Reason: nodescheduler.ReasonTelemetryStaleFallback, Fallback: true,
		Plan: nodescheduler.Plan{GroupID: uuid.New(), Revision: 3, Priority: 0,
			TierReason: nodescheduler.ReasonPrimaryPrioritySelected, EvaluatedAt: now,
			ConfigurationDigest: make([]byte, 32), Candidates: []nodescheduler.Endpoint{endpoint}, Digest: [32]byte{0x42},
			Evaluations: []nodescheduler.EndpointEvaluation{{Endpoint: endpoint, Disposition: nodescheduler.EndpointDispositionCandidate}}},
	}}
	authenticator := &staticAuthenticator{actor: nodescheduler.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant"}}
	handler, _ := NewHandler(service, authenticator)
	request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+uuid.NewString()+"/decisions",
		strings.NewReader(`{"selector":{"region":"华东","carrier":"电信"},"requested_mode":"p2c_least_loaded","stable_key":"client-1"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "decision-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"effective_mode":"weighted_baseline"`) ||
		!strings.Contains(response.Body.String(), `"reason":"telemetry_stale_fallback"`) ||
		!strings.Contains(response.Body.String(), `"tier_reason":"primary_priority_selected"`) ||
		!strings.Contains(response.Body.String(), `"health_row_revision":2`) ||
		!strings.Contains(response.Body.String(), `"evaluated_at":"2026-08-09T09:00:00Z"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if service.decisionRequest.RequestID != "decision-1" {
		t.Fatalf("decision request ID=%q", service.decisionRequest.RequestID)
	}
}

func TestHandlerDecisionStableKeyUnicodeCodePointBoundary(t *testing.T) {
	scopeID := uuid.New()
	service := &fakeService{}
	handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		stableKey  string
		wantStatus int
	}{
		{name: "1024 multibyte code points", stableKey: strings.Repeat("界", 1024), wantStatus: http.StatusOK},
		{name: "1025 multibyte code points", stableKey: strings.Repeat("界", 1025), wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(decisionBody{
				Selector:      &nodescheduler.Selector{},
				RequestedMode: nodescheduler.StrategyWeightedBaseline,
				StableKey:     test.stableKey,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+uuid.NewString()+"/decisions", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", "decision-unicode-boundary")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantStatus == http.StatusOK && service.decisionRequest.StableKey != test.stableKey {
				t.Fatalf("stable key code points were not preserved")
			}
			if test.wantStatus == http.StatusBadRequest {
				assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
			}
		})
	}
}

func TestHandlerRejectsInvalidUTF8BeforeJSONDecoding(t *testing.T) {
	prefix := []byte(`{"selector":{"region":"","carrier":""},"requested_mode":"weighted_baseline","stable_key":"`)
	suffix := []byte(`"}`)
	valueBody := func(value []byte) []byte {
		body := append([]byte(nil), prefix...)
		body = append(body, value...)
		return append(body, suffix...)
	}
	validBody := valueBody([]byte("client"))
	invalidKey := []byte(`{"selector":{"region":"","carrier":""},"requested_mode":"weighted_baseline","stable_`)
	invalidKey = append(invalidKey, 0xff)
	invalidKey = append(invalidKey, []byte(`key":"client"}`)...)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "invalid leading byte", body: append([]byte{0xff}, validBody...)},
		{name: "lone continuation", body: valueBody([]byte{'c', 'l', 'i', 'e', 'n', 't', 0x80})},
		{name: "truncated multibyte", body: append(append([]byte(nil), prefix...), 0xe2, 0x82)},
		{name: "embedded invalid key", body: invalidKey},
		{name: "embedded invalid value", body: valueBody([]byte{'c', 'l', 'i', 'e', 'n', 't', 0xff})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &countingDecisionService{fakeService: &fakeService{}}
			handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
				UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+uuid.NewString()+"/decisions", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", "decision-invalid-utf8")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
			if service.calls != 0 {
				t.Fatalf("invalid UTF-8 reached service %d times", service.calls)
			}
		})
	}
}

func TestHandlerAcceptsLegalUTF8ReplacementRune(t *testing.T) {
	service := &countingDecisionService{fakeService: &fakeService{}}
	handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"selector":{"region":"","carrier":""},"requested_mode":"weighted_baseline","stable_key":"client-` + "\ufffd" + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+uuid.NewString()+"/decisions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "decision-legal-replacement-rune")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || service.calls != 1 || service.decisionRequest.StableKey != "client-\ufffd" {
		t.Fatalf("status=%d calls=%d stable_key=%q body=%s",
			response.Code, service.calls, service.decisionRequest.StableKey, response.Body.String())
	}
}

func TestHandlerDecodePreservesStrictJSONContracts(t *testing.T) {
	validBody := []byte(`{"selector":{"region":"","carrier":""},"requested_mode":"weighted_baseline","stable_key":"client"}`)
	unknownField := append([]byte(nil), validBody[:len(validBody)-1]...)
	unknownField = append(unknownField, []byte(`,"extra":true}`)...)
	trailingJSON := append(append([]byte(nil), validBody...), []byte(`{}`)...)
	oversize := append([]byte(nil), validBody...)
	oversize = append(oversize, bytes.Repeat([]byte{' '}, int(maxRequestBytes)-len(oversize)+1)...)
	tests := []struct {
		name string
		body []byte
	}{
		{name: "oversize", body: oversize},
		{name: "unknown field", body: unknownField},
		{name: "trailing JSON", body: trailingJSON},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &countingDecisionService{fakeService: &fakeService{}}
			handler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
				UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant",
			}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+uuid.NewString()+"/decisions", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", "decision-strict-json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
			if service.calls != 0 {
				t.Fatalf("invalid JSON reached service %d times", service.calls)
			}
		})
	}
}

func TestHandlerTargetSnapshotGetScopesErrorsAndPostDTO(t *testing.T) {
	tenantScope, platformScope, groupID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var nodeDigest [32]byte
	nodeDigest[0] = 0x42
	snapshot := nodescheduler.TargetSnapshot{
		Reference:     nodescheduler.TargetSnapshotReference{ID: uuid.New(), Revision: 3, SHA256: nodeDigest},
		TenantScopeID: tenantScope, SourceLineGroupID: groupID, SourceRevision: 2,
		SourceConfigurationDigest: bytes.Repeat([]byte{0x24}, 32), NodeIDs: []uuid.UUID{nodeID},
	}
	service := &fakeService{snapshot: snapshot}
	tenantHandler, err := NewHandler(service, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: tenantScope, ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet,
		"/v1/node-line-groups/"+groupID.String()+"/target-snapshots?source_revision=2", nil)
	getResponse := httptest.NewRecorder()
	tenantHandler.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || service.snapshotRevision != 2 || service.actor.TargetScopeID != tenantScope {
		t.Fatalf("GET status=%d revision=%d actor=%#v body=%s",
			getResponse.Code, service.snapshotRevision, service.actor, getResponse.Body.String())
	}

	post := httptest.NewRequest(http.MethodPost, "/v1/node-line-groups/"+groupID.String()+"/target-snapshots",
		strings.NewReader(`{"source_revision":2,"node_ids":["`+nodeID.String()+`"]}`))
	post.Header.Set("Content-Type", "application/json")
	post.Header.Set("Idempotency-Key", "snapshot-dto")
	post.Header.Set("X-Request-ID", "snapshot-dto-request")
	postResponse := httptest.NewRecorder()
	tenantHandler.ServeHTTP(postResponse, post)
	if postResponse.Code != http.StatusCreated || postResponse.Body.String() != getResponse.Body.String() {
		t.Fatalf("POST status=%d body=%s GET body=%s", postResponse.Code, postResponse.Body.String(), getResponse.Body.String())
	}

	for _, query := range []string{"", "?source_revision=0", "?source_revision=1&source_revision=2"} {
		response := httptest.NewRecorder()
		tenantHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
			"/v1/node-line-groups/"+groupID.String()+"/target-snapshots"+query, nil))
		assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
	}

	platformService := &fakeService{snapshot: snapshot}
	platformHandler, err := NewHandler(platformService, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: platformScope, ScopeKind: "platform",
	}})
	if err != nil {
		t.Fatal(err)
	}
	platformResponse := httptest.NewRecorder()
	platformHandler.ServeHTTP(platformResponse, httptest.NewRequest(http.MethodGet,
		"/v1/node-line-groups/"+groupID.String()+"/target-snapshots?source_revision=2&target_scope_id="+tenantScope.String(), nil))
	if platformResponse.Code != http.StatusOK || platformService.actor.TargetScopeID != tenantScope {
		t.Fatalf("platform status=%d actor=%#v body=%s", platformResponse.Code, platformService.actor, platformResponse.Body.String())
	}

	missingService := &fakeService{snapshotErr: nodescheduler.ErrNotFound}
	missingHandler, _ := NewHandler(missingService, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: tenantScope, ScopeKind: "tenant",
	}})
	missingResponse := httptest.NewRecorder()
	missingHandler.ServeHTTP(missingResponse, httptest.NewRequest(http.MethodGet,
		"/v1/node-line-groups/"+groupID.String()+"/target-snapshots?source_revision=99", nil))
	assertErrorCode(t, missingResponse, http.StatusNotFound, "node_scheduling_not_found")
}

func TestHandlerRejectsMissingRequiredJSONFields(t *testing.T) {
	scopeID, groupID, endpointID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	handler, err := NewHandler(&fakeService{}, &staticAuthenticator{actor: nodescheduler.Actor{
		UserID: uuid.New(), ScopeID: scopeID, ScopeKind: "tenant",
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, path, body string
		ifMatch          string
		idempotent       bool
	}{
		{name: "line group name", path: "/v1/node-line-groups", body: `{"health_policy":{"probe_interval_ms":10000,"probe_timeout_ms":3000,"failure_threshold":3,"recovery_threshold":3,"failure_debounce_ms":0,"recovery_debounce_ms":0},"endpoints":[{"id":"` + endpointID.String() + `","node_id":"` + nodeID.String() + `","address":"192.0.2.10","port":443,"region":"华东","carrier":"电信","priority":0,"weight":10,"enabled":true}]}`, ifMatch: `"0"`, idempotent: true},
		{name: "decision stable key", path: "/v1/node-line-groups/" + groupID.String() + "/decisions", body: `{"selector":{"region":"华东","carrier":"电信"},"requested_mode":"weighted_baseline"}`},
		{name: "snapshot source and nodes", path: "/v1/node-line-groups/" + groupID.String() + "/target-snapshots", body: `{}`, idempotent: true},
		{name: "rollback source", path: "/v1/node-line-groups/" + groupID.String() + "/rollback", body: `{}`, ifMatch: `"1"`, idempotent: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Request-ID", "required-fields")
			if test.ifMatch != "" {
				request.Header.Set("If-Match", test.ifMatch)
			}
			if test.idempotent {
				request.Header.Set("Idempotency-Key", "required-fields")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertErrorCode(t, response, http.StatusBadRequest, "node_scheduling_invalid_request")
		})
	}
}

func assertErrorCode(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
