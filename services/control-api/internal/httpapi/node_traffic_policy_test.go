package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodetrafficpolicy"
	"github.com/google/uuid"
)

type nodeTrafficPolicyApplicationStub struct {
	state        nodetrafficpolicy.PolicyState
	record       nodetrafficpolicy.EvaluationRecord
	put          nodetrafficpolicy.PutRequest
	evaluate     nodetrafficpolicy.EvaluateRequest
	getSyncTask  uuid.UUID
	getCallCount int
}

func (stub *nodeTrafficPolicyApplicationStub) Get(_ context.Context, _ nodetrafficpolicy.Actor, scopeID, nodeID uuid.UUID) (nodetrafficpolicy.PolicyState, error) {
	stub.getCallCount++
	if scopeID != stub.state.Policy.ScopeID || nodeID != stub.state.Policy.NodeID {
		return nodetrafficpolicy.PolicyState{}, nodetrafficpolicy.ErrNotFound
	}
	return stub.state, nil
}

func (stub *nodeTrafficPolicyApplicationStub) Put(_ context.Context, _ nodetrafficpolicy.Actor, request nodetrafficpolicy.PutRequest) (nodetrafficpolicy.WriteResult, error) {
	stub.put = request
	return nodetrafficpolicy.WriteResult{State: stub.state}, nil
}

func (stub *nodeTrafficPolicyApplicationStub) Evaluate(_ context.Context, _ nodetrafficpolicy.Actor, request nodetrafficpolicy.EvaluateRequest) (nodetrafficpolicy.EvaluationRecord, error) {
	stub.evaluate = request
	return stub.record, nil
}

func (stub *nodeTrafficPolicyApplicationStub) GetSyncTask(_ context.Context, _ nodetrafficpolicy.Actor, taskID uuid.UUID) (nodetrafficpolicy.SyncTask, error) {
	stub.getSyncTask = taskID
	return *stub.record.SyncTask, nil
}

func TestNodeTrafficPolicyHandlerReadsAndWritesStrongContract(t *testing.T) {
	policy := nodetrafficpolicy.Policy{
		ID:                uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ScopeID:           uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		NodeID:            uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		MonthlyLimitBytes: 1_000, Timezone: "Asia/Shanghai", Revision: 4,
	}
	stub := &nodeTrafficPolicyApplicationStub{state: nodetrafficpolicy.PolicyState{Policy: policy, AdminState: nodetrafficpolicy.NodeStateActive}}
	handler, err := NewNodeTrafficPolicyHandler(stub, func(*http.Request) (nodetrafficpolicy.Actor, error) {
		return nodetrafficpolicy.Actor{
			UserID: uuid.New(), ScopeID: policy.ScopeID, ScopeKind: nodetrafficpolicy.ScopeKindPlatform,
			Permissions: []string{nodetrafficpolicy.PermissionRead, nodetrafficpolicy.PermissionManage},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/admin/node-traffic-policies/"+policy.NodeID.String()+"?scope_id="+policy.ScopeID.String(), nil)
	get.Header.Set("X-Request-ID", "node-policy-read")
	read := httptest.NewRecorder()
	handler.ServeHTTP(read, get)
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"4"` || read.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("read = status %d headers %#v body %s", read.Code, read.Header(), read.Body.String())
	}

	body := `{"monthly_limit_bytes":2000,"timezone":"Asia/Shanghai","windows":[],"manual_override":{"mode":"none","revision":0,"expires_at":null}}`
	put := httptest.NewRequest(http.MethodPut, "/v1/admin/node-traffic-policies/"+policy.NodeID.String()+"?scope_id="+policy.ScopeID.String(), strings.NewReader(body))
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("If-Match", `"4"`)
	put.Header.Set("Idempotency-Key", "node-policy-write-1")
	put.Header.Set("X-Request-ID", "node-policy-write-request")
	write := httptest.NewRecorder()
	handler.ServeHTTP(write, put)
	if write.Code != http.StatusOK || stub.put.ExpectedRevision != 4 || stub.put.IdempotencyKey != "node-policy-write-1" ||
		stub.put.Policy.ScopeID != policy.ScopeID || stub.put.Policy.NodeID != policy.NodeID || stub.put.Policy.MonthlyLimitBytes != 2_000 {
		t.Fatalf("write = status %d request %#v body %s", write.Code, stub.put, write.Body.String())
	}
}

func TestNodeTrafficPolicyHandlerEvaluationAndSyncTaskAreDurableFacts(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	nodeID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	taskID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	configID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	stub := &nodeTrafficPolicyApplicationStub{
		state: nodetrafficpolicy.PolicyState{Policy: nodetrafficpolicy.Policy{ScopeID: scopeID, NodeID: nodeID}},
		record: nodetrafficpolicy.EvaluationRecord{
			ID: uuid.New(), ScopeID: scopeID, NodeID: nodeID,
			SyncTask: &nodetrafficpolicy.SyncTask{ID: taskID, ScopeID: scopeID, NodeID: nodeID, ConfigVersionID: configID, Status: nodetrafficpolicy.SyncTaskQueued},
		},
	}
	handler, err := NewNodeTrafficPolicyHandler(stub, func(*http.Request) (nodetrafficpolicy.Actor, error) {
		return nodetrafficpolicy.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: nodetrafficpolicy.ScopeKindPlatform, Permissions: []string{nodetrafficpolicy.PermissionManage, nodetrafficpolicy.PermissionRead}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	evaluate := httptest.NewRequest(http.MethodPost, "/v1/admin/node-traffic-policies/"+nodeID.String()+"/evaluate?scope_id="+scopeID.String(), http.NoBody)
	evaluate.Header.Set("Idempotency-Key", "node-policy-evaluate")
	evaluate.Header.Set("X-Request-ID", "node-policy-evaluate-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, evaluate)
	if response.Code != http.StatusOK || stub.evaluate.ScopeID != scopeID || stub.evaluate.NodeID != nodeID {
		t.Fatalf("evaluate = status %d request %#v body %s", response.Code, stub.evaluate, response.Body.String())
	}

	query := httptest.NewRequest(http.MethodGet, "/v1/admin/node-traffic-sync-tasks/"+taskID.String(), nil)
	queryResponse := httptest.NewRecorder()
	handler.ServeHTTP(queryResponse, query)
	if queryResponse.Code != http.StatusOK || stub.getSyncTask != taskID {
		t.Fatalf("sync query = status %d id %s body %s", queryResponse.Code, stub.getSyncTask, queryResponse.Body.String())
	}
	var task nodetrafficpolicy.SyncTask
	if err := json.Unmarshal(queryResponse.Body.Bytes(), &task); err != nil || task.ConfigVersionID != configID || task.Status != nodetrafficpolicy.SyncTaskQueued {
		t.Fatalf("sync response = (%#v, %v)", task, err)
	}
}

func TestNodeTrafficPolicyHandlerRejectsUnauthenticatedBeforeApplication(t *testing.T) {
	stub := &nodeTrafficPolicyApplicationStub{}
	handler, err := NewNodeTrafficPolicyHandler(stub, func(*http.Request) (nodetrafficpolicy.Actor, error) {
		return nodetrafficpolicy.Actor{}, nodetrafficpolicy.ErrUnauthenticated
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/node-traffic-policies/"+uuid.NewString()+"?scope_id="+uuid.NewString(), nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || stub.getCallCount != 0 {
		t.Fatalf("response = %d calls=%d body=%s", response.Code, stub.getCallCount, response.Body.String())
	}
}

func TestNodeTrafficPolicyHandlerRejectsStaleOrMalformedWrites(t *testing.T) {
	scopeID := uuid.New()
	nodeID := uuid.New()
	stub := &nodeTrafficPolicyApplicationStub{}
	handler, err := NewNodeTrafficPolicyHandler(stub, func(*http.Request) (nodetrafficpolicy.Actor, error) {
		return nodetrafficpolicy.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: nodetrafficpolicy.ScopeKindPlatform, Permissions: []string{nodetrafficpolicy.PermissionManage}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct{ body, match string }{
		"missing if match": {body: `{}`, match: ""},
		"invalid timezone": {body: `{"monthly_limit_bytes":1,"timezone":"../UTC","windows":[],"manual_override":{"mode":"none","revision":0,"expires_at":null}}`, match: `"1"`},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, "/v1/admin/node-traffic-policies/"+nodeID.String()+"?scope_id="+scopeID.String(), strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", test.match)
			request.Header.Set("Idempotency-Key", "write-1")
			request.Header.Set("X-Request-ID", "request-1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || stub.put.Policy.NodeID != uuid.Nil {
				t.Fatalf("response = %d request=%#v body=%s", response.Code, stub.put, response.Body.String())
			}
		})
	}
}
