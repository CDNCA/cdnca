package nodeschedulerhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/google/uuid"
)

type l2SpyService struct {
	*fakeService
	configRequest nodescheduler.L2ConfigWriteRequest
	nodeRequest   nodescheduler.L2NodeWriteRequest
	config        nodescheduler.L2Config
	node          nodescheduler.L2Node
	available     []nodescheduler.L2NodeCandidate
	configCalls   int
	nodeCalls     int
}

func (service *l2SpyService) PutL2Config(
	_ context.Context,
	actor nodescheduler.Actor,
	request nodescheduler.L2ConfigWriteRequest,
) (nodescheduler.L2ConfigWriteResult, error) {
	service.actor, service.configRequest = actor, request
	service.configCalls++
	return nodescheduler.L2ConfigWriteResult{Config: service.config}, nil
}

func (service *l2SpyService) PutL2Node(
	_ context.Context,
	actor nodescheduler.Actor,
	request nodescheduler.L2NodeWriteRequest,
) (nodescheduler.L2NodeWriteResult, error) {
	service.actor, service.nodeRequest = actor, request
	service.nodeCalls++
	return nodescheduler.L2NodeWriteResult{Node: service.node}, nil
}

func (service *l2SpyService) ListAvailableL2Nodes(
	_ context.Context,
	actor nodescheduler.Actor,
	_ uuid.UUID,
) ([]nodescheduler.L2NodeCandidate, error) {
	service.actor = actor
	return service.available, nil
}

func TestL2ConfigCreateRequiresGuardedMetadataAndReturnsCanonicalResource(t *testing.T) {
	actor := nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	actor.TargetScopeID = actor.ScopeID
	configID := uuid.New()
	service := &l2SpyService{fakeService: &fakeService{}, config: nodescheduler.L2Config{
		ID: configID, DisplayID: "7", TenantScopeID: actor.ScopeID, Revision: 1,
		Name: "华东 L2", Region: "华东", Mode: nodescheduler.L2ModeCache, LoadMethod: nodescheduler.L2LoadRoundRobin,
	}}
	handler, err := NewHandler(service, &staticAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"华东 L2","region":"华东","remark":"主配置","mode":"cache","load_method":"rr"}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/l2-configs", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "l2-create-request")
	request.Header.Set("Idempotency-Key", "l2-create-key")
	request.Header.Set("If-Match", `"0"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"1"` ||
		response.Header().Get("Location") != "/v1/l2-configs/"+configID.String() {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.configCalls != 1 || service.configRequest.Name != "华东 L2" ||
		service.configRequest.ExpectedRevision != 0 || service.configRequest.IdempotencyKey != "l2-create-key" {
		t.Fatalf("config request = %#v calls=%d", service.configRequest, service.configCalls)
	}
	var decoded nodescheduler.L2Config
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || decoded.ID != configID {
		t.Fatalf("response config=%#v err=%v", decoded, err)
	}

	missing := httptest.NewRequest(http.MethodPost, "/v1/l2-configs", bytes.NewReader(body))
	missing.Header.Set("Content-Type", "application/json")
	missing.Header.Set("X-Request-ID", "l2-missing-request")
	missing.Header.Set("Idempotency-Key", "l2-missing-key")
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missing)
	if missingResponse.Code != http.StatusBadRequest || service.configCalls != 1 {
		t.Fatalf("missing guard status=%d calls=%d", missingResponse.Code, service.configCalls)
	}
}

func TestL2AvailableNodeListAndRevisionGuardedUpdate(t *testing.T) {
	actor := nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	actor.TargetScopeID = actor.ScopeID
	configID, membershipID, nodeID := uuid.New(), uuid.New(), uuid.New()
	service := &l2SpyService{
		fakeService: &fakeService{},
		available:   []nodescheduler.L2NodeCandidate{{NodeID: nodeID, DisplayID: "9", Name: "上海节点", OnlineStatus: "online"}},
		node:        nodescheduler.L2Node{ID: membershipID, NodeID: nodeID, ConfigID: configID, Revision: 3, Weight: 80, Enabled: true},
	}
	handler, err := NewHandler(service, &staticAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, httptest.NewRequest(http.MethodGet,
		"/v1/l2-nodes?config_id="+configID.String()+"&available=true", nil))
	if listResponse.Code != http.StatusOK || !bytes.Contains(listResponse.Body.Bytes(), []byte("上海节点")) {
		t.Fatalf("available response=%d %s", listResponse.Code, listResponse.Body.String())
	}

	body := []byte(`{"condition_id":null,"enabled":true,"weight":80,"sort":20}`)
	request := httptest.NewRequest(http.MethodPut, "/v1/l2-nodes/"+membershipID.String(), bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "l2-node-update-request")
	request.Header.Set("Idempotency-Key", "l2-node-update-key")
	request.Header.Set("If-Match", `"2"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"3"` || service.nodeCalls != 1 ||
		service.nodeRequest.MembershipID != membershipID || service.nodeRequest.ExpectedRevision != 2 ||
		service.nodeRequest.Weight != 80 || !service.nodeRequest.Enabled || service.nodeRequest.Sort != 20 {
		t.Fatalf("status=%d request=%#v calls=%d body=%s", response.Code, service.nodeRequest, service.nodeCalls, response.Body.String())
	}
}

func TestL2NodeUpdateRejectsMissingRequiredFields(t *testing.T) {
	actor := nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	actor.TargetScopeID = actor.ScopeID
	service := &l2SpyService{fakeService: &fakeService{}}
	handler, err := NewHandler(service, &staticAuthenticator{actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/v1/l2-nodes/"+uuid.NewString(), bytes.NewBufferString(`{"enabled":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "l2-node-invalid-request")
	request.Header.Set("Idempotency-Key", "l2-node-invalid-key")
	request.Header.Set("If-Match", `"1"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || service.nodeCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, service.nodeCalls, response.Body.String())
	}
}

func TestL2ConfigRegionRequiredDefault(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		for _, testCase := range []struct {
			name, region string
			valid        bool
		}{
			{name: "explicit default", region: `,"region":""`, valid: true},
			{name: "missing"},
			{name: "null", region: `,"region":null`},
			{name: "wrong type", region: `,"region":0`},
		} {
			t.Run(method+"/"+testCase.name, func(t *testing.T) {
				actor := nodescheduler.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
				configID := uuid.New()
				service := &l2SpyService{fakeService: &fakeService{}, config: nodescheduler.L2Config{
					ID: configID, TenantScopeID: actor.ScopeID, Revision: 1, Region: "",
				}}
				handler, err := NewHandler(service, &staticAuthenticator{actor: actor})
				if err != nil {
					t.Fatal(err)
				}
				path, revision, success := "/v1/l2-configs", `"0"`, http.StatusCreated
				if method == http.MethodPut {
					path, revision, success = path+"/"+configID.String(), `"1"`, http.StatusOK
				}
				request := httptest.NewRequest(method, path, bytes.NewBufferString(
					`{"name":"default","mode":"cache","load_method":"rr"`+testCase.region+`}`))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("If-Match", revision)
				request.Header.Set("Idempotency-Key", "default-region")
				request.Header.Set("X-Request-ID", "default-region-request")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if !testCase.valid {
					if response.Code != http.StatusBadRequest || service.configCalls != 0 {
						t.Fatalf("invalid region status=%d calls=%d body=%s", response.Code, service.configCalls, response.Body.String())
					}
					return
				}
				if response.Code != success || service.configCalls != 1 || service.configRequest.Region != "" ||
					service.actor.ResourceScopeID() != actor.ScopeID || !bytes.Contains(response.Body.Bytes(), []byte(`"region":""`)) {
					t.Fatalf("default region status=%d calls=%d body=%s", response.Code, service.configCalls, response.Body.String())
				}
			})
		}
	}
}
