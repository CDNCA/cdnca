package firewallactionhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
	"github.com/google/uuid"
)

type apiStub struct {
	putRequest     firewallactioncontrol.PutRequest
	recoverRequest firewallactioncontrol.RecoverRequest
	policy         firewallactioncontrol.Policy
	putCalls       int
}

func (stub *apiStub) Put(_ context.Context, request firewallactioncontrol.PutRequest) (firewallactioncontrol.WriteResult, error) {
	stub.putCalls++
	stub.putRequest = request
	return firewallactioncontrol.WriteResult{Policy: stub.policy}, nil
}

func (stub *apiStub) Get(context.Context, firewallactioncontrol.ReadRequest) (firewallactioncontrol.Policy, error) {
	return stub.policy, nil
}

func (stub *apiStub) Recover(_ context.Context, request firewallactioncontrol.RecoverRequest) (firewallactioncontrol.WriteResult, error) {
	stub.recoverRequest = request
	return firewallactioncontrol.WriteResult{Policy: stub.policy}, nil
}

func testPolicy() firewallactioncontrol.Policy {
	return firewallactioncontrol.Policy{
		ID:            uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		TenantScopeID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		SiteID:        uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		PolicyInput: firewallactioncontrol.PolicyInput{NormalAction: firewallactioncontrol.ActionDisconnect,
			EscalatedAction: firewallactioncontrol.ActionNFTables, EngageThreshold: 100, RecoverThreshold: 20, RecoveryWindows: 3,
			BlockNetworks: []string{"198.51.100.0/24"}, TrustedProxies: []string{}, TrustedCrawlers: []firewallactioncontrol.TrustedCrawler{},
			ReturnPage: firewallactioncontrol.ReturnPage{Status: 429, ContentType: "text/plain; charset=utf-8", Body: "Request limited"}},
		Revision: 4, ActiveRevision: 3, LKGRevision: 3, DeploymentState: firewallactioncontrol.StateFailed,
		DocumentSHA256: strings.Repeat("a", 64),
	}
}

func newHandler(t *testing.T, api *apiStub) http.Handler {
	t.Helper()
	handler, err := NewHandler(api, func(*http.Request) (firewallactioncontrol.Actor, error) {
		return firewallactioncontrol.Actor{UserID: uuid.New(), ScopeID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
			ScopeKind: firewallactioncontrol.ScopeTenant, Permissions: []string{firewallactioncontrol.PermissionRead, firewallactioncontrol.PermissionManage}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestPutRequiresStrictBodyAndQuotedCAS(t *testing.T) {
	api := &apiStub{policy: testPolicy()}
	handler := newHandler(t, api)
	path := "/v1/firewall-actions/policy?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222"
	for name, body := range map[string]struct{ body, etag string }{
		"unknown_field": {`{"enabled":true,"unknown":1}`, `"0"`},
		"double_json":   {`{} {}`, `"0"`},
		"null_body":     {`null`, `"0"`},
		"weak_etag":     {`{}`, `W/"0"`},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body.body))
			request.Header.Set("If-Match", body.etag)
			request.Header.Set("Idempotency-Key", "sec06-http")
			request.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if api.putCalls != 0 {
		t.Fatalf("invalid requests reached service: %d", api.putCalls)
	}
}

func TestPutReturnsRevisionETagAndForwardsMetadata(t *testing.T) {
	api := &apiStub{policy: testPolicy()}
	handler := newHandler(t, api)
	body, _ := json.Marshal(api.policy.PolicyInput)
	request := httptest.NewRequest(http.MethodPut, "/v1/firewall-actions/policy?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222", strings.NewReader(string(body)))
	request.Header.Set("If-Match", `"3"`)
	request.Header.Set("Idempotency-Key", "sec06-http")
	request.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || api.putRequest.ExpectedRevision != 3 || api.putRequest.SiteID.String() != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("response=%d headers=%v request=%+v body=%s", response.Code, response.Header(), api.putRequest, response.Body.String())
	}
}

func TestRecoverUsesCurrentRevisionAndLKGEndpoint(t *testing.T) {
	api := &apiStub{policy: testPolicy()}
	handler := newHandler(t, api)
	request := httptest.NewRequest(http.MethodPost, "/v1/firewall-actions/policy/recover?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222", strings.NewReader(`{}`))
	request.Header.Set("If-Match", `"4"`)
	request.Header.Set("Idempotency-Key", "sec06-recover")
	request.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || api.recoverRequest.ExpectedRevision != 4 {
		t.Fatalf("response=%d request=%+v body=%s", response.Code, api.recoverRequest, response.Body.String())
	}
}
