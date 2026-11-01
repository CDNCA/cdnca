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
	enableRequest  firewallactioncontrol.SetEnabledRequest
	inheritRequest firewallactioncontrol.InheritRequest
	defaultRequest firewallactioncontrol.DefaultPutRequest
	defaultRead    firewallactioncontrol.DefaultReadRequest
	policy         firewallactioncontrol.Policy
	defaultPolicy  firewallactioncontrol.DefaultPolicy
	err            error
	putCalls       int
	enableCalls    int
}

func (stub *apiStub) SetEnabled(_ context.Context, request firewallactioncontrol.SetEnabledRequest) (firewallactioncontrol.WriteResult, error) {
	stub.enableCalls++
	stub.enableRequest = request
	policy := stub.policy
	policy.Enabled = request.Enabled
	return firewallactioncontrol.WriteResult{Policy: policy}, nil
}

func (stub *apiStub) Inherit(_ context.Context, request firewallactioncontrol.InheritRequest) (firewallactioncontrol.WriteResult, error) {
	stub.inheritRequest = request
	return firewallactioncontrol.WriteResult{Policy: stub.policy}, stub.err
}

func (stub *apiStub) GetDefault(_ context.Context, request firewallactioncontrol.DefaultReadRequest) (firewallactioncontrol.DefaultPolicy, error) {
	stub.defaultRead = request
	return stub.defaultPolicy, stub.err
}

func (stub *apiStub) PutDefault(_ context.Context, request firewallactioncontrol.DefaultPutRequest) (firewallactioncontrol.DefaultWriteResult, error) {
	stub.defaultRequest = request
	return firewallactioncontrol.DefaultWriteResult{Policy: stub.defaultPolicy}, stub.err
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

// autodefense-ux2 / migration 608: PATCH {"enabled":bool} with If-Match the
// current revision switches the policy; the revision (ETag) stays.
func TestPatchSwitchesEnabledAtCurrentRevision(t *testing.T) {
	api := &apiStub{policy: testPolicy()}
	handler := newHandler(t, api)
	path := "/v1/firewall-actions/policy?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222"
	send := func(body, etag string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPatch, path, strings.NewReader(body))
		request.Header.Set("If-Match", etag)
		request.Header.Set("Idempotency-Key", "adux2-patch")
		request.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	for name, invalid := range map[string]struct{ body, etag string }{
		"missing_enabled": {`{}`, `"4"`}, "null_enabled": {`{"enabled":null}`, `"4"`},
		"unknown_field": {`{"enabled":false,"x":1}`, `"4"`}, "zero_etag": {`{"enabled":false}`, `"0"`},
	} {
		if response := send(invalid.body, invalid.etag); response.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d", name, response.Code)
		}
	}
	if api.enableCalls != 0 {
		t.Fatalf("invalid requests reached service: %d", api.enableCalls)
	}
	response := send(`{"enabled":false}`, `"4"`)
	var policy firewallactioncontrol.Policy
	if err := json.Unmarshal(response.Body.Bytes(), &policy); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"4"` || api.enableRequest.ExpectedRevision != 4 ||
		api.enableRequest.Enabled || policy.Enabled || !strings.Contains(response.Body.String(), `"enabled":false`) {
		t.Fatalf("response=%d headers=%v request=%+v body=%s", response.Code, response.Header(), api.enableRequest, response.Body.String())
	}
	if response := send(`{"enabled":true}`, `"4"`); response.Code != http.StatusOK || !api.enableRequest.Enabled {
		t.Fatalf("enable: %d %+v", response.Code, api.enableRequest)
	}
}

const defaultPath = "/v1/firewall-actions/default?target_scope_id=11111111-1111-4111-8111-111111111111"

func writeHeaders(request *http.Request, etag string) {
	request.Header.Set("If-Match", etag)
	request.Header.Set("Idempotency-Key", "fw-default")
	request.Header.Set("X-Request-ID", "44444444-4444-4444-8444-444444444444")
}

func TestDefaultGetAndPutContract(t *testing.T) {
	api := &apiStub{defaultPolicy: firewallactioncontrol.DefaultPolicy{
		TenantScopeID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), Source: firewallactioncontrol.SourceSystemDefault,
		PolicyInput: firewallactioncontrol.SystemDefaultPolicy(), InheritingSiteCount: 2,
	}}
	handler := newHandler(t, api)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, defaultPath, nil))
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK || response.Header().Get("ETag") != `"0"` {
		t.Fatalf("GET default = %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	for _, key := range []string{"tenant_scope_id", "source", "revision", "normal_action", "escalated_action", "engage_threshold",
		"recover_threshold", "recovery_windows", "block_networks", "trusted_proxies", "trusted_crawlers", "return_page",
		"inheriting_site_count", "updated_at"} {
		if _, ok := body[key]; !ok {
			t.Errorf("default response missing %q: %s", key, response.Body.String())
		}
	}
	if len(body) != 14 || body["source"] != "system_default" || body["updated_at"] != nil {
		t.Fatalf("default response = %s", response.Body.String())
	}

	api.defaultPolicy.Revision, api.defaultPolicy.Source = 1, firewallactioncontrol.SourceTenantDefault
	input, _ := json.Marshal(firewallactioncontrol.SystemDefaultPolicy())
	request := httptest.NewRequest(http.MethodPut, defaultPath, strings.NewReader(string(input)))
	writeHeaders(request, `"0"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || api.defaultRequest.ExpectedRevision != 0 ||
		api.defaultRequest.TargetScopeID.String() != "11111111-1111-4111-8111-111111111111" || api.defaultRequest.IdempotencyKey != "fw-default" {
		t.Fatalf("PUT default = %d %v request=%+v", response.Code, response.Header(), api.defaultRequest)
	}
	for name, path := range map[string]string{
		"extra_site_id": defaultPath + "&site_id=22222222-2222-4222-8222-222222222222",
		"no_scope":      "/v1/firewall-actions/default",
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
	unknown := httptest.NewRequest(http.MethodPut, defaultPath, strings.NewReader(`{"unknown":1}`))
	writeHeaders(unknown, `"0"`)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, unknown)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, defaultPath, nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("DELETE default status=%d", response.Code)
	}
}

func TestDeleteSitePolicyRestoresInheritance(t *testing.T) {
	inherited := testPolicy()
	inherited.Inherited, inherited.Source, inherited.Delivered = true, firewallactioncontrol.SourceTenantDefault, true
	inherited.Revision, inherited.ActiveRevision, inherited.LKGRevision, inherited.DeploymentState = 5, 0, 0, firewallactioncontrol.StateInherited
	api := &apiStub{policy: inherited}
	handler := newHandler(t, api)
	path := "/v1/firewall-actions/policy?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222"
	for _, body := range []string{"", "{}"} {
		request := httptest.NewRequest(http.MethodDelete, path, strings.NewReader(body))
		writeHeaders(request, `"4"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var decoded map[string]any
		_ = json.Unmarshal(response.Body.Bytes(), &decoded)
		if response.Code != http.StatusOK || response.Header().Get("ETag") != `"5"` || api.inheritRequest.ExpectedRevision != 4 ||
			decoded["inherited"] != true || decoded["source"] != "tenant_default" || decoded["deployment_state"] != "inherited" {
			t.Fatalf("DELETE body=%q = %d %v %s", body, response.Code, response.Header(), response.Body.String())
		}
	}
	for name, test := range map[string]struct{ body, etag string }{
		"zero_etag":    {"", `"0"`},
		"missing_etag": {"", ""},
		"bad_body":     {`{"x":1}`, `"4"`},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, path, strings.NewReader(test.body))
			writeHeaders(request, test.etag)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
	api.err = firewallactioncontrol.ErrNotFound
	request := httptest.NewRequest(http.MethodDelete, path, nil)
	writeHeaders(request, `"4"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "firewall_action_not_found") {
		t.Fatalf("already inheriting = %d %s", response.Code, response.Body.String())
	}
}

func TestGetSitePolicyCarriesInheritanceFields(t *testing.T) {
	api := &apiStub{policy: testPolicy()}
	api.policy.Source, api.policy.Delivered = firewallactioncontrol.SourceSite, true
	response := httptest.NewRecorder()
	newHandler(t, api).ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/firewall-actions/policy?target_scope_id=11111111-1111-4111-8111-111111111111&site_id=22222222-2222-4222-8222-222222222222", nil))
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil || response.Code != http.StatusOK {
		t.Fatalf("GET = %d %s", response.Code, response.Body.String())
	}
	if decoded["inherited"] != false || decoded["source"] != "site" || decoded["delivered"] != true || len(decoded) != 24 { // 23 + enabled（608）
		t.Fatalf("GET body = %s", response.Body.String())
	}
}
