package openrestysecurityhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/openrestysecurity"
	"github.com/google/uuid"
)

type fakeAPI struct {
	global               openrestysecurity.Document
	globalRequest        openrestysecurity.ReadGlobalRequest
	globalCalls          int
	patchRequest         openrestysecurity.PatchGlobalRequest
	overridePatchRequest openrestysecurity.PatchOverrideRequest
	groupStateRequest    openrestysecurity.RuleGroupStateRequest
	patchError           error
}

func (fake *fakeAPI) GetGlobal(_ context.Context, request openrestysecurity.ReadGlobalRequest) (openrestysecurity.Document, error) {
	fake.globalRequest = request
	fake.globalCalls++
	return fake.global, nil
}
func (fake *fakeAPI) PatchGlobal(_ context.Context, request openrestysecurity.PatchGlobalRequest) (openrestysecurity.WriteResult, error) {
	fake.patchRequest = request
	return openrestysecurity.WriteResult{Document: fake.global}, fake.patchError
}
func (*fakeAPI) ListOverrides(context.Context, openrestysecurity.ListOverridesRequest) (openrestysecurity.OverridePage, error) {
	return openrestysecurity.OverridePage{Items: []openrestysecurity.Document{}, Page: 1, PageSize: 20}, nil
}
func (*fakeAPI) CreateOverride(context.Context, openrestysecurity.CreateOverrideRequest) (openrestysecurity.WriteResult, error) {
	return openrestysecurity.WriteResult{}, nil
}
func (fake *fakeAPI) PatchOverride(_ context.Context, request openrestysecurity.PatchOverrideRequest) (openrestysecurity.WriteResult, error) {
	fake.overridePatchRequest = request
	return openrestysecurity.WriteResult{Document: fake.global}, nil
}
func (*fakeAPI) DeleteOverride(context.Context, openrestysecurity.DeleteOverrideRequest) (bool, error) {
	return false, nil
}
func (*fakeAPI) SearchTargets(context.Context, openrestysecurity.SearchTargetsRequest) (openrestysecurity.TargetPage, error) {
	return openrestysecurity.TargetPage{Items: []openrestysecurity.TargetOption{}, Page: 1, PageSize: 20}, nil
}
func (fake *fakeAPI) Effective(context.Context, openrestysecurity.EffectiveRequest) (openrestysecurity.Document, error) {
	return fake.global, nil
}
func (*fakeAPI) RuleGroups(context.Context, openrestysecurity.RuleGroupsRequest) ([]openrestysecurity.RuleGroup, error) {
	return []openrestysecurity.RuleGroup{{ID: "10003", Name: "旋转图片", Enabled: true, Kind: "system", SystemRule: true, Sort: 8}}, nil
}
func (fake *fakeAPI) SetRuleGroupEnabled(_ context.Context, request openrestysecurity.RuleGroupStateRequest) error {
	fake.groupStateRequest = request
	return nil
}
func (*fakeAPI) DownloadCCImage(context.Context, openrestysecurity.DownloadCCImageRequest) (bool, error) {
	return false, nil
}

func TestPatchGlobalCarriesCASAndStableIdempotency(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fake := &fakeAPI{global: testDocument(scopeID)}
	handler, err := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPatch,
		"/v1/openresty-security/configs/global",
		strings.NewReader(`{"patch":{"cc_enable":true}}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("If-Match", `"4"`)
	request.Header.Set("Idempotency-Key", "autosave-1")
	request.Header.Set("X-Request-ID", "11111111-1111-4111-8111-111111111111")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.patchRequest.ExpectedRevision != 4 || fake.patchRequest.IdempotencyKey != "autosave-1" ||
		string(fake.patchRequest.Patch["cc_enable"]) != "true" {
		t.Fatalf("request=%+v", fake.patchRequest)
	}
	if response.Header().Get("ETag") != `"4"` {
		t.Fatalf("ETag=%q", response.Header().Get("ETag"))
	}
	if response.Header().Get("X-Request-ID") != "11111111-1111-4111-8111-111111111111" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers=%v", response.Header())
	}
}

func TestRevisionConflictUsesPreconditionFailed(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fake := &fakeAPI{global: testDocument(scopeID), patchError: openrestysecurity.ErrRevisionConflict}
	handler, _ := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	request := httptest.NewRequest(http.MethodPatch,
		"/v1/openresty-security/configs/global",
		strings.NewReader(`{"patch":{"cc_enable":true}}`))
	request.Header.Set("If-Match", `"4"`)
	request.Header.Set("Idempotency-Key", "autosave-1")
	request.Header.Set("X-Request-ID", "request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionFailed || !strings.Contains(response.Body.String(), "revision_conflict") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPatchOverrideCarriesRemovedFieldsCASAndStableIdempotency(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	overrideID := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	fake := &fakeAPI{global: testDocument(scopeID)}
	handler, _ := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	request := httptest.NewRequest(http.MethodPatch,
		"/v1/openresty-security/overrides/"+overrideID.String(),
		strings.NewReader(`{"patch":{"cc_enable":false},"removed_fields":["icmp_drop"]}`))
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "override-edit-1")
	request.Header.Set("X-Request-ID", "override-request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	got := fake.overridePatchRequest
	if got.ID != overrideID || got.ExpectedRevision != 7 || got.IdempotencyKey != "override-edit-1" ||
		got.RequestID != "override-request-1" || string(got.Patch["cc_enable"]) != "false" ||
		!reflect.DeepEqual(got.RemovedFields, []string{"icmp_drop"}) {
		t.Fatalf("request=%+v", got)
	}
}

func TestPatchOverrideRejectsUnknownRemovedFieldBeforeAPI(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fake := &fakeAPI{global: testDocument(scopeID)}
	handler, _ := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	request := httptest.NewRequest(http.MethodPatch,
		"/v1/openresty-security/overrides/33333333-3333-4333-8333-333333333333",
		strings.NewReader(`{"patch":{"cc_enable":false},"removed_fields":["resolver"]}`))
	request.Header.Set("If-Match", `"7"`)
	request.Header.Set("Idempotency-Key", "override-edit-2")
	request.Header.Set("X-Request-ID", "override-request-2")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || fake.overridePatchRequest.ID != uuid.Nil {
		t.Fatalf("status=%d request=%+v body=%s", response.Code, fake.overridePatchRequest, response.Body.String())
	}
}

func TestGlobalResponseNeverContainsSecret(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fake := &fakeAPI{global: testDocument(scopeID)}
	handler, _ := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionRead}}, nil
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/openresty-security/configs/global", nil))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "secret-value") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["key_configured"] != true {
		t.Fatalf("response=%v", decoded)
	}
	if _, exists := decoded["target_scope_id"]; exists {
		t.Fatalf("global response leaked removed target_scope_id: %v", decoded)
	}
}

func TestCanonicalRequestsDeriveTargetScopeFromAuthenticatedActor(t *testing.T) {
	for _, scopeKind := range []string{openrestysecurity.ScopePlatform} {
		t.Run(scopeKind, func(t *testing.T) {
			scopeID := uuid.New()
			fake := &fakeAPI{global: testDocument(scopeID)}
			handler, err := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
				return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: scopeKind,
					Permissions: []string{openrestysecurity.PermissionRead}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
				"/v1/openresty-security/configs/global", nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if fake.globalCalls != 1 || fake.globalRequest.TargetScopeID != scopeID ||
				fake.globalRequest.Actor.ScopeID != scopeID || fake.globalRequest.Actor.ScopeKind != scopeKind {
				t.Fatalf("calls=%d request=%+v", fake.globalCalls, fake.globalRequest)
			}
		})
	}
}

func TestCanonicalRequestsRejectTenantActorBeforeAPI(t *testing.T) {
	scopeID := uuid.New()
	fake := &fakeAPI{global: testDocument(scopeID)}
	handler, err := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopeTenant,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/openresty-security/configs/global", nil))
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "permission_denied") ||
		fake.globalCalls != 0 {
		t.Fatalf("status=%d calls=%d body=%s", response.Code, fake.globalCalls, response.Body.String())
	}
}

func TestTargetScopeQueryIsRejectedAfterAuthenticationBeforeAPI(t *testing.T) {
	scopeID := uuid.New()
	for _, rawQuery := range []string{
		"target_scope_id=" + scopeID.String(),
		"target_scope_id=",
		"target_scope_id=" + scopeID.String() + "&target_scope_id=" + scopeID.String(),
	} {
		t.Run(rawQuery, func(t *testing.T) {
			fake := &fakeAPI{global: testDocument(scopeID)}
			authenticationCalls := 0
			handler, err := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
				authenticationCalls++
				return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID,
					ScopeKind:   openrestysecurity.ScopePlatform,
					Permissions: []string{openrestysecurity.PermissionRead}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}

			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
				"/v1/openresty-security/configs/global?"+rawQuery, nil))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_request") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if authenticationCalls != 1 || fake.globalCalls != 0 {
				t.Fatalf("authentication calls=%d API calls=%d", authenticationCalls, fake.globalCalls)
			}
		})
	}
}

func TestAuthenticationFailureStopsBeforeAPI(t *testing.T) {
	fake := &fakeAPI{}
	handler, _ := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{}, openrestysecurity.ErrUnauthenticated
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/openresty-security/configs/global", nil))
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "unauthenticated") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	requestID := response.Header().Get("X-Request-ID")
	if _, err := uuid.Parse(requestID); err != nil || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("request id=%q headers=%v", requestID, response.Header())
	}
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != "unauthenticated" ||
		envelope.Error.RequestID != requestID {
		t.Fatalf("envelope=%+v err=%v", envelope, err)
	}
}

func TestKnownPathsRejectUnsupportedMethods(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	handler, _ := NewHandler(&fakeAPI{}, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionRead}}, nil
	})
	tests := []struct {
		path  string
		allow string
	}{
		{"/v1/openresty-security/configs/global", "GET, PATCH"},
		{"/v1/openresty-security/overrides", "GET, POST"},
		{"/v1/openresty-security/overrides/11111111-1111-4111-8111-111111111111", "PATCH, DELETE"},
		{"/v1/openresty-security/targets", "GET"},
		{"/v1/openresty-security/effective", "GET"},
		{"/v1/cc-rule-groups", "GET"},
		{"/v1/openresty-security/actions/download-cc-image", "POST"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPut, test.path, nil)
			request.Header.Set("X-Request-ID", "unsupported-method")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != test.allow {
				t.Fatalf("status=%d allow=%q body=%s", response.Code, response.Header().Get("Allow"), response.Body.String())
			}
			if response.Header().Get("X-Request-ID") != "unsupported-method" ||
				response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("headers=%v", response.Header())
			}
			var envelope struct {
				Error struct {
					Code      string `json:"code"`
					RequestID string `json:"request_id"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error.Code != "method_not_allowed" ||
				envelope.Error.RequestID != "unsupported-method" {
				t.Fatalf("envelope=%+v err=%v", envelope, err)
			}
		})
	}
}

func TestSetRuleGroupEnabledAcceptsStableSystemRuleKey(t *testing.T) {
	scopeID := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	fake := &fakeAPI{}
	handler, err := NewHandler(fake, func(*http.Request) (openrestysecurity.Actor, error) {
		return openrestysecurity.Actor{UserID: uuid.New(), ScopeID: scopeID, ScopeKind: openrestysecurity.ScopePlatform,
			Permissions: []string{openrestysecurity.PermissionManage}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/cc-rule-groups/cc.challenge.5s/disable", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"cc.challenge.5s"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if fake.groupStateRequest.SystemRuleID != "cc.challenge.5s" || fake.groupStateRequest.Enabled {
		t.Fatalf("state request = %+v", fake.groupStateRequest)
	}
}

func testDocument(scopeID uuid.UUID) openrestysecurity.Document {
	config, err := openrestysecurity.DecodeConfig([]byte(`{"cc_enable":true,"block_time":3600}`), false)
	if err != nil {
		panic(err)
	}
	return openrestysecurity.Document{ID: uuid.MustParse("11111111-1111-4111-8111-111111111111"), TargetScopeID: scopeID,
		ScopeType: openrestysecurity.ScopeGlobal, ScopeID: "0", ScopeLabel: "全局", Revision: 4, Config: config, KeyConfigured: true,
		UpdatedAt: time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)}
}

var _ API = (*fakeAPI)(nil)
