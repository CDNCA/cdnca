package cachecontrolhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func intPointer(value int) *int { return &value }

// CACHE-01 / fix-cachequota: GET /v1/cache-operations/daily-usage returns the
// account's three quotas (no site needed); an extra query (the old site_id)
// is refused before the store is read; a store failure is never a fake zero.
func TestHandlerDailyUsage(t *testing.T) {
	scopeID, userID := uuid.New(), uuid.New()
	resets := time.Date(2026, 10, 25, 16, 0, 0, 0, time.UTC)
	calls := 0
	control := &fakeControl{dailyUsage: func(_ context.Context, actor cachecontrol.Actor) (cachecontrol.DailyUsage, error) {
		calls++
		if actor.ScopeID != scopeID || actor.ActorScopeID != scopeID {
			t.Fatalf("actor=%+v", actor)
		}
		return cachecontrol.DailyUsage{ScopeID: scopeID,
			URLPurge:       cachecontrol.DailyQuota{Limit: 100, Used: 3, Remaining: 97, DefaultLimit: 2000, Override: intPointer(100)},
			DirectoryPurge: cachecontrol.DailyQuota{Limit: 10, Used: 10, DefaultLimit: 10},
			Prewarm:        cachecontrol.DailyQuota{Limit: 50, Remaining: 50, DefaultLimit: 50},
			ResetsAt:       resets, Revision: 2}, nil
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsRead), nil
	})
	response := serve(t, handler, http.MethodGet, "/v1/cache-operations/daily-usage", nil, "tenant", "")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	url := body["url_purge"].(map[string]any)
	if url["limit"] != float64(100) || url["used"] != float64(3) || url["remaining"] != float64(97) ||
		url["default_limit"] != float64(2000) || url["override"] != float64(100) ||
		body["directory_purge"].(map[string]any)["override"] != nil || body["scope_id"] != scopeID.String() ||
		body["resets_at"] != "2026-10-25T16:00:00Z" || body["revision"] != float64(2) {
		t.Fatalf("body=%s", response.Body.String())
	}
	if response := serve(t, handler, http.MethodGet, "/v1/cache-operations/daily-usage?site_id="+uuid.NewString(), nil, "tenant", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("site_id query status=%d body=%s", response.Code, response.Body.String())
	}
	// Tenants cannot set their own limits.
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		if response := serve(t, handler, method, "/v1/cache-operations/daily-usage", nil, "tenant", ""); response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d", method, response.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("store calls=%d", calls)
	}
	control.dailyUsage = func(context.Context, cachecontrol.Actor) (cachecontrol.DailyUsage, error) {
		return cachecontrol.DailyUsage{}, ErrStoreUnavailable
	}
	if response := serve(t, handler, http.MethodGet, "/v1/cache-operations/daily-usage", nil, "tenant", ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status=%d", response.Code)
	}
}

// fix-cachequota: an administrator reads a tenant account's quotas with
// scope_id and sets its own limits with PUT (null = follow the default). The
// write needs the user management permission, sends every key and
// expected_revision, and a stale revision is 412.
func TestHandlerAdminAccountLimits(t *testing.T) {
	platformScopeID, adminID, tenantScopeID := uuid.New(), uuid.New(), uuid.New()
	var got cachecontrol.SetAccountLimitsRequest
	writes := 0
	control := &fakeControl{
		dailyUsage: func(_ context.Context, actor cachecontrol.Actor) (cachecontrol.DailyUsage, error) {
			if actor.ScopeID != tenantScopeID || actor.ActorScopeID != platformScopeID || actor.UserID != adminID {
				t.Fatalf("read actor=%+v", actor)
			}
			return cachecontrol.DailyUsage{ScopeID: tenantScopeID, ResetsAt: time.Now().UTC()}, nil
		},
		setLimits: func(_ context.Context, actor cachecontrol.Actor, request cachecontrol.SetAccountLimitsRequest) (cachecontrol.DailyUsage, error) {
			writes++
			if actor.ScopeID != tenantScopeID || actor.ActorScopeID != platformScopeID {
				t.Fatalf("write actor=%+v", actor)
			}
			got = request
			if request.ExpectedRevision == 9 {
				return cachecontrol.DailyUsage{}, cachecontrol.ErrRevisionConflict
			}
			return cachecontrol.DailyUsage{ScopeID: tenantScopeID, Revision: request.ExpectedRevision + 1,
				URLPurge: cachecontrol.DailyQuota{Limit: 5000, DefaultLimit: 2000, Override: request.Limits.URLPurge, Remaining: 5000},
				ResetsAt: time.Now().UTC()}, nil
		},
	}
	permissions := []string{PermissionOperationsRead, PermissionAccountQuotaManage}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(adminID, platformScopeID, "platform", permissions...), nil
	})
	path := "/v1/admin/cache-operations/daily-usage?scope_id=" + tenantScopeID.String()
	if response := serve(t, handler, http.MethodGet, path, nil, "admin", ""); response.Code != http.StatusOK {
		t.Fatalf("admin read status=%d body=%s", response.Code, response.Body.String())
	}
	if response := serve(t, handler, http.MethodGet, "/v1/admin/cache-operations/daily-usage", nil, "admin", ""); response.Code != http.StatusBadRequest {
		t.Fatalf("admin read without scope status=%d", response.Code)
	}
	valid := `{"expected_revision":1,"url_purge_limit":5000,"directory_purge_limit":null,"prewarm_limit":0}`
	response := serveRaw(t, handler, http.MethodPut, path, valid, "admin", "")
	if response.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", response.Code, response.Body.String())
	}
	if got.ExpectedRevision != 1 || got.Limits.URLPurge == nil || *got.Limits.URLPurge != 5000 ||
		got.Limits.DirectoryPurge != nil || got.Limits.Prewarm == nil || *got.Limits.Prewarm != 0 || got.RequestID != "request-raw-01" {
		t.Fatalf("request=%+v", got)
	}
	for name, body := range map[string]string{
		"missing key":      `{"expected_revision":1,"url_purge_limit":5000,"directory_purge_limit":null}`,
		"missing revision": `{"url_purge_limit":5000,"directory_purge_limit":null,"prewarm_limit":null}`,
		"null revision":    `{"expected_revision":null,"url_purge_limit":5000,"directory_purge_limit":null,"prewarm_limit":null}`,
		"unknown key":      `{"expected_revision":1,"url_purge_limit":5000,"directory_purge_limit":null,"prewarm_limit":null,"site_id":"x"}`,
		"string limit":     `{"expected_revision":1,"url_purge_limit":"5000","directory_purge_limit":null,"prewarm_limit":null}`,
	} {
		if response := serveRaw(t, handler, http.MethodPut, path, body, "admin", ""); response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", name, response.Code, response.Body.String())
		}
	}
	stale := `{"expected_revision":9,"url_purge_limit":null,"directory_purge_limit":null,"prewarm_limit":null}`
	if response := serveRaw(t, handler, http.MethodPut, path, stale, "admin", ""); response.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale status=%d body=%s", response.Code, response.Body.String())
	}
	if writes != 2 {
		t.Fatalf("writes=%d", writes)
	}
	// Reading quotas is not enough to set them.
	permissions = []string{PermissionOperationsRead}
	if response := serveRaw(t, handler, http.MethodPut, path, valid, "admin", ""); response.Code != http.StatusForbidden {
		t.Fatalf("without identity.users.manage status=%d", response.Code)
	}
	permissions = []string{"platform.admin"}
	if response := serveRaw(t, handler, http.MethodPut, path, valid, "admin", ""); response.Code != http.StatusOK {
		t.Fatalf("platform.admin status=%d", response.Code)
	}
}

// fix-cachequota: a create over the account's quota is 429 with which quota,
// its limit, today's use and the requested targets.
func TestHandlerDailyLimitExceededDetails(t *testing.T) {
	scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New()
	control := &fakeControl{createOperation: func(context.Context, cachecontrol.Actor, cachecontrol.CreateOperationRequest) (cachecontrol.OperationWriteResult, error) {
		return cachecontrol.OperationWriteResult{}, fmt.Errorf("persist cache operation: %w", &cachecontrol.DailyLimitError{
			Quota: cachecontrol.QuotaDirectoryPurge, Limit: 10, Used: 9, Requested: 2})
	}}
	handler := testHandler(t, control, &fakeReader{}, func(*http.Request) (identity.Principal, error) {
		return principal(userID, scopeID, "tenant", PermissionOperationsManage), nil
	})
	body := fmt.Sprintf(`{"site_id":%q,"action":"purge","target_type":"directory_prefix","targets":["https://example.com/a/","https://example.com/b/"],"node_ids":[],"max_retries":0}`, siteID)
	response := serveRaw(t, handler, http.MethodPost, "/v1/cache-operations", body, "tenant", "quota-create-01")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	details := envelope.Error.Details
	if envelope.Error.Code != "daily_limit_exceeded" || details["field"] != "targets" || details["reason"] != "daily_limit_exceeded" ||
		details["quota"] != "directory_purge" || details["limit"] != float64(10) || details["used"] != float64(9) ||
		details["requested"] != float64(2) {
		t.Fatalf("body=%s", response.Body.String())
	}
}
