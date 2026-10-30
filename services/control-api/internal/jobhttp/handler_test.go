package jobhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHandlerAuthenticationRBACAndStrictQueries(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000011")
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000011")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000011")
	reader := &fixtureReader{
		jobs:         []Job{fixtureJob(uuid.MustParse("40000000-0000-4000-8000-000000000011"), tenantID, StateQueued, fixtureNow)},
		scopeTenants: map[uuid.UUID]uuid.UUID{tenantScope: tenantID},
	}
	handler := fixtureHandler(t, reader, func(request *http.Request) (Principal, error) {
		switch request.Header.Get("X-Test-Principal") {
		case "platform":
			return platformPrincipal(platformScope), nil
		case "tenant":
			return tenantPrincipal(tenantScope), nil
		case "tenant-denied":
			principal := tenantPrincipal(tenantScope)
			principal.Permissions = nil
			return principal, nil
		default:
			return Principal{}, errors.New("no session")
		}
	}, HandlerConfig{})

	tests := []struct {
		name      string
		method    string
		path      string
		principal string
		status    int
		code      string
	}{
		{name: "missing authentication", method: http.MethodGet, path: listURL("/v1/jobs"), status: 401, code: "job_authentication_required"},
		{name: "tenant success", method: http.MethodGet, path: listURL("/v1/jobs"), principal: "tenant", status: 200},
		{name: "tenant permission denied", method: http.MethodGet, path: listURL("/v1/jobs"), principal: "tenant-denied", status: 403, code: "job_permission_denied"},
		{name: "platform cannot use tenant route", method: http.MethodGet, path: listURL("/v1/jobs"), principal: "platform", status: 403, code: "job_permission_denied"},
		{name: "tenant cannot use platform route", method: http.MethodGet, path: listURL("/v1/admin/jobs"), principal: "tenant", status: 403, code: "job_permission_denied"},
		{name: "tenant override forbidden", method: http.MethodGet, path: listURL("/v1/jobs") + "&tenant_id=" + tenantID.String(), principal: "tenant", status: 403, code: "job_scope_forbidden"},
		{name: "missing range", method: http.MethodGet, path: "/v1/jobs", principal: "tenant", status: 400, code: "job_invalid_request"},
		{name: "invalid enum", method: http.MethodGet, path: listURL("/v1/jobs") + "&status=unknown", principal: "tenant", status: 400, code: "job_invalid_request"},
		{name: "unknown query", method: http.MethodGet, path: listURL("/v1/jobs") + "&payload=secret", principal: "tenant", status: 400, code: "job_invalid_request"},
		{name: "duplicate query", method: http.MethodGet, path: listURL("/v1/jobs") + "&limit=1&limit=2", principal: "tenant", status: 400, code: "job_invalid_request"},
		{name: "noncanonical uuid", method: http.MethodGet, path: "/v1/jobs/40000000000040008000000000000011", principal: "tenant", status: 400, code: "job_invalid_request"},
		{name: "command method only", method: http.MethodGet, path: "/v1/jobs/40000000-0000-4000-8000-000000000011/retry", principal: "tenant", status: 405, code: "job_method_not_allowed"},
		{name: "read method only", method: http.MethodPost, path: listURL("/v1/jobs"), principal: "tenant", status: 405, code: "job_method_not_allowed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("X-Test-Principal", test.principal)
			request.Header.Set("X-Request-ID", "job-handler-test")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if response.Header().Get("X-Request-ID") != "job-handler-test" || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response headers = %v", response.Header())
			}
			if test.code != "" && errorCode(t, response.Body.Bytes()) != test.code {
				t.Fatalf("body=%s, want code %q", response.Body.String(), test.code)
			}
		})
	}
}

func TestHandlerDetailAttemptsResultsAndSensitiveFieldOmission(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000012")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000012")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000012")
	nodeID := uuid.MustParse("60000000-0000-4000-8000-000000000012")
	completed := fixtureNow
	reader := &fixtureReader{
		jobs: []Job{fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow)},
		attempts: map[uuid.UUID][]Attempt{taskID: {
			{Number: 1, Status: AttemptSucceeded, StartedAt: completed.Add(-3 * time.Second), LastHeartbeatAt: completed.Add(-2 * time.Second), LeaseExpiresAt: completed.Add(time.Second), CompletedAt: &completed},
		}},
		results: map[uuid.UUID][]ItemResult{taskID: {
			{Ordinal: 1, ItemID: "node-1", NodeID: &nodeID, Status: ResultSucceeded, Attempt: 1, Sequence: 1, CompletedAt: &completed},
		}},
	}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		return platformPrincipal(platformScope), nil
	}, HandlerConfig{})
	for _, suffix := range []string{"", "/attempts?limit=1", "/results?limit=1"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
			"/v1/admin/jobs/"+taskID.String()+suffix, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %q status=%d body=%s", suffix, response.Code, response.Body.String())
		}
		body := response.Body.String()
		for _, forbidden := range []string{"payload", "request_digest", "idempotency_key", "worker_id", "lease_id", "password"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("GET %q leaked field %q: %s", suffix, forbidden, body)
			}
		}
	}
}

func TestHandlerUnavailableCancellationTimeoutAndResponseLimit(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000013")
	authenticate := func(*http.Request) (Principal, error) { return platformPrincipal(platformScope), nil }

	unavailable := fixtureHandler(t, &fixtureReader{listErr: errors.New("dial failed password=secret")}, authenticate, HandlerConfig{})
	response := httptest.NewRecorder()
	unavailable.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs"), nil))
	if response.Code != http.StatusServiceUnavailable || errorCode(t, response.Body.Bytes()) != "job_store_unavailable" ||
		strings.Contains(response.Body.String(), "password") || strings.Contains(response.Body.String(), "dial failed") {
		t.Fatalf("unavailable response: status=%d body=%s", response.Code, response.Body.String())
	}

	cancelReader := &fixtureReader{waitForCancel: true, contextDone: make(chan struct{})}
	cancelHandler := fixtureHandler(t, cancelReader, authenticate, HandlerConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response = httptest.NewRecorder()
	cancelHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs"), nil).WithContext(ctx))
	if response.Code != http.StatusRequestTimeout || errorCode(t, response.Body.Bytes()) != "job_request_cancelled" {
		t.Fatalf("cancel response: status=%d body=%s", response.Code, response.Body.String())
	}

	timeoutReader := &fixtureReader{waitForCancel: true}
	timeoutHandler := fixtureHandler(t, timeoutReader, authenticate, HandlerConfig{QueryTimeout: time.Millisecond})
	response = httptest.NewRecorder()
	timeoutHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs"), nil))
	if response.Code != http.StatusGatewayTimeout || errorCode(t, response.Body.Bytes()) != "job_query_timeout" {
		t.Fatalf("timeout response: status=%d body=%s", response.Code, response.Body.String())
	}

	largeReader := &fixtureReader{}
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000013")
	for index := 1; index <= 3; index++ {
		job := fixtureJob(uuid.MustParse("40000000-0000-4000-8000-00000000001"+string(rune('0'+index))), tenantID, StateQueued, fixtureNow.Add(-time.Duration(index)*time.Second))
		job.RelatedResource.Reference = strings.Repeat("x", 512)
		largeReader.jobs = append(largeReader.jobs, job)
	}
	limitHandler := fixtureHandler(t, largeReader, authenticate, HandlerConfig{MaxResponseBytes: 512})
	response = httptest.NewRecorder()
	limitHandler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs")+"&limit=3", nil))
	if response.Code != http.StatusBadGateway || errorCode(t, response.Body.Bytes()) != "job_response_too_large" {
		t.Fatalf("response limit: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerCommandResponseIgnoresReadResponseLimitAfterCommit(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000014")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000014")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000014")
	job := fixtureJob(taskID, tenantID, StateQueued, fixtureNow)
	job.Kind = "a" + strings.Repeat("z", 127)
	job.RelatedResource.Reference = strings.Repeat("r", 512)
	job.RequestID = strings.Repeat("q", 128)
	job.TraceID = strings.Repeat("t", 512)
	reader := &fixtureReader{
		jobs:         []Job{job},
		scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
	}
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}
	handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		return principal, nil
	}, HandlerConfig{MaxResponseBytes: 512})

	for attempt, replayed := range []bool{false, true} {
		request := httptest.NewRequest(http.MethodPost, "/v1/jobs/"+taskID.String()+"/cancel", strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "maximal-command-response")
		request.Header.Set("If-Match", `"1"`)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status=%d body=%s", attempt+1, response.Code, response.Body.String())
		}
		var result CommandResult
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Replayed != replayed || result.Data.TaskID != taskID ||
			result.Data.RelatedResource.Reference != job.RelatedResource.Reference {
			t.Fatalf("attempt %d result=%+v", attempt+1, result)
		}
	}
}

func TestHandlerRejectsEscapedCommandRoutesBeforeStore(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000015")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000015")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000015")
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}

	for _, path := range []string{
		"/v1/jobs/40000000-0000-4000-8000-0000000000%31%35/cancel",
		"/v1/jobs/" + taskID.String() + "/can%63el",
		"/v1/jobs/" + taskID.String() + "/re%74ry",
	} {
		t.Run(path, func(t *testing.T) {
			authenticateCalls := 0
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
			}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				authenticateCalls++
				return principal, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "escaped-command-route")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || errorCode(t, response.Body.Bytes()) != "job_route_not_found" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if authenticateCalls != 0 || reader.commandCalls != 0 {
				t.Fatalf("authenticate calls=%d command calls=%d, want 0/0",
					authenticateCalls, reader.commandCalls)
			}
		})
	}

	for _, test := range []struct {
		operation string
		state     State
	}{
		{operation: "cancel", state: StateQueued},
		{operation: "retry", state: StateFailed},
	} {
		t.Run("canonical "+test.operation, func(t *testing.T) {
			authenticateCalls := 0
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, test.state, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
			}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				authenticateCalls++
				return principal, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodPost,
				"/v1/jobs/"+taskID.String()+"/"+test.operation, strings.NewReader("{}"))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "canonical-"+test.operation)
			request.Header.Set("If-Match", `"1"`)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || authenticateCalls != 1 || reader.commandCalls != 1 {
				t.Fatalf("status=%d body=%s authenticate calls=%d command calls=%d, want 1/1",
					response.Code, response.Body.String(), authenticateCalls, reader.commandCalls)
			}
		})
	}
}

func TestHandlerRejectsAnyCommandQueryBeforeStore(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000016")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000016")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000016")
	principal := tenantPrincipal(scopeID)
	principal.Permissions[PermissionManage] = struct{}{}

	for _, test := range []struct {
		name       string
		rawQuery   string
		forceQuery bool
	}{
		{name: "malformed percent", rawQuery: "force=%zz"},
		{name: "invalid semicolon", rawQuery: ";"},
		{name: "bare question mark", forceQuery: true},
		{name: "valid nonempty", rawQuery: "force=true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticateCalls := 0
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
			}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				authenticateCalls++
				return principal, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodPost,
				"/v1/jobs/"+taskID.String()+"/cancel", strings.NewReader("{}"))
			request.URL.RawQuery = test.rawQuery
			request.URL.ForceQuery = test.forceQuery
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "invalid-command-query")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || errorCode(t, response.Body.Bytes()) != "job_invalid_request" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if authenticateCalls != 1 || reader.commandCalls != 0 {
				t.Fatalf("authenticate calls=%d command calls=%d, want 1/0",
					authenticateCalls, reader.commandCalls)
			}
		})
	}
}

func TestHandlerSettlementHistoryAndPlatformReplayRoutes(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000040")
	tenantScope := uuid.MustParse("20000000-0000-4000-8000-000000000040")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000040")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000040")
	failed := fixtureJob(taskID, tenantID, StateFailed, fixtureNow)
	failed.Attempt = failed.MaxAttempts
	reader := &fixtureReader{
		jobs:         []Job{failed},
		scopeTenants: map[uuid.UUID]uuid.UUID{tenantScope: tenantID},
	}

	for _, suffix := range []string{"receipts", "dead-letters"} {
		response := httptest.NewRecorder()
		fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
			return platformPrincipal(platformScope), nil
		}, HandlerConfig{}).ServeHTTP(response, httptest.NewRequest(
			http.MethodGet, "/v1/admin/jobs/"+taskID.String()+"/"+suffix, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s, want 200", suffix, response.Code, response.Body.String())
		}
	}

	tenantReplay := httptest.NewRecorder()
	fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		principal := tenantPrincipal(tenantScope)
		principal.Permissions[PermissionManage] = struct{}{}
		return principal, nil
	}, HandlerConfig{}).ServeHTTP(tenantReplay, commandRequest(
		"/v1/jobs/"+taskID.String()+"/replay", "tenant-replay-denied"))
	if tenantReplay.Code != http.StatusNotFound || reader.commandCalls != 0 {
		t.Fatalf("tenant replay status=%d body=%s calls=%d, want 404/0",
			tenantReplay.Code, tenantReplay.Body.String(), reader.commandCalls)
	}

	platformReplay := httptest.NewRecorder()
	fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
		principal := platformPrincipal(platformScope)
		principal.Permissions[PermissionManageAll] = struct{}{}
		return principal, nil
	}, HandlerConfig{}).ServeHTTP(platformReplay, commandRequest(
		"/v1/admin/jobs/"+taskID.String()+"/replay", "platform-replay"))
	if platformReplay.Code != http.StatusOK || reader.commandCalls != 1 {
		t.Fatalf("platform replay status=%d body=%s calls=%d, want 200/1",
			platformReplay.Code, platformReplay.Body.String(), reader.commandCalls)
	}
}

func commandRequest(path, idempotencyKey string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	request.Header.Set("If-Match", `"1"`)
	return request
}

func TestHandlerRejectsMalformedReadQueriesBeforeStore(t *testing.T) {
	scopeID := uuid.MustParse("20000000-0000-4000-8000-000000000017")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000017")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000017")
	principal := tenantPrincipal(scopeID)
	canonicalListQuery := strings.TrimPrefix(listURL(""), "?")

	for _, test := range []struct {
		name       string
		path       string
		rawQuery   string
		forceQuery bool
		status     int
		storeCalls int
	}{
		{name: "malformed detail percent", path: "/v1/jobs/" + taskID.String(), rawQuery: "force=%zz", status: http.StatusBadRequest},
		{name: "malformed list fragment", path: "/v1/jobs", rawQuery: canonicalListQuery + "&fragment=%zz", status: http.StatusBadRequest},
		{name: "malformed attempts semicolon", path: "/v1/jobs/" + taskID.String() + "/attempts", rawQuery: ";", status: http.StatusBadRequest},
		{name: "malformed results bare question", path: "/v1/jobs/" + taskID.String() + "/results", forceQuery: true, status: http.StatusBadRequest},
		{name: "canonical detail", path: "/v1/jobs/" + taskID.String(), status: http.StatusOK, storeCalls: 1},
		{name: "canonical list", path: "/v1/jobs", rawQuery: canonicalListQuery, status: http.StatusOK, storeCalls: 1},
		{name: "canonical attempts", path: "/v1/jobs/" + taskID.String() + "/attempts", status: http.StatusOK, storeCalls: 2},
		{name: "canonical results", path: "/v1/jobs/" + taskID.String() + "/results", rawQuery: "limit=1", status: http.StatusOK, storeCalls: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			authenticateCalls := 0
			reader := &fixtureReader{
				jobs:         []Job{fixtureJob(taskID, tenantID, StateQueued, fixtureNow)},
				scopeTenants: map[uuid.UUID]uuid.UUID{scopeID: tenantID},
			}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				authenticateCalls++
				return principal, nil
			}, HandlerConfig{})
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			request.URL.RawQuery = test.rawQuery
			request.URL.ForceQuery = test.forceQuery
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), test.status)
			}
			if test.status == http.StatusBadRequest && errorCode(t, response.Body.Bytes()) != "job_invalid_request" {
				t.Fatalf("body=%s", response.Body.String())
			}
			if authenticateCalls != 1 || reader.callCount() != test.storeCalls {
				t.Fatalf("authenticate calls=%d store calls=%d, want 1/%d",
					authenticateCalls, reader.callCount(), test.storeCalls)
			}
		})
	}
}

func TestHandlerRejectsInvalidStoredAttemptAndResultFacts(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000023")
	tenantID := uuid.MustParse("30000000-0000-4000-8000-000000000023")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000023")
	authenticate := func(*http.Request) (Principal, error) { return platformPrincipal(platformScope), nil }

	badJob := fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow)
	badJob.MaxAttempts = maximumJobAttempts + 1
	response := httptest.NewRecorder()
	fixtureHandler(t, &fixtureReader{jobs: []Job{badJob}}, authenticate, HandlerConfig{}).ServeHTTP(
		response, httptest.NewRequest(http.MethodGet, listURL("/v1/admin/jobs"), nil))
	if response.Code != http.StatusBadGateway || errorCode(t, response.Body.Bytes()) != "job_store_invalid_response" {
		t.Fatalf("max attempts response: status=%d body=%s", response.Code, response.Body.String())
	}

	zero := time.Time{}
	reader := &fixtureReader{
		jobs: []Job{fixtureJob(taskID, tenantID, StateSucceeded, fixtureNow)},
		results: map[uuid.UUID][]ItemResult{taskID: {{
			Ordinal: 1, ItemID: "item-1", Status: ResultSucceeded, Attempt: 1, Sequence: 1, CompletedAt: &zero,
		}}},
	}
	response = httptest.NewRecorder()
	fixtureHandler(t, reader, authenticate, HandlerConfig{}).ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/v1/admin/jobs/"+taskID.String()+"/results", nil))
	if response.Code != http.StatusBadGateway || errorCode(t, response.Body.Bytes()) != "job_store_invalid_response" {
		t.Fatalf("zero completed_at response: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsBoundChildCursorMisuseBeforeReader(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000024")
	otherScope := uuid.MustParse("10000000-0000-4000-8000-000000000025")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000024")
	otherTaskID := uuid.MustParse("40000000-0000-4000-8000-000000000025")
	scope := cursorScope{Kind: ScopePlatform, ID: platformScope}
	codec := fixtureCursorCodec()
	attempt := func(value attemptCursor) string {
		encoded, err := codec.encode("attempts", value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	result := func(value resultCursor) string {
		encoded, err := codec.encode("results", value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	validAttempt := attempt(attemptCursor{
		Version: cursorVersion, Endpoint: "attempts", Scope: scope, TaskID: taskID, Attempt: 2,
	})
	validResult := result(resultCursor{
		Version: cursorVersion, Endpoint: "results", Scope: scope, TaskID: taskID, Ordinal: 2,
	})
	wrongKeyCodec, err := newCursorCodec(ServiceConfig{
		ActiveCursorKeyID: fixtureCursorKeyID,
		CursorKeys: map[string][]byte{
			fixtureCursorKeyID: []byte("abcdef0123456789abcdef0123456789"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyAttempt, err := wrongKeyCodec.encode("attempts", attemptCursor{
		Version: cursorVersion, Endpoint: "attempts", Scope: scope, TaskID: taskID, Attempt: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	tamper := func(cursor string) string {
		replacement := byte('A')
		if cursor[len(cursor)-1] == replacement {
			replacement = 'B'
		}
		return cursor[:len(cursor)-1] + string(replacement)
	}
	semanticAttemptTamper := rewriteCursorPayload(t, validAttempt, func(cursor *attemptCursor) {
		cursor.Attempt++
	})
	semanticOrdinalTamper := rewriteCursorPayload(t, validResult, func(cursor *resultCursor) {
		cursor.Ordinal++
	})
	unknownVersion := rewriteCursorEnvelope(t, validAttempt, func(envelope *cursorEnvelope) {
		envelope.Version++
	})
	unknownKeyID := rewriteCursorEnvelope(t, validAttempt, func(envelope *cursorEnvelope) {
		envelope.KeyID = "unknown"
	})
	malformedPayload := rewriteCursorEnvelope(t, validAttempt, func(envelope *cursorEnvelope) {
		envelope.Payload = "*"
	})
	malformedMAC := rewriteCursorEnvelope(t, validAttempt, func(envelope *cursorEnvelope) {
		envelope.MAC = "*"
	})
	tests := []struct {
		name     string
		endpoint string
		cursor   string
	}{
		{name: "attempt cross scope", endpoint: "attempts", cursor: attempt(attemptCursor{Version: cursorVersion, Endpoint: "attempts", Scope: cursorScope{Kind: ScopePlatform, ID: otherScope}, TaskID: taskID, Attempt: 2})},
		{name: "attempt cross endpoint", endpoint: "attempts", cursor: validResult},
		{name: "attempt cross task", endpoint: "attempts", cursor: attempt(attemptCursor{Version: cursorVersion, Endpoint: "attempts", Scope: scope, TaskID: otherTaskID, Attempt: 2})},
		{name: "attempt tamper", endpoint: "attempts", cursor: tamper(validAttempt)},
		{name: "attempt semantic rewrite", endpoint: "attempts", cursor: semanticAttemptTamper},
		{name: "unknown envelope version", endpoint: "attempts", cursor: unknownVersion},
		{name: "unknown key id", endpoint: "attempts", cursor: unknownKeyID},
		{name: "wrong key", endpoint: "attempts", cursor: wrongKeyAttempt},
		{name: "malformed envelope", endpoint: "attempts", cursor: base64.RawURLEncoding.EncodeToString([]byte("{"))},
		{name: "malformed payload", endpoint: "attempts", cursor: malformedPayload},
		{name: "malformed mac", endpoint: "attempts", cursor: malformedMAC},
		{name: "attempt overlong", endpoint: "attempts", cursor: strings.Repeat("a", maximumCursorLen+1)},
		{name: "result cross scope", endpoint: "results", cursor: result(resultCursor{Version: cursorVersion, Endpoint: "results", Scope: cursorScope{Kind: ScopePlatform, ID: otherScope}, TaskID: taskID, Ordinal: 2})},
		{name: "result cross endpoint", endpoint: "results", cursor: validAttempt},
		{name: "result cross task", endpoint: "results", cursor: result(resultCursor{Version: cursorVersion, Endpoint: "results", Scope: scope, TaskID: otherTaskID, Ordinal: 2})},
		{name: "result tamper", endpoint: "results", cursor: tamper(validResult)},
		{name: "result semantic rewrite", endpoint: "results", cursor: semanticOrdinalTamper},
		{name: "result overlong", endpoint: "results", cursor: strings.Repeat("a", maximumCursorLen+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fixtureReader{}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				return platformPrincipal(platformScope), nil
			}, HandlerConfig{})
			path := "/v1/admin/jobs/" + taskID.String() + "/" + test.endpoint + "?cursor=" + url.QueryEscape(test.cursor)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusBadRequest || errorCode(t, response.Body.Bytes()) != "job_invalid_request" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if calls := reader.callCount(); calls != 0 {
				t.Fatalf("Reader calls=%d, want 0", calls)
			}
		})
	}
}

func TestHandlerRejectsSemanticListCursorRewriteBeforeReader(t *testing.T) {
	platformScope := uuid.MustParse("10000000-0000-4000-8000-000000000026")
	taskID := uuid.MustParse("40000000-0000-4000-8000-000000000026")
	codec := fixtureCursorCodec()
	valid, err := codec.encode("jobs", listCursor{
		Version: cursorVersion, Endpoint: "jobs",
		Scope: cursorScope{Kind: ScopePlatform, ID: platformScope},
		From:  fixtureNow.Add(-time.Hour), To: fixtureNow.Add(time.Hour),
		CreatedAt: fixtureNow, TaskID: taskID,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		cursor string
	}{
		{
			name: "created_at rewrite",
			cursor: rewriteCursorPayload(t, valid, func(cursor *listCursor) {
				cursor.CreatedAt = cursor.CreatedAt.Add(-time.Second)
			}),
		},
		{
			name: "task pagination key rewrite",
			cursor: rewriteCursorPayload(t, valid, func(cursor *listCursor) {
				cursor.TaskID = uuid.MustParse("40000000-0000-4000-8000-000000000027")
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fixtureReader{}
			handler := fixtureHandler(t, reader, func(*http.Request) (Principal, error) {
				return platformPrincipal(platformScope), nil
			}, HandlerConfig{})
			path := listURL("/v1/admin/jobs") + "&cursor=" + url.QueryEscape(test.cursor)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusBadRequest || errorCode(t, response.Body.Bytes()) != "job_invalid_request" {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if calls := reader.callCount(); calls != 0 {
				t.Fatalf("Reader calls=%d, want 0", calls)
			}
		})
	}
}

func rewriteCursorPayload[T any](t *testing.T, encoded string, rewrite func(*T)) string {
	t.Helper()
	return rewriteCursorEnvelope(t, encoded, func(envelope *cursorEnvelope) {
		payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		var cursor T
		if err := json.Unmarshal(payload, &cursor); err != nil {
			t.Fatal(err)
		}
		rewrite(&cursor)
		payload, err = json.Marshal(cursor)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Payload = base64.RawURLEncoding.EncodeToString(payload)
	})
}

func rewriteCursorEnvelope(t *testing.T, encoded string, rewrite func(*cursorEnvelope)) string {
	t.Helper()
	envelopeJSON, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var envelope cursorEnvelope
	if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
		t.Fatal(err)
	}
	rewrite(&envelope)
	envelopeJSON, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(envelopeJSON)
}

func fixtureHandler(t *testing.T, reader *fixtureReader, authenticate AuthenticateFunc, config HandlerConfig) *Handler {
	t.Helper()
	service, err := NewService(reader, fixtureServiceConfig())
	if err != nil {
		t.Fatal(err)
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler, err := NewHandler(service, authenticate, config)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func listURL(base string) string {
	query := url.Values{}
	query.Set("from", fixtureNow.Add(-time.Hour).Format(time.RFC3339))
	query.Set("to", fixtureNow.Add(time.Hour).Format(time.RFC3339))
	return base + "?" + query.Encode()
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var envelope errorEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode error body: %v: %s", err, body)
	}
	return envelope.Error.Code
}
