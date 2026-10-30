package analyticslog

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type unreadRequestBody struct {
	reads *atomic.Int64
}

func (body unreadRequestBody) Read([]byte) (int, error) {
	body.reads.Add(1)
	return 0, io.EOF
}

func (unreadRequestBody) Close() error { return nil }

func TestGETRoutesRejectBodiesBeforeDependencies(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()

	var authenticationCalls atomic.Int64
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(request *http.Request) (Principal, error) {
		authenticationCalls.Add(1)
		if strings.HasPrefix(request.URL.Path, "/v1/admin/") {
			return Principal{ID: siteA, ScopeKind: "platform"}, nil
		}
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}, authorizer, time.Second)

	query := queryValues(now.Add(-time.Hour), now)
	platformQuery := queryValues(now.Add(-time.Hour), now)
	platformQuery.Set("tenant_id", tenantA)
	routes := []struct {
		name   string
		path   string
		values url.Values
	}{
		{name: "tenant_access", path: "/v1/analytics/logs/access", values: query},
		{name: "platform_access", path: "/v1/admin/analytics/logs/access", values: platformQuery},
		{name: "tenant_block_events", path: "/v1/analytics/logs/block-events", values: query},
		{name: "platform_block_events", path: "/v1/admin/analytics/logs/block-events", values: platformQuery},
		{name: "tenant_current", path: "/v1/analytics/logs/blocks/current"},
		{name: "platform_current", path: "/v1/admin/analytics/logs/blocks/current", values: url.Values{"tenant_id": {tenantA}}},
		{name: "tenant_history", path: "/v1/analytics/logs/blocks/history"},
		{name: "platform_history", path: "/v1/admin/analytics/logs/blocks/history", values: url.Values{"tenant_id": {tenantA}}},
	}
	for _, route := range routes {
		for _, bodyKind := range []string{"known_1_mib", "chunked_unknown"} {
			t.Run(route.name+"_"+bodyKind, func(t *testing.T) {
				target := route.path
				if route.values != nil {
					target += "?" + route.values.Encode()
				}
				var reads atomic.Int64
				request := httptest.NewRequest(http.MethodGet, target, nil)
				request.Body = unreadRequestBody{reads: &reads}
				if bodyKind == "known_1_mib" {
					request.ContentLength = 1 << 20
				} else {
					request.ContentLength = -1
					request.TransferEncoding = []string{"chunked"}
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
				if reads.Load() != 0 {
					t.Fatalf("request body was read %d times", reads.Load())
				}
			})
		}
	}
	if authenticationCalls.Load() != 0 || len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("body reached dependencies: authentication=%d authorization=%d storage=%d",
			authenticationCalls.Load(), len(authorizer.calls()), storageCalls.Load())
	}
}

func TestLowLevelHandlerRejectsBodyBeforeAuthentication(t *testing.T) {
	store := &recordingStore{}
	var authenticationCalls atomic.Int64
	handler := newTestHandlerWithAuth(t, store, func(*http.Request) (Actor, error) {
		authenticationCalls.Add(1)
		return Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}, nil
	}, HandlerConfig{})
	var reads atomic.Int64
	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/blocks/history", nil)
	request.Body = unreadRequestBody{reads: &reads}
	request.ContentLength = -1
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
	if reads.Load() != 0 || authenticationCalls.Load() != 0 || store.accessCalls != 0 || store.blockCalls != 0 {
		t.Fatalf("body reached low-level dependencies: reads=%d authentication=%d access=%d block=%d",
			reads.Load(), authenticationCalls.Load(), store.accessCalls, store.blockCalls)
	}
}

func TestZonedClientIPRejectedBeforeAuthorizationAndStorage(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}, authorizer, time.Second)
	values := queryValues(now.Add(-time.Hour), now)
	values.Set("client_ip", "fe80::1%en0")

	assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/access", values, "zoned-ip"),
		http.StatusBadRequest, "analytics_logs_invalid_request")
	if len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("zoned address reached dependencies: authorization=%d storage=%d",
			len(authorizer.calls()), storageCalls.Load())
	}
}

func TestBlockEventRoutesQueryClickHouseAndFailClosed(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		storageCalls.Add(1)
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		for _, required := range []string{
			"FROM security_event_query_index_state_v1", "FROM security_event_query_payload_state_v1",
			"argMaxMerge(latest_filter_state)", "argMaxMerge(latest_payload_state)",
			"uniqExactMerge(version_pair_state)",
		} {
			if !strings.Contains(query, required) {
				t.Errorf("security route query missing %q: %s", required, body)
			}
		}
		for _, forbidden := range []string{"FROM security_events", "FROM security_version_evidence_v1"} {
			if strings.Contains(query, forbidden) {
				t.Errorf("security route query contains raw path %q: %s", forbidden, body)
			}
		}
		rows := []blockEventRow{
			{EventID: "security-c", OccurredAtMS: now.Add(-time.Minute).UnixMilli()},
			{EventID: "security-b", OccurredAtMS: now.Add(-2 * time.Minute).UnixMilli()},
			{EventID: "security-a", OccurredAtMS: now.Add(-3 * time.Minute).UnixMilli()},
		}
		for index := range rows {
			rows[index].SnapshotMS = now.UnixMilli()
			rows[index].SiteID = siteA
			rows[index].NodeID = nodeA
			rows[index].RequestID = requiredString(rows[index].EventID + "-request")
			rows[index].TraceID = requiredString(rows[index].EventID + "-trace")
			rows[index].ConfigVersion = requiredString(configA)
			rows[index].Host = "example.test"
			rows[index].URIPath = "/blocked"
			rows[index].ClientIP = "2001:db8::1"
			rows[index].CountryCode = "CN"
			rows[index].Carrier = "carrier-a"
			rows[index].EventType = "waf"
			rows[index].Action = "block"
			rows[index].Severity = "high"
			rows[index].RuleID = "rule-a"
			rows[index].StatusCode = 403
			rows[index].VersionCount = 1
			_ = json.NewEncoder(writer).Encode(rows[index])
		}
	}))
	defer server.Close()

	t.Run("tenant_and_platform", func(t *testing.T) {
		tenantAuthorizer := &recordingAuthorizer{}
		tenantHandler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, tenantAuthorizer, time.Second)
		tenantValues := queryValues(now.Add(-time.Hour), now)
		tenantValues.Set("limit", "2")
		tenantResponse := doFactoryGET(tenantHandler, "/v1/analytics/logs/block-events",
			tenantValues, "tenant-block-events")
		var tenantPage blockEventResponse
		if tenantResponse.Code != http.StatusOK || json.Unmarshal(tenantResponse.Body.Bytes(), &tenantPage) != nil ||
			len(tenantPage.Data) != 2 || tenantPage.Data[0].EventID != "security-c" ||
			tenantPage.Data[1].EventID != "security-b" || tenantPage.Meta.NextCursor == "" ||
			tenantPage.Meta.SnapshotAt != "2026-07-23T12:00:00Z" ||
			tenantPage.Meta.Consistency != "snapshot" ||
			tenantPage.Meta.ReplacementConsistency != "latest_event_id_at_snapshot" ||
			tenantPage.Meta.Pagination != "keyset" {
			t.Fatalf("tenant block-events status=%d body=%s", tenantResponse.Code, tenantResponse.Body.String())
		}

		platformAuthorizer := &recordingAuthorizer{}
		platformHandler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "platform"}, nil
		}, platformAuthorizer, time.Second)
		values := queryValues(now.Add(-time.Hour), now)
		values.Set("tenant_id", tenantB)
		values.Set("limit", "2")
		platformResponse := doFactoryGET(platformHandler, "/v1/admin/analytics/logs/block-events",
			values, "platform-block-events")
		var platformPage blockEventResponse
		if platformResponse.Code != http.StatusOK || json.Unmarshal(platformResponse.Body.Bytes(), &platformPage) != nil ||
			len(platformPage.Data) != 2 || platformPage.Data[0].EventID != "security-c" ||
			platformPage.Data[1].EventID != "security-b" || platformPage.Meta.NextCursor == "" ||
			platformPage.Meta.SnapshotAt != "2026-07-23T12:00:00Z" ||
			platformPage.Meta.Consistency != "snapshot" ||
			platformPage.Meta.ReplacementConsistency != "latest_event_id_at_snapshot" ||
			platformPage.Meta.Pagination != "keyset" {
			t.Fatalf("platform block-events status=%d body=%s", platformResponse.Code, platformResponse.Body.String())
		}
		tenantAuthorizations := tenantAuthorizer.calls()
		platformAuthorizations := platformAuthorizer.calls()
		if len(tenantAuthorizations) != 1 || tenantAuthorizations[0] != (AuthorizationRequest{
			Permission: ReadPermission, Audience: AudienceTenant, TenantID: tenantA,
		}) || len(platformAuthorizations) != 1 || platformAuthorizations[0] != (AuthorizationRequest{
			Permission: ReadPermission, Audience: AudiencePlatform, TenantID: tenantB,
		}) {
			t.Fatalf("authorizations: tenant=%#v platform=%#v", tenantAuthorizations, platformAuthorizations)
		}
	})

	t.Run("authentication_and_dependency_errors", func(t *testing.T) {
		values := queryValues(now.Add(-time.Hour), now)
		unauthAuthorizer := &recordingAuthorizer{}
		unauthenticated := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{}, errors.New("private authentication detail")
		}, unauthAuthorizer, time.Second)
		assertHandlerError(t, doFactoryGET(unauthenticated, "/v1/analytics/logs/block-events", values,
			"block-authentication"), http.StatusUnauthorized, "analytics_logs_authentication_required")
		if len(unauthAuthorizer.calls()) != 0 {
			t.Fatal("authentication failure reached authorizer")
		}

		for _, test := range []struct {
			name   string
			err    error
			status int
			code   string
		}{
			{name: "permission_denied", err: ErrPermissionDenied, status: http.StatusForbidden, code: "analytics_logs_permission_denied"},
			{name: "unavailable", err: errors.New("private authorization detail"), status: http.StatusServiceUnavailable, code: "analytics_logs_unavailable"},
			{name: "timeout", err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "analytics_logs_query_timeout"},
		} {
			t.Run(test.name, func(t *testing.T) {
				authorizer := &recordingAuthorizer{}
				authorizer.setError(test.err)
				handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
					return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
				}, authorizer, time.Second)
				assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/block-events", values,
					"block-dependency"), test.status, test.code)
			})
		}

		notFoundAuthorizer := &recordingAuthorizer{}
		notFound := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, notFoundAuthorizer, time.Second)
		response := doFactoryGET(notFound, "/v1/analytics/logs/missing", nil, "block-not-found")
		assertHandlerError(t, response, http.StatusNotFound, "analytics_logs_route_not_found")
		if response.Header().Get("X-Request-ID") != "block-not-found" || len(notFoundAuthorizer.calls()) != 0 {
			t.Fatalf("not-found request id=%q authorizations=%d",
				response.Header().Get("X-Request-ID"), len(notFoundAuthorizer.calls()))
		}

		var authenticationCalls atomic.Int64
		methodAuthorizer := &recordingAuthorizer{}
		methodNotFound := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			authenticationCalls.Add(1)
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, methodAuthorizer, time.Second)
		request := httptest.NewRequest(http.MethodPost, "/v1/analytics/logs/block-events", nil)
		request.Header.Set("X-Request-ID", "block-method-not-found")
		methodResponse := httptest.NewRecorder()
		methodNotFound.ServeHTTP(methodResponse, request)
		assertHandlerError(t, methodResponse, http.StatusNotFound, "analytics_logs_route_not_found")
		if authenticationCalls.Load() != 0 || len(methodAuthorizer.calls()) != 0 || storageCalls.Load() != 2 {
			t.Fatalf("method not-found reached dependencies: authentication=%d authorization=%d storage=%d",
				authenticationCalls.Load(), len(methodAuthorizer.calls()), storageCalls.Load())
		}

		scopeAuthorizer := &recordingAuthorizer{}
		scopeHandler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, scopeAuthorizer, time.Second)
		scopeValues := queryValues(now.Add(-time.Hour), now)
		scopeValues.Set("tenant_id", tenantB)
		assertHandlerError(t, doFactoryGET(scopeHandler, "/v1/analytics/logs/block-events", scopeValues,
			"block-scope"), http.StatusForbidden, "analytics_logs_scope_forbidden")
		if len(scopeAuthorizer.calls()) != 0 || storageCalls.Load() != 2 {
			t.Fatalf("scope failure reached dependencies: authorization=%d storage=%d",
				len(scopeAuthorizer.calls()), storageCalls.Load())
		}
	})
	if storageCalls.Load() != 2 {
		t.Fatalf("block-events ClickHouse calls=%d want=2", storageCalls.Load())
	}
}
