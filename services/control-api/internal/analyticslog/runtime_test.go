package analyticslog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
)

type recordingAuthorizer struct {
	mu       sync.Mutex
	err      error
	requests []AuthorizationRequest
}

type recordingRoundTripper struct {
	calls atomic.Int64
}

func TestIAMAuthorizationErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "invalid credential", err: iamlock.ErrInvalidCredential, want: errAuthenticationRequired},
		{name: "permission denied", err: iamlock.ErrPermissionDenied, want: ErrPermissionDenied},
		{name: "unavailable", err: iamlock.ErrUnavailable, want: ErrStorageUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := (*iamAuthorizer)(nil).authorizationError(context.Background(), test.err)
			if !errors.Is(got, test.want) {
				t.Fatalf("authorization error=%v want=%v", got, test.want)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := (*iamAuthorizer)(nil).authorizationError(ctx, iamlock.ErrInvalidCredential); !errors.Is(got, context.Canceled) {
		t.Fatalf("canceled authorization error=%v want=%v", got, context.Canceled)
	}
}

func (transport *recordingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("mutable default transport was used")
}

func (authorizer *recordingAuthorizer) AuthorizeAnalyticsLogRead(
	_ context.Context,
	_ Principal,
	request AuthorizationRequest,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.requests = append(authorizer.requests, request)
	return authorizer.err
}

func (authorizer *recordingAuthorizer) setError(err error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.err = err
}

func (authorizer *recordingAuthorizer) calls() []AuthorizationRequest {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	return append([]AuthorizationRequest(nil), authorizer.requests...)
}

func TestHTTPFactoryFailsClosedOnMissingOrInconsistentDependencies(t *testing.T) {
	validConfig := HTTPConfig{
		Client:  ClientConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", CursorKeyring: testLogCursorKeyring()},
		Handler: HandlerConfig{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
	}
	authenticate := func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}
	authorizer := &recordingAuthorizer{}

	for name, dependencies := range map[string]handlerDependencies{
		"missing_authenticator": {Authorizer: authorizer},
		"missing_authorizer":    {Authenticate: authenticate},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newHTTPHandler(validConfig, dependencies); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}

	invalidTimeouts := validConfig
	invalidTimeouts.Client.QueryTimeout = 5 * time.Second
	invalidTimeouts.Handler.QueryTimeout = 5 * time.Second
	if _, err := newHTTPHandler(invalidTimeouts, handlerDependencies{
		Authenticate: authenticate, Authorizer: authorizer,
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("equal timeout error=%v", err)
	}

	invalidLimits := validConfig
	invalidLimits.Client.MaxResponseBytes = 1024
	invalidLimits.Handler.MaxResponseBytes = 2048
	if _, err := newHTTPHandler(invalidLimits, handlerDependencies{
		Authenticate: authenticate, Authorizer: authorizer,
	}); !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("response limit error=%v", err)
	}
}

func TestHTTPFactoryRejectsTypedNilAuthorizer(t *testing.T) {
	var authorizer *recordingAuthorizer
	handler, err := newHTTPHandler(HTTPConfig{
		Client: ClientConfig{Endpoint: "http://127.0.0.1:8123", Database: "analytics", CursorKeyring: testLogCursorKeyring()},
	}, handlerDependencies{
		Authenticate: func(*http.Request) (Principal, error) { return Principal{}, nil },
		Authorizer:   authorizer,
	})
	if handler != nil || !errors.Is(err, ErrInvalidConfiguration) {
		t.Fatalf("newHTTPHandler() = (%T, %v), want nil invalid configuration", handler, err)
	}
}

func TestHTTPFactoryQueriesAccessAndBlockEventsOverNetwork(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.URL.Query().Get("param_tenant_id") != tenantA {
			t.Errorf("tenant parameter=%q", request.URL.Query().Get("param_tenant_id"))
		}
		body, _ := io.ReadAll(request.Body)
		query := string(body)
		if strings.Contains(query, tenantA) || strings.Contains(query, "tenant_id=") {
			t.Errorf("scope was interpolated into SQL: %s", body)
		}
		if strings.Contains(query, "FROM security_event_query_index_state_v1") {
			if !strings.Contains(query, "FROM security_event_query_payload_state_v1") {
				t.Errorf("security query lost bounded payload state: %s", body)
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
			return
		}
		if !strings.Contains(query, "FROM access_event_query_index_state_v1") ||
			!strings.Contains(query, "FROM access_event_query_payload_state_v1") {
			t.Errorf("access query lost state authority: %s", body)
		}
		for index, eventID := range []string{"event-c", "event-b", "event-a"} {
			row := accessTestRow(eventID, now.Add(-time.Duration(index+1)*time.Minute), "/asset.js")
			row.SnapshotMS = now.UnixMilli()
			_ = json.NewEncoder(writer).Encode(row)
		}
	}))
	defer server.Close()

	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}, authorizer, 500*time.Millisecond)
	values := queryValues(now.Add(-time.Hour), now)
	values.Set("site_id", siteA)
	values.Set("node_id", nodeA)
	values.Set("limit", "2")

	access := doFactoryGET(handler, "/v1/analytics/logs/access", values, "runtime-request-a")
	var accessPage accessResponse
	if access.Code != http.StatusOK || json.Unmarshal(access.Body.Bytes(), &accessPage) != nil ||
		len(accessPage.Data) != 2 || accessPage.Data[0].EventID != "event-c" || accessPage.Meta.NextCursor == "" ||
		accessPage.Meta.Pagination != "keyset" {
		t.Fatalf("access status=%d body=%s", access.Code, access.Body.String())
	}
	block := doFactoryGET(handler, "/v1/analytics/logs/block-events", values, "runtime-request-b")
	var blockPage blockEventResponse
	if block.Code != http.StatusOK || json.Unmarshal(block.Body.Bytes(), &blockPage) != nil ||
		len(blockPage.Data) != 2 || blockPage.Data[0].EventID != "security-c" || blockPage.Meta.NextCursor == "" ||
		blockPage.Meta.SnapshotAt != "2026-07-23T12:00:00Z" || blockPage.Meta.Consistency != "snapshot" ||
		blockPage.Meta.ReplacementConsistency != "latest_event_id_at_snapshot" || blockPage.Meta.Pagination != "keyset" ||
		block.Header().Get("Content-Type") != "application/json" ||
		block.Header().Get("X-Request-ID") != "runtime-request-b" || block.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("block status=%d body=%s", block.Code, block.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("storage calls=%d", calls.Load())
	}
	authorizations := authorizer.calls()
	if len(authorizations) != 2 {
		t.Fatalf("authorizations=%#v", authorizations)
	}
	wantAuthorization := AuthorizationRequest{
		Permission: ReadPermission, Audience: AudienceTenant, TenantID: tenantA, SiteID: siteA, NodeID: nodeA,
	}
	for _, authorization := range authorizations {
		if authorization != wantAuthorization {
			t.Fatalf("authorization=%#v want=%#v all=%#v", authorization, wantAuthorization, authorizations)
		}
	}

	mismatchedValues := queryValues(now.Add(-time.Hour), now)
	mismatchedValues.Set("site_id", tenantB)
	mismatchedValues.Set("node_id", nodeA)
	mismatchedValues.Set("limit", "2")
	mismatchedValues.Set("cursor", accessPage.Meta.NextCursor)
	assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/access", mismatchedValues,
		"runtime-cursor-mismatch"), http.StatusBadRequest, "analytics_logs_invalid_request")
	if calls.Load() != 2 {
		t.Fatalf("cursor mismatch reached storage: calls=%d", calls.Load())
	}
}

func TestHTTPFactoryPlatformScopeUsesExplicitTenant(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("param_tenant_id") != tenantB {
			t.Errorf("tenant parameter=%q", request.URL.Query().Get("param_tenant_id"))
		}
		_ = json.NewEncoder(writer).Encode(accessTestRow("platform-event", now.Add(-time.Minute), "/platform"))
	}))
	defer server.Close()
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "platform"}, nil
	}, authorizer, time.Second)
	values := queryValues(now.Add(-time.Hour), now)
	values.Set("tenant_id", strings.ToUpper(tenantB))

	response := doFactoryGET(handler, "/v1/admin/analytics/logs/access", values, "platform-request")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"event_id":"platform-event"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	authorizations := authorizer.calls()
	if len(authorizations) != 1 || authorizations[0].Audience != AudiencePlatform ||
		authorizations[0].TenantID != tenantB {
		t.Fatalf("authorizations=%#v", authorizations)
	}
}

func TestHTTPFactoryAuthenticationAuthorizationAndScopeFailClosed(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()

	t.Run("unauthorized", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{}, errors.New("bearer secret detail")
		}, authorizer, time.Second)
		response := doFactoryGET(handler, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now), "request-unauth")
		assertHandlerError(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
		if strings.Contains(response.Body.String(), "secret") || len(authorizer.calls()) != 0 {
			t.Fatalf("unauthorized detail/call leaked: body=%s calls=%#v", response.Body.String(), authorizer.calls())
		}
	})

	t.Run("live_revocation", func(t *testing.T) {
		var liveStorageCalls atomic.Int64
		liveServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			liveStorageCalls.Add(1)
		}))
		defer liveServer.Close()
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, liveServer, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		values := queryValues(now.Add(-time.Hour), now)
		allowed := doFactoryGET(handler, "/v1/analytics/logs/access", values, "request-allowed")
		if allowed.Code != http.StatusOK {
			t.Fatalf("allowed status=%d body=%s", allowed.Code, allowed.Body.String())
		}
		authorizer.setError(ErrPermissionDenied)
		response := doFactoryGET(handler, "/v1/analytics/logs/access", values, "request-denied")
		assertHandlerError(t, response, http.StatusForbidden, "analytics_logs_permission_denied")
		if len(authorizer.calls()) != 2 || liveStorageCalls.Load() != 1 {
			t.Fatalf("authorizer calls=%#v storage=%d", authorizer.calls(), liveStorageCalls.Load())
		}
	})

	t.Run("authorization_unavailable", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		authorizer.setError(errors.New("postgres password=authorization-secret"))
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		response := doFactoryGET(handler, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now), "request-authz-error")
		assertHandlerError(t, response, http.StatusServiceUnavailable, "analytics_logs_unavailable")
		if strings.Contains(response.Body.String(), "authorization-secret") {
			t.Fatalf("authorization error leaked: %s", response.Body.String())
		}
	})

	t.Run("tenant_override", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		values := queryValues(now.Add(-time.Hour), now)
		values.Set("tenant_id", tenantB)
		response := doFactoryGET(handler, "/v1/analytics/logs/access", values, "request-scope")
		assertHandlerError(t, response, http.StatusForbidden, "analytics_logs_scope_forbidden")
		if len(authorizer.calls()) != 0 {
			t.Fatalf("scope failure reached authorizer: %#v", authorizer.calls())
		}
	})

	t.Run("block_permission_denied", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		authorizer.setError(ErrPermissionDenied)
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		response := doFactoryGET(handler, "/v1/analytics/logs/block-events",
			queryValues(now.Add(-time.Hour), now), "block-permission-denied")
		assertHandlerError(t, response, http.StatusForbidden, "analytics_logs_permission_denied")
		if len(authorizer.calls()) != 1 {
			t.Fatalf("block permission authorizations=%#v", authorizer.calls())
		}
	})

	t.Run("block_tenant_override", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		values := queryValues(now.Add(-time.Hour), now)
		values.Set("tenant_id", tenantB)
		response := doFactoryGET(handler, "/v1/analytics/logs/block-events", values, "block-scope")
		assertHandlerError(t, response, http.StatusForbidden, "analytics_logs_scope_forbidden")
		if len(authorizer.calls()) != 0 {
			t.Fatalf("block scope failure reached authorizer: %#v", authorizer.calls())
		}
	})

	t.Run("malformed_query", func(t *testing.T) {
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		}, authorizer, time.Second)
		request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil)
		request.URL.RawQuery = "from=%zz&to=2026-07-23T12%3A00%3A00Z"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
		if len(authorizer.calls()) != 0 {
			t.Fatalf("malformed query reached authorizer: %#v", authorizer.calls())
		}
	})

	invalidQueries := map[string]url.Values{
		"site_uuid":       queryValues(now.Add(-time.Hour), now),
		"node_uuid":       queryValues(now.Add(-time.Hour), now),
		"client_ip":       queryValues(now.Add(-time.Hour), now),
		"status_zero":     queryValues(now.Add(-time.Hour), now),
		"status_range":    queryValues(now.Add(-time.Hour), now),
		"method_token":    queryValues(now.Add(-time.Hour), now),
		"reversed_window": queryValues(now, now.Add(-time.Hour)),
		"precision":       queryValues(now.Add(-time.Hour).Add(time.Nanosecond), now),
		"oversize_window": queryValues(now.Add(-32*24*time.Hour), now),
	}
	invalidQueries["site_uuid"].Set("site_id", "not-a-uuid")
	invalidQueries["node_uuid"].Set("node_id", "not-a-uuid")
	invalidQueries["client_ip"].Set("client_ip", "not-an-ip")
	invalidQueries["status_zero"].Set("status_code", "0")
	invalidQueries["status_range"].Set("status_code", "600")
	invalidQueries["method_token"].Set("method", "bad method")
	for name, values := range invalidQueries {
		t.Run("invalid_"+name, func(t *testing.T) {
			authorizer := &recordingAuthorizer{}
			handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
				return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
			}, authorizer, time.Second)
			response := doFactoryGET(handler, "/v1/analytics/logs/access", values, "request-invalid-filter")
			assertHandlerError(t, response, http.StatusBadRequest, "analytics_logs_invalid_request")
			if len(authorizer.calls()) != 0 {
				t.Fatalf("invalid query reached authorizer: %#v", authorizer.calls())
			}
		})
	}

	if storageCalls.Load() != 0 {
		t.Fatalf("rejected request reached storage: calls=%d", storageCalls.Load())
	}
}

func TestHTTPFactoryPlatformRejectsAPIKeyBeforeDependencies(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	var authenticationCalls atomic.Int64
	var storageCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		storageCalls.Add(1)
	}))
	defer server.Close()
	authorizer := &recordingAuthorizer{}
	handler := newFactoryHandler(t, server, func(*http.Request) (Principal, error) {
		authenticationCalls.Add(1)
		return Principal{ID: siteA, ScopeKind: "platform"}, nil
	}, authorizer, time.Second)
	values := queryValues(now.Add(-time.Hour), now)
	values.Set("tenant_id", tenantA)
	request := httptest.NewRequest(http.MethodGet,
		"/v1/admin/analytics/logs/access?"+values.Encode(), nil)
	request.Header.Set("Authorization", "CdncaKey key.secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assertHandlerError(t, response, http.StatusUnauthorized, "analytics_logs_authentication_required")
	if authenticationCalls.Load() != 0 || len(authorizer.calls()) != 0 || storageCalls.Load() != 0 {
		t.Fatalf("platform API key reached dependencies: authentication=%d authorization=%d storage=%d",
			authenticationCalls.Load(), len(authorizer.calls()), storageCalls.Load())
	}
}

func TestHTTPFactoryCapabilityRequestIDAndUpstreamFailures(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	actor := func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}

	t.Run("block_state_and_malformed_cursor", func(t *testing.T) {
		var storageCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			storageCalls.Add(1)
		}))
		defer server.Close()
		authorizer := &recordingAuthorizer{}
		handler := newFactoryHandler(t, server, actor, authorizer, time.Second)
		for _, path := range []string{"/v1/analytics/logs/blocks/current", "/v1/analytics/logs/blocks/history"} {
			response := doFactoryGET(handler, path, nil, "capability-request")
			assertHandlerError(t, response, http.StatusUnprocessableEntity, "analytics_logs_capability_unsupported")
			if response.Header().Get("X-Request-ID") != "capability-request" {
				t.Fatalf("request id=%q", response.Header().Get("X-Request-ID"))
			}
		}
		for _, cursor := range []string{"payload.invalid-mac", "changed-scope", "changed-time", "changed-keyset"} {
			values := queryValues(now.Add(-time.Hour), now)
			values.Set("cursor", cursor)
			assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/access", values, "cursor-request"),
				http.StatusUnprocessableEntity, "analytics_logs_capability_unsupported")
		}
		if storageCalls.Load() != 0 || len(authorizer.calls()) != 6 {
			t.Fatalf("storage=%d authorizations=%d", storageCalls.Load(), len(authorizer.calls()))
		}
	})

	for _, test := range []struct {
		name    string
		timeout time.Duration
		serve   func(http.ResponseWriter, *http.Request)
		status  int
		code    string
	}{
		{
			name: "storage_status", timeout: time.Second, status: http.StatusServiceUnavailable,
			code: "analytics_logs_storage_unavailable",
			serve: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte("password=storage-secret SELECT token"))
			},
		},
		{
			name: "partial_json", timeout: time.Second, status: http.StatusServiceUnavailable,
			code: "analytics_logs_storage_unavailable",
			serve: func(writer http.ResponseWriter, _ *http.Request) {
				row := accessTestRow("event-a", now.Add(-time.Minute), "/safe")
				_ = json.NewEncoder(writer).Encode(row)
				_, _ = writer.Write([]byte(`{"event_id":"storage-secret"`))
			},
		},
		{
			name: "invalid_json", timeout: time.Second, status: http.StatusServiceUnavailable,
			code: "analytics_logs_storage_unavailable",
			serve: func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write([]byte(`{"event_id":"storage-secret","unknown":true}`))
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(test.serve))
			defer server.Close()
			handler := newFactoryHandler(t, server, actor, &recordingAuthorizer{}, test.timeout)
			response := doFactoryGET(handler, "/v1/analytics/logs/access", queryValues(now.Add(-time.Hour), now), "upstream-request")
			assertHandlerError(t, response, test.status, test.code)
			if strings.Contains(response.Body.String(), "storage-secret") || strings.Contains(response.Body.String(), "SELECT") {
				t.Fatalf("upstream detail leaked: %s", response.Body.String())
			}
		})
	}

	t.Run("timeout", func(t *testing.T) {
		requestCanceled := make(chan struct{})
		release := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			select {
			case <-request.Context().Done():
				close(requestCanceled)
			case <-release:
			}
		}))
		defer func() {
			close(release)
			server.Close()
		}()
		handler := newFactoryHandler(t, server, actor, &recordingAuthorizer{}, 20*time.Millisecond)
		response := doFactoryGET(handler, "/v1/analytics/logs/access",
			queryValues(now.Add(-time.Hour), now), "upstream-request")
		assertHandlerError(t, response, http.StatusGatewayTimeout, "analytics_logs_query_timeout")
		select {
		case <-requestCanceled:
		case <-time.After(time.Second):
			t.Fatal("ClickHouse request context was not canceled")
		}
	})
}

func newFactoryHandler(
	t *testing.T,
	server *httptest.Server,
	authenticate AuthenticatePrincipalFunc,
	authorizer Authorizer,
	queryTimeout time.Duration,
) http.Handler {
	t.Helper()
	handler, err := newHTTPHandler(HTTPConfig{
		Client: ClientConfig{
			Endpoint: server.URL, Database: "task_analyticslog_runtime", QueryTimeout: queryTimeout,
			CursorKeyring: testLogCursorKeyring(),
		},
		Handler: HandlerConfig{
			QueryTimeout: queryTimeout + 100*time.Millisecond,
			Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}, handlerDependencies{
		Authenticate: authenticate, Authorizer: authorizer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func doFactoryGET(handler http.Handler, path string, values url.Values, requestID string) *httptest.ResponseRecorder {
	target := path
	if values != nil {
		target += "?" + values.Encode()
	}
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("X-Request-ID", requestID)
	request.Header.Set("X-Tenant-ID", tenantB)
	request.Header.Set("X-Scope-Kind", "platform")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestRuntimeHTTPClientDisablesProxyAndRedirects(t *testing.T) {
	client := newRuntimeHTTPClient(time.Second, time.Second, nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || !transport.DisableCompression || transport.ResponseHeaderTimeout != time.Second ||
		client.Timeout != 0 {
		t.Fatalf("transport=%#v", client.Transport)
	}
	if !errors.Is(client.CheckRedirect(&http.Request{}, nil), http.ErrUseLastResponse) {
		t.Fatal("redirect policy did not fail closed")
	}
}

func TestHTTPFactoryTLSVerificationAndTrustedRoots(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Context().Err() != nil {
			return
		}
		_ = json.NewEncoder(writer).Encode(accessTestRow("tls-event", now.Add(-time.Minute), "/tls"))
	}))
	defer server.Close()
	authenticate := func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}

	untrusted := newFactoryHandler(t, server, authenticate, &recordingAuthorizer{}, time.Second)
	assertHandlerError(t, doFactoryGET(untrusted, "/v1/analytics/logs/access",
		queryValues(now.Add(-time.Hour), now), "tls-untrusted"),
		http.StatusServiceUnavailable, "analytics_logs_storage_unavailable")

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	trusted, err := newHTTPHandler(HTTPConfig{
		Client: ClientConfig{Endpoint: server.URL, Database: "task_analyticslog_tls", QueryTimeout: time.Second,
			CursorKeyring: testLogCursorKeyring()},
		Handler: HandlerConfig{
			QueryTimeout: 1100 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		RootCAs: roots,
	}, handlerDependencies{Authenticate: authenticate, Authorizer: &recordingAuthorizer{}})
	if err != nil {
		t.Fatal(err)
	}
	response := doFactoryGET(trusted, "/v1/analytics/logs/access",
		queryValues(now.Add(-time.Hour), now), "tls-trusted")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"event_id":"tls-event"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHTTPFactoryIgnoresMutableDefaultTransport(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Context().Err() != nil {
			return
		}
		_ = json.NewEncoder(writer).Encode(accessTestRow("unsafe-event", now.Add(-time.Minute), "/unsafe"))
	}))
	defer server.Close()
	authenticate := func(*http.Request) (Principal, error) {
		return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
	}
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original }()

	t.Run("non_transport", func(t *testing.T) {
		transport := &recordingRoundTripper{}
		http.DefaultTransport = transport
		handler := newFactoryHandler(t, server, authenticate, &recordingAuthorizer{}, time.Second)
		assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/access",
			queryValues(now.Add(-time.Hour), now), "default-non-transport"),
			http.StatusServiceUnavailable, "analytics_logs_storage_unavailable")
		if transport.calls.Load() != 0 {
			t.Fatalf("mutable default transport calls=%d", transport.calls.Load())
		}
	})

	t.Run("insecure_tls", func(t *testing.T) {
		http.DefaultTransport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		handler := newFactoryHandler(t, server, authenticate, &recordingAuthorizer{}, time.Second)
		assertHandlerError(t, doFactoryGET(handler, "/v1/analytics/logs/access",
			queryValues(now.Add(-time.Hour), now), "default-insecure-tls"),
			http.StatusServiceUnavailable, "analytics_logs_storage_unavailable")
	})
}

func TestHTTPFactoryEnforcesStorageResponseLimit(t *testing.T) {
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Context().Err() != nil {
			return
		}
		_, _ = writer.Write([]byte(strings.Repeat("storage-secret", 64)))
	}))
	defer server.Close()
	handler, err := newHTTPHandler(HTTPConfig{
		Client: ClientConfig{
			Endpoint: server.URL, Database: "task_analyticslog_limit", QueryTimeout: time.Second,
			MaxResponseBytes: 512, CursorKeyring: testLogCursorKeyring(),
		},
		Handler: HandlerConfig{
			QueryTimeout: 1100 * time.Millisecond, MaxResponseBytes: 512,
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}, handlerDependencies{
		Authenticate: func(*http.Request) (Principal, error) {
			return Principal{ID: siteA, ScopeKind: "tenant", TenantID: tenantA}, nil
		},
		Authorizer: &recordingAuthorizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := doFactoryGET(handler, "/v1/analytics/logs/access",
		queryValues(now.Add(-time.Hour), now), "response-limit")
	assertHandlerError(t, response, http.StatusServiceUnavailable, "analytics_logs_storage_unavailable")
	if strings.Contains(response.Body.String(), "storage-secret") {
		t.Fatalf("oversize storage response leaked: %s", response.Body.String())
	}
}
