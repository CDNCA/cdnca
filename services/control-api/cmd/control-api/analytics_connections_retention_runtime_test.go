package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnectionshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

const (
	retentionRuntimeTenant       = "11111111-1111-1111-1111-111111111111"
	retentionRuntimeSubscription = "33333333-3333-3333-3333-333333333333"
)

type retentionRuntimeAuthenticator struct {
	calls   int
	revoked bool
}

func (authenticator *retentionRuntimeAuthenticator) AuthenticateSession(_ context.Context, token string) (identity.AuthenticatedSession, error) {
	authenticator.calls++
	if token != "retention-session" || authenticator.revoked {
		return identity.AuthenticatedSession{}, identity.ErrInvalidSession
	}
	return identity.AuthenticatedSession{
		SessionID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		Principal: identity.Principal{
			UserID:      uuid.MustParse("55555555-5555-4555-8555-555555555555"),
			ScopeID:     uuid.MustParse("66666666-6666-4666-8666-666666666666"),
			ScopeKind:   "tenant",
			TenantID:    uuidPtr(uuid.MustParse(retentionRuntimeTenant)),
			Permissions: []string{"sites.read"},
		},
	}, nil
}

type retentionRuntimeHTTPClient struct {
	do             func(*http.Request) (*http.Response, error)
	closeIdleCalls int
}

func (client *retentionRuntimeHTTPClient) Do(request *http.Request) (*http.Response, error) {
	if client.do == nil {
		return nil, errors.New("unexpected ClickHouse request")
	}
	return client.do(request)
}

func (client *retentionRuntimeHTTPClient) CloseIdleConnections() { client.closeIdleCalls++ }

func TestOpenAnalyticsConnectionsRetentionRuntimeDisabledHasZeroDependencies(t *testing.T) {
	factoryCalled := false
	runtime, err := openAnalyticsConnectionsRetentionRuntime(config.Config{}, nil, &retentionRuntimeHTTPClient{}, func(
		analyticsconnectionshttp.RetentionStore,
		analyticsconnectionshttp.AuthenticateFunc,
		analyticsconnectionshttp.HandlerConfig,
	) (http.Handler, error) {
		factoryCalled = true
		return nil, errors.New("disabled runtime reached handler factory")
	})
	if err != nil || runtime != nil || factoryCalled {
		t.Fatalf("disabled retention runtime = (%v, %v), factory called=%t", runtime, err, factoryCalled)
	}
}

func TestRunServerGuardsDisabledAnalyticsConnectionsRetentionHandlerInjection(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	rendered := strings.Join(strings.Fields(string(source)), " ")
	for _, required := range []string{
		"var analyticsConnectionsRetentionHandler http.Handler",
		"if analyticsConnectionsRetentionRuntime != nil {",
		"analyticsConnectionsRetentionHandler = analyticsConnectionsRetentionRuntime.Handler()",
		"AnalyticsConnectionsRetentionHandler: analyticsConnectionsRetentionHandler",
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("runServer disabled retention guard omitted %q", required)
		}
	}
}

func TestOpenAnalyticsConnectionsRetentionRuntimeBuildsScopedBoundedStoreAndRevocableSession(t *testing.T) {
	var capturedStore analyticsconnectionshttp.RetentionStore
	var capturedAuthenticate analyticsconnectionshttp.AuthenticateFunc
	var capturedHandlerConfig analyticsconnectionshttp.HandlerConfig
	client := &retentionRuntimeHTTPClient{}
	client.do = func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/" {
			t.Fatalf("ClickHouse request = %s %s", request.Method, request.URL.Path)
		}
		values := request.URL.Query()
		for key, want := range map[string]string{
			"database":             "analytics",
			"param_tenant":         retentionRuntimeTenant,
			"param_subscription":   retentionRuntimeSubscription,
			"param_limit":          "6",
			"max_result_rows":      "6",
			"result_overflow_mode": "throw",
		} {
			if got := values.Get(key); got != want {
				t.Errorf("ClickHouse query parameter %s = %q, want %q", key, got, want)
			}
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		query := string(body)
		for _, required := range []string{
			"tenant_id={tenant:UUID}", "package_subscription_id={subscription:UUID}",
			"period_start>={from:DateTime64(3)}", "period_end<={to:DateTime64(3)}", "LIMIT {limit:UInt64}",
		} {
			if !strings.Contains(query, required) {
				t.Errorf("ClickHouse query omitted %q", required)
			}
		}
		row := `{"metric":"connections","tenant_id":"` + retentionRuntimeTenant +
			`","subscription_id":"` + retentionRuntimeSubscription +
			`","period_start":"2026-08-07T00:00:00Z","period_end":"2026-08-07T01:00:00Z","value":7,` +
			`"finalized_through":"2026-08-07T01:00:00Z","source_watermark":9,` +
			`"evidence_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",` +
			`"retention_until":"2027-09-11T01:00:00Z"}` + "\n"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(row))}, nil
	}
	authenticator := &retentionRuntimeAuthenticator{}
	runtime, err := openAnalyticsConnectionsRetentionRuntime(validRetentionRuntimeConfig(), authenticator, client, func(
		store analyticsconnectionshttp.RetentionStore,
		authenticate analyticsconnectionshttp.AuthenticateFunc,
		handlerConfig analyticsconnectionshttp.HandlerConfig,
	) (http.Handler, error) {
		capturedStore, capturedAuthenticate, capturedHandlerConfig = store, authenticate, handlerConfig
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil
	})
	if err != nil || runtime == nil || runtime.Handler() == nil {
		t.Fatalf("configured retention runtime = (%v, %v)", runtime, err)
	}
	if capturedStore == nil || capturedAuthenticate == nil || capturedHandlerConfig.QueryTimeout != 2*time.Second ||
		capturedHandlerConfig.MaxResponseBytes != 2048 {
		t.Fatalf("captured retention dependencies = (%T, %v, %+v)", capturedStore, capturedAuthenticate, capturedHandlerConfig)
	}

	request := func(scheme string) *http.Request {
		r := new(http.Request)
		r.Header = make(http.Header)
		r.Header.Set("Authorization", scheme)
		return r.WithContext(context.Background())
	}
	if _, err := capturedAuthenticate(request("CdncaKey workload-key")); !errors.Is(err, identity.ErrInvalidSession) || authenticator.calls != 0 {
		t.Fatalf("non-session credential = %v, authenticator calls=%d", err, authenticator.calls)
	}
	if _, err := capturedAuthenticate(request("Bearer retention-session")); err != nil || authenticator.calls != 1 {
		t.Fatalf("first session authentication = %v, calls=%d", err, authenticator.calls)
	}
	authenticator.revoked = true
	if _, err := capturedAuthenticate(request("Bearer retention-session")); !errors.Is(err, identity.ErrInvalidSession) || authenticator.calls != 2 {
		t.Fatalf("revoked session authentication = %v, calls=%d", err, authenticator.calls)
	}

	from := time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)
	rows, err := capturedStore.QueryRetention(context.Background(), analyticsconnectionshttp.RetentionStoreQuery{
		RetentionQuery: analyticsconnections.RetentionQuery{
			TenantID: retentionRuntimeTenant, SubscriptionID: retentionRuntimeSubscription, From: from, To: from.Add(2 * time.Hour),
		},
		Limit: 6,
	})
	if err != nil || len(rows) != 1 || rows[0].Value != 7 {
		t.Fatalf("retention rows = %+v, err=%v", rows, err)
	}
	for _, limit := range []int{1, 1002} {
		if _, err := capturedStore.QueryRetention(context.Background(), analyticsconnectionshttp.RetentionStoreQuery{
			RetentionQuery: analyticsconnections.RetentionQuery{
				TenantID: retentionRuntimeTenant, SubscriptionID: retentionRuntimeSubscription, From: from, To: from.Add(time.Hour),
			},
			Limit: limit,
		}); !errors.Is(err, analyticsconnections.ErrRetentionInvalidRequest) {
			t.Errorf("store limit %d error = %v", limit, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := capturedStore.QueryRetention(canceled, analyticsconnectionshttp.RetentionStoreQuery{
		RetentionQuery: analyticsconnections.RetentionQuery{
			TenantID: retentionRuntimeTenant, SubscriptionID: retentionRuntimeSubscription, From: from, To: from.Add(time.Hour),
		},
		Limit: 2,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled retention query error = %v", err)
	}
	runtime.Close()
	runtime.Close()
	if client.closeIdleCalls != 1 {
		t.Fatalf("CloseIdleConnections calls = %d, want 1", client.closeIdleCalls)
	}
}

func TestOpenAnalyticsConnectionsRetentionRuntimeFailsClosedAndRedactsSecrets(t *testing.T) {
	configWithSecrets := validRetentionRuntimeConfig()
	configWithSecrets.ClickHouseURL = "https://visible-user:visible-url-secret@clickhouse.example.test"
	configWithSecrets.ClickHousePassword = "visible-password-secret"
	client := &retentionRuntimeHTTPClient{}
	factory := func(analyticsconnectionshttp.RetentionStore, analyticsconnectionshttp.AuthenticateFunc, analyticsconnectionshttp.HandlerConfig) (http.Handler, error) {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), nil
	}
	if _, err := openAnalyticsConnectionsRetentionRuntime(validRetentionRuntimeConfig(), nil, client, factory); err == nil {
		t.Fatal("enabled retention runtime accepted missing session authority")
	}
	_, err := openAnalyticsConnectionsRetentionRuntime(configWithSecrets, &retentionRuntimeAuthenticator{}, client, factory)
	if err == nil || !errors.Is(err, analyticsconnections.ErrInvalidConfiguration) ||
		strings.Contains(err.Error(), "visible-url-secret") || strings.Contains(err.Error(), "visible-password-secret") {
		t.Fatalf("invalid retention configuration error = %v", err)
	}
	factoryErr := errors.New("retention handler unavailable")
	_, err = openAnalyticsConnectionsRetentionRuntime(validRetentionRuntimeConfig(), &retentionRuntimeAuthenticator{}, client,
		func(analyticsconnectionshttp.RetentionStore, analyticsconnectionshttp.AuthenticateFunc, analyticsconnectionshttp.HandlerConfig) (http.Handler, error) {
			return nil, factoryErr
		})
	if !errors.Is(err, factoryErr) {
		t.Fatalf("retention handler factory error = %v, want %v", err, factoryErr)
	}
}

func validRetentionRuntimeConfig() config.Config {
	return config.Config{
		AnalyticsQueryEnabled:       true,
		ClickHouseURL:               "http://127.0.0.1:8123",
		ClickHouseDatabase:          "analytics",
		ClickHouseUsername:          "analytics-reader",
		ClickHousePassword:          "retention-password",
		AnalyticsConnectTimeout:     time.Second,
		AnalyticsQueryTimeout:       time.Second,
		AnalyticsQueryMaxResponse:   4096,
		AnalyticsHandlerTimeout:     2 * time.Second,
		AnalyticsHandlerMaxResponse: 2048,
	}
}

func uuidPtr(value uuid.UUID) *uuid.UUID { return &value }
