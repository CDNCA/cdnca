package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
)

func TestUnavailableAnalyticsStorePreservesRealDependencyFailure(t *testing.T) {
	store := unavailableAnalyticsStore{}
	ctx := context.Background()
	if _, err := store.Summary(ctx, analytics.Scope{}, analytics.Filter{}); !errors.Is(err, analytics.ErrTransport) {
		t.Fatalf("unavailable summary error = %v, want analytics transport error", err)
	}
	if _, err := store.Trend(ctx, analytics.Scope{}, analytics.Filter{}); !errors.Is(err, analytics.ErrTransport) {
		t.Fatalf("unavailable trend error = %v, want analytics transport error", err)
	}
	if _, err := store.Rank(ctx, analytics.Scope{}, analytics.Filter{}, analytics.RankByURL, 20, ""); !errors.Is(err, analytics.ErrTransport) {
		t.Fatalf("unavailable rank error = %v, want analytics transport error", err)
	}
}

func TestOpenAnalyticsQueryStoreDisabledHasNoDependencies(t *testing.T) {
	runtime, err := openAnalyticsQueryStore(config.Config{}, nil)
	if err != nil || runtime != nil {
		t.Fatalf("disabled analytics runtime = (%v, %v)", runtime, err)
	}
}

func TestOpenAnalyticsQueryStoreBuildsWithInjectedHTTPClient(t *testing.T) {
	cfg := validAnalyticsQueryConfig()
	runtime, err := openAnalyticsQueryStore(cfg, inertAnalyticsHTTPClient{})
	if err != nil || runtime == nil || runtime.QueryStore() == nil {
		t.Fatalf("configured analytics runtime = (%v, %v)", runtime, err)
	}
	if rendered := fmt.Sprint(runtime.QueryStore()); strings.Contains(rendered, cfg.ClickHousePassword) {
		t.Fatalf("analytics client string exposed password: %s", rendered)
	}
}

func TestOpenAnalyticsQueryStoreRedactsInvalidConfiguration(t *testing.T) {
	cfg := validAnalyticsQueryConfig()
	cfg.ClickHouseURL = "https://analytics:visible-secret@clickhouse.example.test"
	_, err := openAnalyticsQueryStore(cfg, inertAnalyticsHTTPClient{})
	if err == nil || !strings.Contains(err.Error(), analytics.ErrInvalidConfiguration.Error()) ||
		strings.Contains(err.Error(), "visible-secret") {
		t.Fatalf("invalid analytics client error = %v", err)
	}
}

func TestNewAnalyticsHTTPClientIsBoundedAndRejectsRedirects(t *testing.T) {
	queryTimeout := 5 * time.Second
	client := newAnalyticsHTTPClient(2*time.Second, 6*time.Second)
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.DialContext == nil || transport.TLSHandshakeTimeout != 2*time.Second ||
		transport.IdleConnTimeout != analyticsIdleConnTimeout ||
		// FX04: keep enough idle connections per ClickHouse host so dashboard
		// bursts reuse them instead of churning ports into TIME_WAIT.
		transport.MaxIdleConnsPerHost != analyticsMaxIdleConnsPerHost || analyticsMaxIdleConnsPerHost < 16 {
		t.Fatalf("analytics transport = %#v", client.Transport)
	}
	if client.Timeout != 6*time.Second || client.Timeout <= queryTimeout || client.CheckRedirect == nil {
		t.Fatalf("analytics HTTP client = %#v", client)
	}
	if err := client.CheckRedirect(new(http.Request), nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy error = %v", err)
	}
}

func TestAnalyticsQueryRuntimeClosesIdleConnectionsOnce(t *testing.T) {
	cfg := validAnalyticsQueryConfig()
	httpClient := &closeTrackingAnalyticsHTTPClient{}
	runtime, err := openAnalyticsQueryStore(cfg, httpClient)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Close()
	runtime.Close()
	if httpClient.closeCalls != 1 {
		t.Fatalf("CloseIdleConnections calls = %d, want 1", httpClient.closeCalls)
	}
}

func validAnalyticsQueryConfig() config.Config {
	return config.Config{
		AnalyticsQueryEnabled:       true,
		ClickHouseURL:               "https://clickhouse.example.test",
		ClickHouseDatabase:          "cdnca_analytics",
		ClickHouseUsername:          "analytics",
		ClickHousePassword:          "visible-secret",
		AnalyticsConnectTimeout:     2 * time.Second,
		AnalyticsQueryTimeout:       5 * time.Second,
		AnalyticsQueryMaxResponse:   2 << 20,
		AnalyticsHandlerTimeout:     6 * time.Second,
		AnalyticsHandlerMaxResponse: 1 << 20,
	}
}

type inertAnalyticsHTTPClient struct{}

func (inertAnalyticsHTTPClient) Do(*http.Request) (*http.Response, error) {
	panic("analytics HTTP client must not be called during construction")
}

type closeTrackingAnalyticsHTTPClient struct {
	closeCalls int
}

func (*closeTrackingAnalyticsHTTPClient) Do(*http.Request) (*http.Response, error) {
	panic("analytics HTTP client must not be called during construction")
}

func (client *closeTrackingAnalyticsHTTPClient) CloseIdleConnections() {
	client.closeCalls++
}
