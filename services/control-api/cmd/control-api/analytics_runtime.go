package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
)

const analyticsIdleConnTimeout = 30 * time.Second

// analyticsMaxIdleConnsPerHost replaces net/http's default of 2 so concurrent
// dashboard queries reuse ClickHouse connections (FX04).
const analyticsMaxIdleConnsPerHost = 16

type analyticsQueryRuntime struct {
	store     analytics.QueryStore
	closeIdle func()
	closeOnce sync.Once
}

// unavailableAnalyticsStore keeps the production analytics route mounted when
// ClickHouse is intentionally disabled. The shared analytics handler converts
// ErrTransport into the stable 503 storage-unavailable response and never
// returns synthetic rows.
type unavailableAnalyticsStore struct{}

func (unavailableAnalyticsStore) Summary(context.Context, analytics.Scope, analytics.Filter) (analytics.Summary, error) {
	return analytics.Summary{}, analytics.ErrTransport
}

func (unavailableAnalyticsStore) Trend(context.Context, analytics.Scope, analytics.Filter) ([]analytics.TrendPoint, error) {
	return nil, analytics.ErrTransport
}

func (unavailableAnalyticsStore) Rank(context.Context, analytics.Scope, analytics.Filter, analytics.RankDimension, uint16, string) (analytics.RankPage, error) {
	return analytics.RankPage{}, analytics.ErrTransport
}

func openAnalyticsQueryStore(cfg config.Config, httpClient analytics.HTTPClient) (*analyticsQueryRuntime, error) {
	if !cfg.AnalyticsQueryEnabled {
		return nil, nil
	}
	if httpClient == nil {
		httpClient = newAnalyticsHTTPClient(
			cfg.AnalyticsConnectTimeout,
			cfg.AnalyticsHandlerTimeout,
		)
	}
	client, err := analytics.NewClient(analytics.Config{
		Endpoint:         cfg.ClickHouseURL,
		Database:         cfg.ClickHouseDatabase,
		Username:         cfg.ClickHouseUsername,
		Password:         cfg.ClickHousePassword,
		QueryTimeout:     cfg.AnalyticsQueryTimeout,
		MaxResponseBytes: cfg.AnalyticsQueryMaxResponse,
	}, httpClient)
	if err != nil {
		return nil, fmt.Errorf("initialize analytics query client: %w", err)
	}
	runtime := &analyticsQueryRuntime{store: client}
	if closer, ok := httpClient.(interface{ CloseIdleConnections() }); ok {
		runtime.closeIdle = closer.CloseIdleConnections
	}
	return runtime, nil
}

func (runtime *analyticsQueryRuntime) QueryStore() analytics.QueryStore {
	if runtime == nil {
		return nil
	}
	return runtime.store
}

func (runtime *analyticsQueryRuntime) Close() {
	if runtime == nil || runtime.closeIdle == nil {
		return
	}
	runtime.closeOnce.Do(runtime.closeIdle)
}

func newAnalyticsHTTPClient(connectTimeout, handlerTimeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSHandshakeTimeout: connectTimeout,
			IdleConnTimeout:     analyticsIdleConnTimeout,
			MaxIdleConnsPerHost: analyticsMaxIdleConnsPerHost,
		},
		Timeout: handlerTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
