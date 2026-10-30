package dashboardhttp

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/dashboard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/jackc/pgx/v5/pgxpool"
)

type productionAnalyticsReader struct{}

func (*productionAnalyticsReader) Summary(context.Context, analytics.Actor, analytics.QueryRequest) (analytics.Summary, error) {
	return analytics.Summary{}, nil
}

func (*productionAnalyticsReader) Trend(context.Context, analytics.Actor, analytics.QueryRequest) ([]analytics.TrendPoint, error) {
	return nil, nil
}

func (*productionAnalyticsReader) Rank(context.Context, analytics.Actor, analytics.QueryRequest, analytics.RankDimension, uint16, string) (analytics.RankPage, error) {
	return analytics.RankPage{}, nil
}

func TestNewProductionHandlerBindsProductionReaderAndFences(t *testing.T) {
	dependencies := productionDependencies(t)
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	config := ProductionConfig{
		Reader: dashboard.ProductionConfig{QueryTimeout: 25 * time.Millisecond, MaxConcurrent: 3},
		HTTP:   Config{Now: func() time.Time { return now }, QueryTimeout: 40 * time.Millisecond, MaxResponseBytes: 4096},
	}
	handler, err := NewProductionHandler(config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := handler.reader.(*dashboard.ProductionReader); !ok {
		t.Fatalf("reader = %T, want *dashboard.ProductionReader", handler.reader)
	}
	if handler.authenticator != dependencies.Identity || handler.queryTimeout != config.HTTP.QueryTimeout ||
		handler.maxResponseBytes != config.HTTP.MaxResponseBytes || !handler.now().Equal(now) {
		t.Fatalf("handler fences not preserved: %+v", handler)
	}
}

func TestNewProductionHandlerRejectsMissingTypedNilAndUnconfiguredDependencies(t *testing.T) {
	tests := map[string]func(*ProductionDependencies){
		"pool missing":     func(value *ProductionDependencies) { value.Pool = nil },
		"pool zero":        func(value *ProductionDependencies) { value.Pool = new(pgxpool.Pool) },
		"identity missing": func(value *ProductionDependencies) { value.Identity = nil },
		"identity zero":    func(value *ProductionDependencies) { value.Identity = new(identity.Service) },
		"IAM missing":      func(value *ProductionDependencies) { value.IAM = nil },
		"IAM zero":         func(value *ProductionDependencies) { value.IAM = new(iamlock.Authorizer) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := productionDependencies(t)
			mutate(&dependencies)
			handler, err := NewProductionHandler(ProductionConfig{}, dependencies)
			if handler != nil || !errors.Is(err, dashboard.ErrInvalidConfig) {
				t.Fatalf("NewProductionHandler() = (%T, %v), want nil ErrInvalidConfig", handler, err)
			}
		})
	}
}

func TestNewProductionHandlerAllowsUnavailableAnalytics(t *testing.T) {
	for _, test := range []struct {
		name      string
		analytics dashboard.AnalyticsReader
	}{
		{name: "missing"},
		{name: "typed nil", analytics: (*productionAnalyticsReader)(nil)},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := productionDependencies(t)
			dependencies.Analytics = test.analytics
			handler, err := NewProductionHandler(ProductionConfig{}, dependencies)
			if err != nil || handler == nil {
				t.Fatalf("NewProductionHandler() = (%T, %v), want configured degraded handler", handler, err)
			}
		})
	}
}

func TestNewProductionHandlerRejectsInvalidReaderAndHTTPFences(t *testing.T) {
	tests := map[string]ProductionConfig{
		"reader timeout below minimum":  {Reader: dashboard.ProductionConfig{QueryTimeout: time.Nanosecond}},
		"reader timeout above maximum":  {Reader: dashboard.ProductionConfig{QueryTimeout: 31 * time.Second}},
		"reader capacity negative":      {Reader: dashboard.ProductionConfig{MaxConcurrent: -1}},
		"reader capacity above maximum": {Reader: dashboard.ProductionConfig{MaxConcurrent: 257}},
		"HTTP timeout negative":         {HTTP: Config{QueryTimeout: -time.Second}},
		"HTTP timeout above maximum":    {HTTP: Config{QueryTimeout: 31 * time.Second}},
		"HTTP response below minimum":   {HTTP: Config{MaxResponseBytes: 511}},
		"HTTP response above maximum":   {HTTP: Config{MaxResponseBytes: (4 << 20) + 1}},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			handler, err := NewProductionHandler(config, productionDependencies(t))
			if handler != nil || !errors.Is(err, dashboard.ErrInvalidConfig) {
				t.Fatalf("NewProductionHandler() = (%T, %v), want nil ErrInvalidConfig", handler, err)
			}
		})
	}
}

func productionDependencies(t *testing.T) ProductionDependencies {
	t.Helper()
	poolConfig, err := pgxpool.ParseConfig("postgresql://dashboard:dashboard@127.0.0.1:1/dashboard?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	tokens, err := identity.NewTokenManager(strings.Repeat("d", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{'d'}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return ProductionDependencies{
		Pool: pool, Identity: identityService, IAM: authorizer, Analytics: &productionAnalyticsReader{},
	}
}
