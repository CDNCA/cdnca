package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnectionshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const maximumRetentionStoreLimit = 1001

type analyticsConnectionsSessionAuthenticator interface {
	AuthenticateSession(context.Context, string) (identity.AuthenticatedSession, error)
}

type analyticsConnectionsRetentionHandlerFactory func(
	analyticsconnectionshttp.RetentionStore,
	analyticsconnectionshttp.AuthenticateFunc,
	analyticsconnectionshttp.HandlerConfig,
) (http.Handler, error)

type analyticsConnectionsRetentionRuntime struct {
	handler   http.Handler
	closeIdle func()
	closeOnce sync.Once
}

type analyticsConnectionsRetentionStore struct {
	clickHouse       analyticsconnections.ClickHouseConfig
	maxResponseBytes int64
	client           analyticsconnections.HTTPClient
}

func openAnalyticsConnectionsRetentionRuntime(
	cfg config.Config,
	authenticator analyticsConnectionsSessionAuthenticator,
	client analyticsconnections.HTTPClient,
	factory analyticsConnectionsRetentionHandlerFactory,
) (*analyticsConnectionsRetentionRuntime, error) {
	if !cfg.AnalyticsQueryEnabled {
		return nil, nil
	}
	if nilRetentionDependency(authenticator) {
		return nil, analyticsconnections.ErrInvalidConfiguration
	}
	if client == nil {
		client = newAnalyticsHTTPClient(cfg.AnalyticsConnectTimeout, cfg.AnalyticsHandlerTimeout)
	}
	clickHouse := analyticsconnections.ClickHouseConfig{
		Endpoint: cfg.ClickHouseURL, Database: cfg.ClickHouseDatabase,
		Username: cfg.ClickHouseUsername, Password: cfg.ClickHousePassword,
		ConnectTimeout: cfg.AnalyticsConnectTimeout, OperationTimeout: cfg.AnalyticsQueryTimeout,
		MaxResponseBytes: cfg.AnalyticsQueryMaxResponse,
	}
	if _, err := analyticsconnections.NewClickHouseRetentionReader(clickHouse, analyticsconnections.RetentionConfig{
		MaxRows: 1, MaxResponseBytes: cfg.AnalyticsQueryMaxResponse, TTL: analyticsconnections.DefaultRetentionTTL,
	}, client); err != nil {
		return nil, fmt.Errorf("initialize analytics connections retention reader: %w", err)
	}
	store := &analyticsConnectionsRetentionStore{
		clickHouse: clickHouse, maxResponseBytes: cfg.AnalyticsQueryMaxResponse, client: client,
	}
	if factory == nil {
		factory = func(
			store analyticsconnectionshttp.RetentionStore,
			authenticate analyticsconnectionshttp.AuthenticateFunc,
			config analyticsconnectionshttp.HandlerConfig,
		) (http.Handler, error) {
			return analyticsconnectionshttp.NewHandler(store, authenticate, config)
		}
	}
	authenticate := func(request *http.Request) (identity.AuthenticatedSession, error) {
		if request == nil {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		authorization := strings.TrimSpace(request.Header.Get("Authorization"))
		scheme, token, found := strings.Cut(authorization, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(token) == "" {
			return identity.AuthenticatedSession{}, identity.ErrInvalidSession
		}
		return authenticator.AuthenticateSession(request.Context(), strings.TrimSpace(token))
	}
	handler, err := factory(store, authenticate, analyticsconnectionshttp.HandlerConfig{
		QueryTimeout: cfg.AnalyticsHandlerTimeout, MaxResponseBytes: cfg.AnalyticsHandlerMaxResponse,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize analytics connections retention handler: %w", err)
	}
	if nilRetentionDependency(handler) {
		return nil, errors.New("analytics connections retention handler factory returned nil handler")
	}
	runtime := &analyticsConnectionsRetentionRuntime{handler: handler}
	if closer, ok := client.(interface{ CloseIdleConnections() }); ok {
		runtime.closeIdle = closer.CloseIdleConnections
	}
	return runtime, nil
}

func (store *analyticsConnectionsRetentionStore) QueryRetention(
	ctx context.Context,
	query analyticsconnectionshttp.RetentionStoreQuery,
) ([]analyticsconnections.RetentionRow, error) {
	if store == nil || store.client == nil || ctx == nil || query.Limit < 2 || query.Limit > maximumRetentionStoreLimit {
		return nil, analyticsconnections.ErrRetentionInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := analyticsconnections.NewClickHouseRetentionReader(store.clickHouse, analyticsconnections.RetentionConfig{
		MaxRows: query.Limit - 1, MaxResponseBytes: store.maxResponseBytes, TTL: analyticsconnections.DefaultRetentionTTL,
	}, store.client)
	if err != nil {
		return nil, err
	}
	return reader.Read(ctx, query.RetentionQuery)
}

func (runtime *analyticsConnectionsRetentionRuntime) Handler() http.Handler {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

func (runtime *analyticsConnectionsRetentionRuntime) Close() {
	if runtime == nil || runtime.closeIdle == nil {
		return
	}
	runtime.closeOnce.Do(runtime.closeIdle)
}

func nilRetentionDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
