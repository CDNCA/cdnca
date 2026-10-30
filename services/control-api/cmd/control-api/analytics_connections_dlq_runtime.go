package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnectionshttp"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/nats-io/nats.go"
)

type analyticsConnectionsDLQHandlerFactory func(
	analyticsconnectionshttp.DeadLetterStore,
	analyticsconnectionshttp.AuthenticateFunc,
	analyticsconnectionshttp.DLQHandlerConfig,
) (http.Handler, error)

type analyticsConnectionsDLQRuntime struct {
	handler   http.Handler
	closeOnce sync.Once
	closeErr  error
}

func openAnalyticsConnectionsDLQRuntime(
	cfg config.Config,
	connectionsRuntime *analyticsConnectionsProcessRuntime,
	authenticator analyticsConnectionsSessionAuthenticator,
	factory analyticsConnectionsDLQHandlerFactory,
) (*analyticsConnectionsDLQRuntime, error) {
	if connectionsRuntime == nil {
		return nil, nil
	}
	if connectionsRuntime.connection == nil || connectionsRuntime.connection.IsClosed() || nilRetentionDependency(authenticator) {
		return nil, errors.New("analytics connections DLQ runtime is unavailable")
	}
	runtimeConfig := analyticsConnectionsRuntimeConfig(cfg)
	if runtimeConfig.OperationTimeout <= 0 {
		return nil, errors.New("analytics connections DLQ runtime operation timeout is invalid")
	}
	jetstream, err := connectionsRuntime.connection.JetStream(nats.MaxWait(runtimeConfig.OperationTimeout))
	if err != nil {
		return nil, errors.New("analytics connections DLQ JetStream is unavailable")
	}
	store, err := analyticsconnections.NewNATSDlqReceiptStore(jetstream, runtimeConfig.OperationTimeout)
	if err != nil {
		return nil, fmt.Errorf("initialize analytics connections DLQ receipt store: %w", err)
	}
	if factory == nil {
		factory = func(
			store analyticsconnectionshttp.DeadLetterStore,
			authenticate analyticsconnectionshttp.AuthenticateFunc,
			config analyticsconnectionshttp.DLQHandlerConfig,
		) (http.Handler, error) {
			return analyticsconnectionshttp.NewDLQHandler(store, authenticate, config)
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
	handler, err := factory(store, authenticate, analyticsconnectionshttp.DLQHandlerConfig{
		QueryTimeout: cfg.AnalyticsHandlerTimeout, MaxResponseBytes: cfg.AnalyticsHandlerMaxResponse,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize analytics connections DLQ handler: %w", err)
	}
	if nilRetentionDependency(handler) {
		return nil, errors.New("analytics connections DLQ handler factory returned nil handler")
	}
	return &analyticsConnectionsDLQRuntime{handler: handler}, nil
}

func (runtime *analyticsConnectionsDLQRuntime) Handler() http.Handler {
	if runtime == nil {
		return nil
	}
	return runtime.handler
}

func (runtime *analyticsConnectionsDLQRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {})
	return runtime.closeErr
}
