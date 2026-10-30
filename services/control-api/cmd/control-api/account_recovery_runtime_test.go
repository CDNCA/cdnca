package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoveryhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenAccountRecoveryRuntimeDisabledDoesNotRequireDependencies(t *testing.T) {
	runtime, err := openAccountRecoveryRuntime(
		context.Background(), accountRecoveryRuntimeConfig{}, nil, nil, accountRecoveryRuntimeDependencies{},
	)
	if err != nil || runtime != nil {
		t.Fatalf("open disabled account recovery runtime = (%#v, %v)", runtime, err)
	}
}

func TestOpenAccountRecoveryRuntimeEnabledFailsClosedWithoutProductionDependencies(t *testing.T) {
	config := validAccountRecoveryRuntimeConfig(t)
	secret := canonicalAccountRecoveryTestKey(0x11)
	_, err := openAccountRecoveryRuntime(
		context.Background(), config, new(pgxpool.Pool), nil, accountRecoveryRuntimeDependencies{
			TrustedContext: func(*http.Request) (accountrecoveryhttp.TrustedContext, error) {
				return accountrecoveryhttp.TrustedContext{}, nil
			},
		},
	)
	if err == nil || err.Error() != "account recovery notification delivery runtime is unavailable" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("enabled account recovery runtime error = %v", err)
	}
}

func TestAccountRecoveryPublicRoutesStripAmbientAuthentication(t *testing.T) {
	secret := "ambient-auth-must-not-reach-handler"
	var called atomic.Int32
	runtime := &accountRecoveryRuntime{handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called.Add(1)
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key"} {
			if value := request.Header.Get(name); value != "" {
				t.Errorf("%s reached public account recovery handler: %q", name, value)
			}
		}
		if request.Header.Get("X-Request-ID") != "request-1" {
			t.Errorf("safe request metadata was removed")
		}
		writer.WriteHeader(http.StatusAccepted)
	})}
	nextCalls := 0
	handler := withAccountRecoveryRoutes(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		nextCalls++
		writer.WriteHeader(http.StatusTeapot)
	}), runtime)
	for _, path := range []string{accountRecoveryRequestPath, accountRecoveryConfirmationPath} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Authorization", "Bearer "+secret)
		request.Header.Set("Proxy-Authorization", secret)
		request.Header.Set("Cookie", "session="+secret)
		request.Header.Set("X-API-Key", secret)
		request.Header.Set("X-Request-ID", "request-1")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusAccepted {
			t.Fatalf("public route %s status = %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if called.Load() != 2 || nextCalls != 1 || response.Code != http.StatusTeapot {
		t.Fatalf("route calls account=%d next=%d status=%d", called.Load(), nextCalls, response.Code)
	}
}

func TestAccountRecoveryPublicRoutesFailClosedWhenRuntimeIsDisabled(t *testing.T) {
	nextCalls := 0
	handler := withAccountRecoveryRoutes(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		nextCalls++
		writer.WriteHeader(http.StatusTeapot)
	}), nil)
	for _, path := range []string{accountRecoveryRequestPath, accountRecoveryConfirmationPath} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.Header.Set("Authorization", "Bearer must-not-be-used")
		request.Header.Set("X-Request-ID", "recovery-disabled")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable ||
			response.Header().Get("Cache-Control") != "no-store" ||
			!strings.Contains(response.Body.String(), `"code":"account_recovery_unavailable"`) ||
			strings.Contains(response.Body.String(), "must-not-be-used") {
			t.Fatalf("disabled route %s status=%d body=%q", path, response.Code, response.Body.String())
		}
	}
	if nextCalls != 0 {
		t.Fatalf("disabled account recovery routes reached authenticated API %d times", nextCalls)
	}
}

func TestAccountRecoveryHealthDetailIsSafeAndPreservesAnalyticsState(t *testing.T) {
	secret := "must-not-appear-in-health"
	accountRuntime := &accountRecoveryRuntime{
		registration:   &accountRecoveryTestRegistration{},
		shutdownPeriod: time.Second,
	}
	handler := withControlRuntimeHealthDetail(http.NotFoundHandler(), nil, accountRuntime)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"analytics_ingest":{"enabled":false,"state":"disabled"`) ||
		!strings.Contains(body, `"account_recovery":{"enabled":true,"state":"ready","dispatcher_registered":true,"notification_runtime_ready":true}`) ||
		strings.Contains(body, secret) {
		t.Fatalf("health detail status=%d body=%q", response.Code, body)
	}
}

func TestAccountRecoveryRuntimeCloseIsBoundedIdempotentAndRedacted(t *testing.T) {
	secret := "provider-secret-close-error"
	sentinel := errors.New(secret)
	registration := &accountRecoveryTestRegistration{close: func(context.Context) error { return sentinel }}
	runtime := &accountRecoveryRuntime{registration: registration, shutdownPeriod: time.Second}
	first := runtime.Close()
	second := runtime.Close()
	if !errors.Is(first, sentinel) || first.Error() != "close account recovery dispatcher registration" ||
		strings.Contains(first.Error(), secret) || first != second || registration.calls.Load() != 1 {
		t.Fatalf("Close() first=%v second=%v calls=%d", first, second, registration.calls.Load())
	}
	if health := runtime.Health(); health.State != "stopped" || !health.Enabled || health.DispatcherRegistered {
		t.Fatalf("health after Close() = %#v", health)
	}

	release := make(chan struct{})
	blocking := &accountRecoveryTestRegistration{close: func(ctx context.Context) error {
		<-release
		return ctx.Err()
	}}
	bounded := &accountRecoveryRuntime{registration: blocking, shutdownPeriod: 20 * time.Millisecond}
	started := time.Now()
	err := bounded.Close()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second ||
		err.Error() != "close account recovery dispatcher registration" {
		t.Fatalf("bounded Close() elapsed=%v error=%v", time.Since(started), err)
	}
	close(release)
}

func validAccountRecoveryRuntimeConfig(t *testing.T) accountRecoveryRuntimeConfig {
	t.Helper()
	config, err := loadAccountRecoveryRuntimeConfigFromEnv(mapAccountRecoveryEnv(validAccountRecoveryEnvironment()))
	if err != nil {
		t.Fatalf("load valid account recovery config: %v", err)
	}
	t.Cleanup(config.clearSecrets)
	return config
}

type accountRecoveryTestRegistration struct {
	close func(context.Context) error
	calls atomic.Int32
}

func (registration *accountRecoveryTestRegistration) Close(ctx context.Context) error {
	registration.calls.Add(1)
	if registration.close == nil {
		return nil
	}
	return registration.close(ctx)
}

type accountRecoveryTestBridge struct {
	sender   accountrecovery.RecoverySender
	ready    func(context.Context, notification.ChannelSwitches) error
	register func(context.Context, notification.AnonymousDispatcher) (accountRecoveryDispatcherRegistration, error)
}

func (bridge *accountRecoveryTestBridge) Ready(ctx context.Context, switches notification.ChannelSwitches) error {
	if bridge.ready == nil {
		return nil
	}
	return bridge.ready(ctx, switches)
}

func (bridge *accountRecoveryTestBridge) RecoverySender() accountrecovery.RecoverySender {
	return bridge.sender
}

func (bridge *accountRecoveryTestBridge) RegisterAnonymousDispatcher(
	ctx context.Context,
	dispatcher notification.AnonymousDispatcher,
) (accountRecoveryDispatcherRegistration, error) {
	if bridge.register == nil {
		return nil, errors.New("test registration is missing")
	}
	return bridge.register(ctx, dispatcher)
}
