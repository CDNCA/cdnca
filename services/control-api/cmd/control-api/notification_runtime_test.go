package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStartNotificationProcessRuntimeWaitsForCoreReadiness(t *testing.T) {
	allowReady := make(chan struct{})
	core := &notificationTestCore{
		run: func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		},
		ready: func(context.Context, notification.ChannelSwitches) error {
			select {
			case <-allowReady:
				return nil
			default:
				return notificationruntime.ErrWorkerNotRunning
			}
		},
		health: notificationruntime.HealthSnapshot{Enabled: true, State: notificationruntime.StateRunning, WorkerRunning: true},
	}
	result := make(chan *notificationProcessRuntime, 1)
	errorsChannel := make(chan error, 1)
	go func() {
		runtime, err := startNotificationProcessRuntime(
			context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, time.Second,
		)
		result <- runtime
		errorsChannel <- err
	}()
	select {
	case runtime := <-result:
		t.Fatalf("runtime became ready before first successful batch: %#v", runtime)
	case <-time.After(25 * time.Millisecond):
	}
	close(allowReady)
	var runtime *notificationProcessRuntime
	select {
	case runtime = <-result:
	case <-time.After(time.Second):
		t.Fatal("runtime did not become ready")
	}
	if err := <-errorsChannel; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStartNotificationProcessRuntimeAcceptsSMSOnlyAndBothChannels(t *testing.T) {
	for _, switches := range []notification.ChannelSwitches{
		{SMS: true},
		{Email: true, SMS: true},
	} {
		core := &notificationTestCore{
			run:   func(ctx context.Context) error { <-ctx.Done(); return nil },
			ready: func(context.Context, notification.ChannelSwitches) error { return nil },
		}
		runtime, err := startNotificationProcessRuntime(
			context.Background(), core, switches, time.Second, time.Second,
		)
		if err != nil {
			t.Fatalf("start with switches=%+v: %v", switches, err)
		}
		if err := runtime.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStartNotificationProcessRuntimeFailsClosedAndRedactsDependencyError(t *testing.T) {
	const secret = "provider-body-visible-secret"
	sentinel := errors.New(secret)
	core := &notificationTestCore{
		run:   func(ctx context.Context) error { <-ctx.Done(); return nil },
		ready: func(context.Context, notification.ChannelSwitches) error { return sentinel },
	}
	runtime, err := startNotificationProcessRuntime(
		context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, time.Second,
	)
	if runtime != nil || !errors.Is(err, sentinel) || err.Error() != "verify notification runtime readiness" ||
		strings.Contains(err.Error(), secret) || core.closeCalls.Load() != 1 {
		t.Fatalf("failed startup runtime=%#v error=%v close_calls=%d", runtime, err, core.closeCalls.Load())
	}
}

func TestOpenNotificationProcessRuntimeRedactsProviderFactoryFailure(t *testing.T) {
	const secret = "smtp-credential-visible-secret"
	sentinel := errors.New(secret)
	config := notificationRuntimeConfig{
		Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS,
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: {ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail},
		},
		StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(
		context.Background(), config, new(pgxpool.Pool), notificationRuntimeDependencies{
			Verify: func(
				context.Context,
				*pgxpool.Pool,
				map[notification.Channel]notification.TemplateRef,
			) (notification.ChannelSwitches, error) {
				return notification.ChannelSwitches{Email: true}, nil
			},
			NewSMTP: func(smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
				return nil, sentinel
			},
		},
	)
	if runtime != nil || !errors.Is(err, sentinel) || err.Error() != "configure notification SMTP TLS provider" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("provider failure runtime=%#v error=%v", runtime, err)
	}
}

func TestOpenNotificationProcessRuntimeAcceptsSTARTTLSProvider(t *testing.T) {
	const secret = "starttls-provider-visible-secret"
	sentinel := errors.New(secret)
	config := notificationRuntimeConfig{
		Enabled: true, EmailProvider: notificationEmailProviderSMTPSTARTTLS,
		SMTP: smtpTLSConfig{StartTLS: true},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: {ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail},
		},
		StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(
		context.Background(), config, new(pgxpool.Pool), notificationRuntimeDependencies{
			Verify: func(
				context.Context,
				*pgxpool.Pool,
				map[notification.Channel]notification.TemplateRef,
			) (notification.ChannelSwitches, error) {
				return notification.ChannelSwitches{Email: true}, nil
			},
			NewSMTP: func(config smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
				if !config.StartTLS {
					t.Fatal("STARTTLS provider lost transport mode at composition")
				}
				return nil, sentinel
			},
		},
	)
	if runtime != nil || !errors.Is(err, sentinel) || err.Error() != "configure notification SMTP TLS provider" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("STARTTLS provider failure runtime=%#v error=%v", runtime, err)
	}
}

func TestOpenNotificationProcessRuntimeRedactsSMSProviderFactoryFailure(t *testing.T) {
	const secret = "sms-credential-visible-secret"
	sentinel := errors.New(secret)
	config := notificationRuntimeConfig{
		Enabled: true, SMSProvider: notificationSMSProviderHTTPSJSON,
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelSMS: {ID: "account_recovery_sms", Version: 1, Channel: notification.ChannelSMS},
		},
		StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(
		context.Background(), config, new(pgxpool.Pool), notificationRuntimeDependencies{
			Verify: func(
				context.Context,
				*pgxpool.Pool,
				map[notification.Channel]notification.TemplateRef,
			) (notification.ChannelSwitches, error) {
				return notification.ChannelSwitches{SMS: true}, nil
			},
			NewSMS: func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
				return nil, sentinel
			},
		},
	)
	if runtime != nil || !errors.Is(err, sentinel) || err.Error() != "configure notification HTTPS JSON SMS provider" ||
		strings.Contains(err.Error(), secret) {
		t.Fatalf("SMS provider failure runtime=%#v error=%v", runtime, err)
	}
}

func TestNotificationProcessRuntimeReportsUnexpectedWorkerExitWithoutLeakingCause(t *testing.T) {
	const secret = "database-url-visible-secret"
	sentinel := errors.New(secret)
	release := make(chan struct{})
	core := &notificationTestCore{
		run:    func(context.Context) error { <-release; return sentinel },
		ready:  func(context.Context, notification.ChannelSwitches) error { return nil },
		health: notificationruntime.HealthSnapshot{Enabled: true, State: notificationruntime.StateReady, Ready: true, WorkerRunning: true},
	}
	runtime, err := startNotificationProcessRuntime(
		context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	failures := make(chan error, 1)
	monitorDone := make(chan struct{})
	go func() {
		runRequiredNotificationRuntime(context.Background(), runtime, failures)
		close(monitorDone)
	}()
	close(release)
	select {
	case err := <-failures:
		if !errors.Is(err, sentinel) || err.Error() != "notification runtime stopped" || strings.Contains(err.Error(), secret) {
			t.Fatalf("supervisor error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("unexpected exit was not reported")
	}
	<-monitorDone
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationProcessRuntimeReadinessFailureUpdatesHealth(t *testing.T) {
	core := &notificationTestCore{
		run:   func(ctx context.Context) error { <-ctx.Done(); return nil },
		ready: func(context.Context, notification.ChannelSwitches) error { return nil },
		health: notificationruntime.HealthSnapshot{
			Enabled: true, State: notificationruntime.StateReady, Ready: true, WorkerRunning: true,
		},
	}
	runtime, err := startNotificationProcessRuntime(
		context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	verificationErr := errors.New("notification_runtime_database_unavailable")
	runtime.readinessCheck = func(context.Context) (notification.ChannelSwitches, error) {
		return notification.ChannelSwitches{}, verificationErr
	}
	if err := runtime.ReadinessProbe().Ready(); !errors.Is(err, verificationErr) {
		t.Fatalf("readiness error = %v", err)
	}
	if health := runtime.Health(); health.Ready {
		t.Fatalf("health remained ready after verification failure: %#v", health)
	}

	runtime.readinessCheck = func(context.Context) (notification.ChannelSwitches, error) {
		return notification.ChannelSwitches{Email: true}, nil
	}
	if err := runtime.ReadinessProbe().Ready(); err != nil {
		t.Fatalf("recovered readiness = %v", err)
	}
	if health := runtime.Health(); !health.Ready {
		t.Fatalf("health did not recover readiness: %#v", health)
	}
}

func TestNotificationProcessRuntimeCloseIsBoundedConcurrentAndHealthIsSafe(t *testing.T) {
	core := &notificationTestCore{
		run:   func(ctx context.Context) error { <-ctx.Done(); return nil },
		ready: func(context.Context, notification.ChannelSwitches) error { return nil },
		health: notificationruntime.HealthSnapshot{
			Enabled: true, State: notificationruntime.StateReady, Ready: true, WorkerRunning: true,
			EnabledChannels: 1, ConsecutiveFailures: 2, LastErrorClass: "worker_store_unavailable",
		},
	}
	runtime, err := startNotificationProcessRuntime(
		context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, 100*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := withNotificationRuntimeHealth(http.NotFoundHandler(), runtime)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, notificationRuntimeHealthPath, nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, `"state":"ready"`) ||
		!strings.Contains(body, `"last_error_class":"worker_store_unavailable"`) ||
		strings.Contains(body, "recipient") || strings.Contains(body, "subject") || strings.Contains(body, "payload") {
		t.Fatalf("health response status=%d body=%q", response.Code, body)
	}
	apiResponse := httptest.NewRecorder()
	handler.ServeHTTP(apiResponse, httptest.NewRequest(http.MethodGet, notificationRuntimeHealthAPIPath, nil))
	if apiResponse.Code != http.StatusOK || apiResponse.Body.String() != body {
		t.Fatalf("API health response status=%d body=%q, want status=%d body=%q", apiResponse.Code, apiResponse.Body.String(), response.Code, body)
	}

	var wait sync.WaitGroup
	errorsSeen := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- runtime.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent Close() = %v", err)
		}
	}
	if core.closeCalls.Load() != 1 || runtime.Health().State != "stopped" {
		t.Fatalf("close_calls=%d health=%#v", core.closeCalls.Load(), runtime.Health())
	}
}

func TestNotificationProcessRuntimeCloseTimeoutIsStableAndBounded(t *testing.T) {
	core := &notificationTestCore{
		run:   func(ctx context.Context) error { <-ctx.Done(); return nil },
		ready: func(context.Context, notification.ChannelSwitches) error { return nil },
		close: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
	}
	runtime, err := startNotificationProcessRuntime(
		context.Background(), core, notification.ChannelSwitches{Email: true}, time.Second, 20*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = runtime.Close()
	if !errors.Is(err, context.DeadlineExceeded) || err.Error() != "close notification runtime" ||
		time.Since(started) > time.Second {
		t.Fatalf("Close() elapsed=%v error=%v", time.Since(started), err)
	}
	if second := runtime.Close(); second != err || core.closeCalls.Load() != 1 {
		t.Fatalf("second Close()=%v first=%v calls=%d", second, err, core.closeCalls.Load())
	}
}

type notificationTestCore struct {
	run        func(context.Context) error
	ready      func(context.Context, notification.ChannelSwitches) error
	health     notificationruntime.HealthSnapshot
	close      func(context.Context) error
	closeCalls atomic.Int32
}

func (core *notificationTestCore) Run(ctx context.Context) error { return core.run(ctx) }

func (core *notificationTestCore) Ready(ctx context.Context, switches notification.ChannelSwitches) error {
	return core.ready(ctx, switches)
}

func (core *notificationTestCore) Health() notificationruntime.HealthSnapshot { return core.health }

func (core *notificationTestCore) Close(ctx context.Context) error {
	core.closeCalls.Add(1)
	if core.close != nil {
		return core.close(ctx)
	}
	return nil
}

func (*notificationTestCore) RecoverySender() accountrecovery.RecoverySender { return nil }

func (*notificationTestCore) RegisterAnonymousDispatcher(
	context.Context,
	notification.AnonymousDispatcher,
) (notificationruntime.Registration, error) {
	return nil, notificationruntime.ErrDispatcherInvalid
}

var _ notificationRuntimeCore = (*notificationTestCore)(nil)
