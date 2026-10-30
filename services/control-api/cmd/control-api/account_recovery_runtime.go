package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/accountrecoveryhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	accountRecoveryRequestPath      = "/v1/account-recovery/requests"
	accountRecoveryConfirmationPath = "/v1/account-recovery/confirmations"
)

type accountRecoveryDispatcherRegistration interface {
	Close(context.Context) error
}

type accountRecoveryNotificationBridge interface {
	Ready(context.Context, notification.ChannelSwitches) error
	RecoverySender() accountrecovery.RecoverySender
	RegisterAnonymousDispatcher(
		context.Context,
		notification.AnonymousDispatcher,
	) (accountRecoveryDispatcherRegistration, error)
}

type accountRecoveryRuntimeDependencies struct {
	TrustedContext         accountrecoveryhttp.ResolveTrustedContext
	Notifications          accountRecoveryNotificationBridge
	RegistrationDispatcher notification.AnonymousDispatcher
	LoginDispatcher        notification.AnonymousDispatcher
}

type accountRecoveryHealthSnapshot struct {
	Enabled                  bool   `json:"enabled"`
	State                    string `json:"state"`
	DispatcherRegistered     bool   `json:"dispatcher_registered"`
	NotificationRuntimeReady bool   `json:"notification_runtime_ready"`
}

type accountRecoveryRuntime struct {
	handler        http.Handler
	registration   accountRecoveryDispatcherRegistration
	shutdownPeriod time.Duration
	closeOnce      sync.Once
	closeErr       error
	closed         atomic.Bool
}

func openAccountRecoveryRuntime(
	ctx context.Context,
	config accountRecoveryRuntimeConfig,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	dependencies accountRecoveryRuntimeDependencies,
) (*accountRecoveryRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	if ctx == nil || pool == nil || config.DispatchKeys == nil || len(config.DigestKey) != 32 {
		return nil, errors.New("account recovery runtime configuration is incomplete")
	}
	if dependencies.TrustedContext == nil {
		return nil, errors.New("account recovery trusted tenant scope resolver is unavailable")
	}
	if dependencies.Notifications == nil || dependencies.Notifications.RecoverySender() == nil {
		return nil, errors.New("account recovery notification delivery runtime is unavailable")
	}
	if logger == nil {
		logger = slog.Default()
	}

	startupContext, cancel := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancel()
	switches, err := verifyAccountRecoveryNotificationConfiguration(startupContext, pool, config.Templates)
	if err != nil {
		return nil, runtimeStageError{stage: "verify account recovery notification configuration", err: err}
	}
	if err := dependencies.Notifications.Ready(startupContext, switches); err != nil {
		return nil, runtimeStageError{stage: "verify account recovery notification delivery runtime", err: err}
	}

	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "configure account recovery notification store", err: err}
	}
	templateSettings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		return nil, runtimeStageError{stage: "configure account recovery system user settings", err: err}
	}
	service, err := accountrecovery.NewService(pool, accountrecovery.Config{
		DigestKey: config.DigestKey, TokenTTL: config.TokenTTL, RateWindow: config.RateWindow,
		SubjectLimit: config.SubjectLimit, SourceLimit: config.SourceLimit,
		DispatchKeyring: config.DispatchKeys, DispatchEnqueuer: notificationStore,
		DispatchTemplates: config.Templates, TemplateResolver: templateSettings,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure account recovery service", err: err}
	}
	dispatcher, err := accountrecovery.NewDispatcher(pool, accountrecovery.DispatcherConfig{
		DigestKey: config.DigestKey, Keyring: config.DispatchKeys, RecoveryURL: config.RecoveryURL,
		Sender: dependencies.Notifications.RecoverySender(),
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure account recovery dispatcher", err: err}
	}
	handler, err := accountrecoveryhttp.NewHandler(service, dependencies.TrustedContext, accountrecoveryhttp.Config{
		DigestKey: config.DigestKey, Timeout: config.HandlerTimeout, RetryAfter: config.RateWindow,
		Logger: logger,
	})
	if err != nil {
		return nil, runtimeStageError{stage: "configure account recovery HTTP handler", err: err}
	}
	anonymousDispatcher := notification.AnonymousDispatcher(dispatcher)
	if dependencies.RegistrationDispatcher != nil || dependencies.LoginDispatcher != nil {
		login := dependencies.LoginDispatcher
		if dependencies.RegistrationDispatcher == nil && login == nil {
			// The mux needs one account-flow dispatcher; as without the mux, a
			// login event then reaches the recovery dispatcher, which rejects it.
			login = dispatcher
		}
		mux, err := accountregistrationchallenge.NewAnonymousDispatchMux(
			dispatcher, dependencies.RegistrationDispatcher, login,
		)
		if err != nil {
			return nil, runtimeStageError{stage: "configure account recovery account-flow dispatcher mux", err: err}
		}
		anonymousDispatcher = mux
	}
	registration, err := dependencies.Notifications.RegisterAnonymousDispatcher(startupContext, anonymousDispatcher)
	if err != nil {
		return nil, runtimeStageError{stage: "register account recovery anonymous dispatcher", err: err}
	}
	if registration == nil {
		return nil, errors.New("account recovery anonymous dispatcher registration is unavailable")
	}
	return &accountRecoveryRuntime{
		handler: handler, registration: registration, shutdownPeriod: config.ShutdownPeriod,
	}, nil
}

func verifyAccountRecoveryNotificationConfiguration(
	ctx context.Context,
	pool *pgxpool.Pool,
	templates map[notification.Channel]notification.TemplateRef,
) (notification.ChannelSwitches, error) {
	var switches notification.ChannelSwitches
	if err := pool.QueryRow(ctx, `SELECT sms_enabled,email_enabled
		FROM notification_channel_settings WHERE singleton`).Scan(&switches.SMS, &switches.Email); err != nil {
		return notification.ChannelSwitches{}, err
	}
	if !switches.SMS && !switches.Email {
		return notification.ChannelSwitches{}, errors.New("account recovery notification channels are disabled")
	}
	for _, channel := range []notification.Channel{notification.ChannelEmail, notification.ChannelSMS} {
		ref, configured := templates[channel]
		enabled := channel == notification.ChannelEmail && switches.Email ||
			channel == notification.ChannelSMS && switches.SMS
		if enabled && !configured {
			return notification.ChannelSwitches{}, errors.New("enabled account recovery notification channel has no template")
		}
		if !configured {
			continue
		}
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM notification_templates
			WHERE template_id=$1 AND version=$2 AND channel=$3
			  AND cardinality(variables)=0
		)`, ref.ID, ref.Version, ref.Channel).Scan(&valid); err != nil {
			return notification.ChannelSwitches{}, err
		}
		if !valid {
			return notification.ChannelSwitches{}, errors.New("account recovery notification template is unavailable or requires variables")
		}
	}
	return switches, nil
}

func (runtime *accountRecoveryRuntime) Health() accountRecoveryHealthSnapshot {
	if runtime == nil {
		return accountRecoveryHealthSnapshot{State: "disabled"}
	}
	if runtime.closed.Load() {
		return accountRecoveryHealthSnapshot{Enabled: true, State: "stopped"}
	}
	return accountRecoveryHealthSnapshot{
		Enabled: true, State: "ready", DispatcherRegistered: runtime.registration != nil,
		NotificationRuntimeReady: runtime.registration != nil,
	}
}

func (runtime *accountRecoveryRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.closeOnce.Do(func() {
		runtime.closed.Store(true)
		if runtime.registration == nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), runtime.shutdownPeriod)
		defer cancel()
		closed := make(chan error, 1)
		go func() { closed <- runtime.registration.Close(ctx) }()
		select {
		case err := <-closed:
			if err != nil {
				runtime.closeErr = runtimeStageError{stage: "close account recovery dispatcher registration", err: err}
			}
		case <-ctx.Done():
			runtime.closeErr = runtimeStageError{stage: "close account recovery dispatcher registration", err: ctx.Err()}
		}
	})
	return runtime.closeErr
}

func withAccountRecoveryRoutes(next http.Handler, runtime *accountRecoveryRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != accountRecoveryRequestPath && request.URL.Path != accountRecoveryConfirmationPath {
			next.ServeHTTP(writer, request)
			return
		}
		if runtime == nil || runtime.handler == nil {
			requestID := ""
			if values := request.Header.Values("X-Request-ID"); len(values) == 1 && validRuntimeRequestID(values[0]) {
				requestID = values[0]
			} else {
				requestID = uuid.NewString()
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			writer.Header().Set("X-Content-Type-Options", "nosniff")
			writer.Header().Set("Referrer-Policy", "no-referrer")
			writer.Header().Set("X-Request-ID", requestID)
			writer.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"error": map[string]string{
					"code": "account_recovery_unavailable", "request_id": requestID,
				},
			})
			return
		}
		publicRequest := request.Clone(request.Context())
		publicRequest.Header = request.Header.Clone()
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key"} {
			publicRequest.Header.Del(name)
		}
		runtime.handler.ServeHTTP(writer, publicRequest)
	})
}

func withControlRuntimeHealthDetail(
	next http.Handler,
	analyticsRuntime *analyticsIngestProcessRuntime,
	accountRuntime *accountRecoveryRuntime,
) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/health/detail" {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(struct {
				AnalyticsIngest analyticsIngestHealthSnapshot `json:"analytics_ingest"`
				AccountRecovery accountRecoveryHealthSnapshot `json:"account_recovery"`
			}{AnalyticsIngest: analyticsRuntime.Health(), AccountRecovery: accountRuntime.Health()})
			return
		}
		next.ServeHTTP(writer, request)
	})
}
