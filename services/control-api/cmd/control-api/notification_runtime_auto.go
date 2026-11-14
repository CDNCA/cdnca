package main

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/jackc/pgx/v5/pgxpool"
)

// notificationAutoPollInterval: how often the auto runtime reads the two
// settings revisions (one single-row query); a change rebuilds the outbox
// worker, so a channel switch or a sender saved on the settings page sends
// from the next batch on, without restarting control-api.
const notificationAutoPollInterval = 15 * time.Second

// notificationAutoRuntime owns the outbox worker of the auto mode
// (NOTIFICATION_RUNTIME_ENABLED unset/auto/false). Unlike the explicit mode
// it never fails the process: an incomplete page or switched-off channels
// only leave the worker stopped until the settings change. It also stands in
// for the worker towards anonymous dispatchers (built-in registration codes,
// account recovery), re-registering them on every rebuilt worker.
type notificationAutoRuntime struct {
	base         notificationRuntimeConfig // environment only, before any merge
	cfg          config.Config
	pool         *pgxpool.Pool
	dependencies notificationRuntimeDependencies
	granted      func(context.Context, string) (bool, error)
	logger       *slog.Logger

	mu          sync.Mutex
	current     *notificationProcessRuntime
	config      notificationRuntimeConfig
	fingerprint [2]int64
	// owned: config was built here (the startup one is shared with the
	// login/registration senders and must not be cleared)
	owned bool
	// retryAt: a worker that could not start (sender not answering) is
	// tried again then, or at once when a revision changes
	retryAt     time.Time
	dispatchers map[*notificationAutoRegistration]notification.AnonymousDispatcher
	// accounts: the login / registration / recovery senders rebuilt with
	// the worker (SetAccountRuntimes)
	accounts *accountMailRuntimes
	// health: switches read with the revisions; rebuild progress and the
	// last rebuild's error code (never a server address or secret)
	switches         notification.ChannelSwitches
	switchesKnown    bool
	rebuilding       bool
	lastRebuildAt    time.Time
	lastRebuildError string
}

// SetAccountRuntimes hands the account flow senders to the revision check.
func (auto *notificationAutoRuntime) SetAccountRuntimes(accounts *accountMailRuntimes) {
	auto.mu.Lock()
	auto.accounts = accounts
	auto.mu.Unlock()
}

func newNotificationAutoRuntime(base notificationRuntimeConfig, startup notificationRuntimeConfig, cfg config.Config,
	pool *pgxpool.Pool, dependencies notificationRuntimeDependencies) *notificationAutoRuntime {
	if dependencies.Logger == nil {
		dependencies.Logger = slog.Default()
	}
	return &notificationAutoRuntime{base: base, cfg: cfg, pool: pool, dependencies: dependencies, logger: dependencies.Logger,
		config: startup, fingerprint: [2]int64{-1, -1},
		dispatchers: map[*notificationAutoRegistration]notification.AnonymousDispatcher{}}
}

// Transports is the live notificationcontrol.ChannelTransports source.
func (auto *notificationAutoRuntime) Transports() notificationcontrol.ChannelTransports {
	auto.mu.Lock()
	defer auto.mu.Unlock()
	return notificationChannelTransports(auto.config)
}

// Start builds the first worker (when the settings allow) and polls the
// revisions until ctx ends.
func (auto *notificationAutoRuntime) Start(ctx context.Context, granted func(context.Context, string) (bool, error)) {
	auto.granted = granted
	auto.refresh(ctx)
	go func() {
		ticker := time.NewTicker(notificationAutoPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				auto.refresh(ctx)
			}
		}
	}()
}

func (auto *notificationAutoRuntime) refresh(ctx context.Context) {
	var fingerprint [2]int64
	var switches notification.ChannelSwitches
	if err := auto.pool.QueryRow(ctx, `SELECT
		coalesce((SELECT revision FROM notification_channel_settings WHERE singleton),0),
		coalesce((SELECT email_enabled FROM notification_channel_settings WHERE singleton),false),
		coalesce((SELECT sms_enabled FROM notification_channel_settings WHERE singleton),false),
		coalesce((SELECT max(revision) FROM platform_system_mail_settings),0)`).Scan(
		&fingerprint[0], &switches.Email, &switches.SMS, &fingerprint[1]); err != nil {
		return // the database is back on a later tick
	}
	auto.mu.Lock()
	auto.switches, auto.switchesKnown = switches, true
	running := auto.current != nil && !auto.current.stopped.Load() && !auto.current.closing.Load()
	if fingerprint == auto.fingerprint && (running || !auto.config.Enabled || time.Now().Before(auto.retryAt)) {
		// worker current: only account senders whose retry time has come
		accounts, config := auto.accounts, auto.config
		auto.mu.Unlock()
		accounts.apply(ctx, config, false)
		return
	}
	auto.mu.Unlock()
	auto.rebuild(ctx, fingerprint)
}

// rebuild replaces the worker with one for the current settings.
func (auto *notificationAutoRuntime) rebuild(ctx context.Context, fingerprint [2]int64) {
	auto.mu.Lock()
	auto.rebuilding = true
	auto.mu.Unlock()
	var rebuildError string
	next := auto.base
	// own copies: the previous configuration's secrets are cleared below
	next.SMTP.Password = append([]byte(nil), auto.base.SMTP.Password...)
	next.SMS.AuthToken = append([]byte(nil), auto.base.SMS.AuthToken...)
	next.NativeSMS.AccessKeySecret = append([]byte(nil), auto.base.NativeSMS.AccessKeySecret...)
	next.Unavailable = nil
	if err := applyPersistedNotificationSettings(ctx, auto.cfg, auto.pool, &next); err != nil {
		next.unavailable("settings", err.Error())
		rebuildError = "settings_unreadable"
	}
	resolveNotificationRuntime(&next)
	next.Mail.Granted = auto.granted
	var runtime *notificationProcessRuntime
	if next.Enabled {
		var err error
		runtime, err = openNotificationProcessRuntime(ctx, next, auto.pool, auto.dependencies)
		if err != nil {
			// e.g. both channels switched off: retried when a revision changes
			auto.logger.Info("notification outbox worker not running", "error", err)
			runtime = nil
			if rebuildError == "" {
				rebuildError = "worker_start_failed"
			}
		}
	}
	auto.mu.Lock()
	previous, previousConfig, previousOwned := auto.current, auto.config, auto.owned
	changed := fingerprint != auto.fingerprint
	accounts := auto.accounts
	auto.current, auto.config, auto.fingerprint, auto.owned = runtime, next, fingerprint, true
	auto.retryAt = time.Now().Add(5 * time.Minute)
	dispatchers := make(map[*notificationAutoRegistration]notification.AnonymousDispatcher, len(auto.dispatchers))
	for registration, dispatcher := range auto.dispatchers {
		dispatchers[registration] = dispatcher
	}
	auto.mu.Unlock()
	for registration, dispatcher := range dispatchers {
		registration.attach(ctx, runtime, dispatcher, auto.logger)
	}
	if runtime != nil {
		go func() {
			if err := runWithDBBackoff(ctx, auto.logger, "notification runtime", 5*time.Minute, runtime.Run); err != nil && ctx.Err() == nil {
				auto.logger.Warn("notification outbox worker stopped", "error", err)
			}
		}()
	}
	if previous != nil {
		_ = previous.Close()
	}
	// after the worker: the recovery runtime needs it ready; the account
	// senders copy the secrets they keep
	accounts.apply(ctx, next, changed)
	if _, code := accounts.health(); rebuildError == "" {
		rebuildError = code
	}
	if previousOwned {
		previousConfig.clearSecrets()
	}
	for channel, reason := range next.Unavailable {
		auto.logger.Info("notification channel unavailable", "channel", channel, "reason", reason)
	}
	auto.mu.Lock()
	auto.rebuilding, auto.lastRebuildAt, auto.lastRebuildError = false, time.Now().UTC(), rebuildError
	auto.mu.Unlock()
}

func (auto *notificationAutoRuntime) Close() {
	auto.mu.Lock()
	current := auto.current
	auto.current = nil
	auto.mu.Unlock()
	if current != nil {
		_ = current.Close()
	}
}

func (auto *notificationAutoRuntime) worker() *notificationProcessRuntime {
	auto.mu.Lock()
	defer auto.mu.Unlock()
	return auto.current
}

// Ready, RecoverySender and RegisterAnonymousDispatcher make the auto
// runtime an accountRecoveryNotificationBridge that follows rebuilds.
func (auto *notificationAutoRuntime) Ready(ctx context.Context, switches notification.ChannelSwitches) error {
	if worker := auto.worker(); worker != nil {
		return worker.Ready(ctx, switches)
	}
	return notificationruntime.ErrWorkerNotRunning
}

func (auto *notificationAutoRuntime) RecoverySender() accountrecovery.RecoverySender {
	return notificationAutoRecoverySender{auto: auto}
}

type notificationAutoRecoverySender struct{ auto *notificationAutoRuntime }

func (sender notificationAutoRecoverySender) SendRecovery(ctx context.Context, delivery accountrecovery.RecoveryDelivery) notification.SendResult {
	if worker := sender.auto.worker(); worker != nil {
		if current := worker.RecoverySender(); current != nil {
			return current.SendRecovery(ctx, delivery)
		}
	}
	// temporary: the outbox retries once the settings make a sender available
	return notification.SendResult{Failure: &notification.Failure{Class: notification.FailureTemporary, Code: "notification_sender_unavailable"}}
}

func (auto *notificationAutoRuntime) RegisterAnonymousDispatcher(ctx context.Context, dispatcher notification.AnonymousDispatcher) (
	accountRecoveryDispatcherRegistration, error) {
	if dispatcher == nil {
		return nil, errors.New("notification anonymous dispatcher is required")
	}
	registration := &notificationAutoRegistration{auto: auto}
	auto.mu.Lock()
	auto.dispatchers[registration] = dispatcher
	current := auto.current
	auto.mu.Unlock()
	registration.attach(ctx, current, dispatcher, auto.logger)
	return registration, nil
}

// notificationAutoRegistration is one dispatcher, registered again on every
// rebuilt worker.
type notificationAutoRegistration struct {
	auto  *notificationAutoRuntime
	mu    sync.Mutex
	inner accountRecoveryDispatcherRegistration
}

func (registration *notificationAutoRegistration) attach(ctx context.Context, worker *notificationProcessRuntime,
	dispatcher notification.AnonymousDispatcher, logger *slog.Logger) {
	registration.mu.Lock()
	defer registration.mu.Unlock()
	// the previous worker's registry goes away with that worker
	registration.inner = nil
	if worker == nil {
		return
	}
	inner, err := worker.RegisterAnonymousDispatcher(ctx, dispatcher)
	if err != nil {
		logger.Warn("notification anonymous dispatcher not registered", "error", err)
		return
	}
	registration.inner = inner
}

func (registration *notificationAutoRegistration) Close(ctx context.Context) error {
	registration.auto.mu.Lock()
	delete(registration.auto.dispatchers, registration)
	registration.auto.mu.Unlock()
	registration.mu.Lock()
	inner := registration.inner
	registration.inner = nil
	registration.mu.Unlock()
	if inner != nil {
		return inner.Close(ctx)
	}
	return nil
}

var _ accountRecoveryNotificationBridge = (*notificationAutoRuntime)(nil)

// Health is the current worker's snapshot plus the per-channel states, the
// account senders and the last rebuild.
func (auto *notificationAutoRuntime) Health() notificationRuntimeHealthSnapshot {
	auto.mu.Lock()
	snapshot := auto.current.Health()
	snapshot.Mode = "auto"
	var switches *notification.ChannelSwitches
	if auto.switchesKnown {
		known := auto.switches
		switches = &known
	}
	snapshot.Channels = notificationChannelsHealth(auto.config, snapshot.WorkerRunning, switches, auto.rebuilding)
	if !auto.lastRebuildAt.IsZero() {
		snapshot.LastRebuildAt = auto.lastRebuildAt.Format(time.RFC3339)
	}
	snapshot.LastRebuildError = auto.lastRebuildError
	accounts := auto.accounts
	auto.mu.Unlock()
	snapshot.AccountSenders, _ = accounts.health()
	return snapshot
}

// notificationHealthSource is the health of the notification runtime the
// process runs: auto, explicit or off.
func notificationHealthSource(config notificationRuntimeConfig, runtime *notificationProcessRuntime,
	auto *notificationAutoRuntime) func() notificationRuntimeHealthSnapshot {
	if auto != nil {
		return auto.Health
	}
	return func() notificationRuntimeHealthSnapshot {
		snapshot := runtime.Health()
		snapshot.Mode = "explicit"
		if !config.Requested {
			snapshot.Mode = "off"
		}
		snapshot.Channels = notificationChannelsHealth(config, snapshot.WorkerRunning, nil, false)
		return snapshot
	}
}

// notificationChannelsHealth: reasons are fixed codes, so the output never
// carries an address, account name or secret from the settings.
func notificationChannelsHealth(config notificationRuntimeConfig, workerRunning bool,
	switches *notification.ChannelSwitches, rebuilding bool) map[string]notificationChannelHealth {
	transports := notificationChannelTransports(config)
	channels := make(map[string]notificationChannelHealth, 2)
	for _, channel := range []struct {
		name       string
		configured bool
		on         bool
	}{
		{"email", transports.Email, switches == nil || switches.Email},
		{"sms", transports.SMS, switches == nil || switches.SMS},
	} {
		health := notificationChannelHealth{State: "ready"}
		switch {
		case rebuilding:
			health = notificationChannelHealth{State: "rebuilding"}
		case !config.Requested:
			health = notificationChannelHealth{State: "disabled_by_env"}
		case !channel.configured && config.Unavailable[channel.name] != "":
			health = notificationChannelHealth{State: "degraded", Reason: "config_incomplete"}
		case !channel.configured && config.Unavailable["settings"] != "":
			health = notificationChannelHealth{State: "degraded", Reason: "settings_unreadable"}
		case !channel.configured:
			health = notificationChannelHealth{State: "not_configured"}
		case !channel.on:
			health = notificationChannelHealth{State: "degraded", Reason: "channel_switched_off"}
		case !workerRunning:
			health = notificationChannelHealth{State: "degraded", Reason: "worker_not_running"}
		}
		channels[channel.name] = health
	}
	return channels
}

func notificationHealthOrDisabled(health func() notificationRuntimeHealthSnapshot) notificationRuntimeHealthSnapshot {
	if health == nil {
		return notificationRuntimeHealthSnapshot{State: "disabled"}
	}
	return health()
}
