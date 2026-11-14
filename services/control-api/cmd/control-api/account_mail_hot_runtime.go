package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/jackc/pgx/v5"
)

// accountMailRetryInterval: a sender that could not be built is tried again
// after this long when no settings revision changes in between.
const accountMailRetryInterval = 5 * time.Minute

// accountMailParts is one built account flow runtime (login codes, built-in
// registration codes, Turnstile registration) as the slot serves it.
type accountMailParts struct {
	handler    http.Handler
	dispatcher notification.AnonymousDispatcher
	consumer   identity.LoginChallengeConsumer
	email, sms bool
	close      func() error
}

type accountMailGeneration struct {
	parts    accountMailParts
	inflight sync.WaitGroup
}

// accountMailSlot holds an account flow runtime of the auto notification
// mode and swaps it whole when the system settings change: requests and
// sends already running finish on the old one, which is closed afterwards.
// A failed build keeps the old one; it is retried on the next revision
// change or after accountMailRetryInterval. The slot is the stable handler,
// dispatcher and login challenge consumer handed out at start.
type accountMailSlot struct {
	name string
	// open builds the runtime for a configuration (nil, nil: the flow has
	// no sender configured)
	open func(context.Context, notificationRuntimeConfig) (*accountMailParts, error)
	// fallback serves requests while the slot is empty (nil: 503)
	fallback http.Handler
	logger   *slog.Logger

	mu        sync.Mutex
	current   *accountMailGeneration
	failed    bool
	retryAt   time.Time
	lastError string
}

func newAccountMailSlot(name string, logger *slog.Logger,
	open func(context.Context, notificationRuntimeConfig) (*accountMailParts, error), initial *accountMailParts, initialErr error) *accountMailSlot {
	if logger == nil {
		logger = slog.Default()
	}
	slot := &accountMailSlot{name: name, open: open, logger: logger}
	if initial != nil {
		slot.current = &accountMailGeneration{parts: *initial}
	}
	if initialErr != nil {
		slot.failed, slot.retryAt, slot.lastError = true, time.Now().Add(accountMailRetryInterval), name+"_unavailable"
	}
	return slot
}

func (slot *accountMailSlot) acquire() *accountMailGeneration {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.current != nil {
		slot.current.inflight.Add(1)
	}
	return slot.current
}

// apply rebuilds the runtime from config: always when changed, otherwise only
// a failed build whose retry time has come.
func (slot *accountMailSlot) apply(ctx context.Context, config notificationRuntimeConfig, changed bool) {
	slot.mu.Lock()
	due := changed || slot.failed && !time.Now().Before(slot.retryAt)
	slot.mu.Unlock()
	if !due {
		return
	}
	// own copy of the secrets: the auto runtime clears its configuration on
	// the next rebuild, while this generation may still be sending
	own := config
	own.SMTP.Password = append([]byte(nil), config.SMTP.Password...)
	own.SMS.AuthToken = append([]byte(nil), config.SMS.AuthToken...)
	own.NativeSMS.AccessKeySecret = append([]byte(nil), config.NativeSMS.AccessKeySecret...)
	parts, err := slot.open(ctx, own)
	if err != nil || parts == nil {
		own.clearSecrets()
	}
	if err != nil {
		slot.mu.Lock()
		slot.failed, slot.retryAt, slot.lastError = true, time.Now().Add(accountMailRetryInterval), slot.name+"_unavailable"
		slot.mu.Unlock()
		// the error text can name the mail server: logs only, not health
		slot.logger.Warn("account flow sender not rebuilt, keeping the previous one", "flow", slot.name, "error", err)
		return
	}
	var next *accountMailGeneration
	if parts != nil {
		closeParts := parts.close
		parts.close = func() error {
			var err error
			if closeParts != nil {
				err = closeParts()
			}
			own.clearSecrets()
			return err
		}
		next = &accountMailGeneration{parts: *parts}
	}
	slot.mu.Lock()
	previous := slot.current
	slot.current, slot.failed, slot.lastError = next, false, ""
	slot.mu.Unlock()
	slot.retire(previous)
}

func (slot *accountMailSlot) retire(generation *accountMailGeneration) {
	if generation == nil {
		return
	}
	go func() {
		generation.inflight.Wait()
		if generation.parts.close != nil {
			if err := generation.parts.close(); err != nil {
				slot.logger.Warn("previous account flow sender close failed", "flow", slot.name, "error", err)
			}
		}
	}()
}

// state: ready, not_configured or degraded (a failed build; the previous
// runtime, if any, still serves).
func (slot *accountMailSlot) state() (string, string) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	switch {
	case slot.failed:
		return "degraded", slot.lastError
	case slot.current == nil:
		return "not_configured", ""
	default:
		return "ready", ""
	}
}

func (slot *accountMailSlot) Close() error {
	slot.mu.Lock()
	current := slot.current
	slot.current = nil
	slot.mu.Unlock()
	if current == nil {
		return nil
	}
	current.inflight.Wait()
	if current.parts.close != nil {
		return current.parts.close()
	}
	return nil
}

func (slot *accountMailSlot) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	generation := slot.acquire()
	if generation == nil || generation.parts.handler == nil {
		if generation != nil {
			generation.inflight.Done()
		}
		if slot.fallback != nil {
			slot.fallback.ServeHTTP(writer, request)
			return
		}
		slot.writeUnavailable(writer)
		return
	}
	defer generation.inflight.Done()
	generation.parts.handler.ServeHTTP(writer, request)
}

func (slot *accountMailSlot) Dispatch(ctx context.Context, attempt notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	generation := slot.acquire()
	if generation == nil || generation.parts.dispatcher == nil {
		if generation != nil {
			generation.inflight.Done()
		}
		// temporary: the outbox retries once the settings make a sender available
		return notification.AnonymousDispatchResult{Failure: &notification.Failure{
			Class: notification.FailureTemporary, Code: "notification_sender_unavailable"}}
	}
	defer generation.inflight.Done()
	return generation.parts.dispatcher.Dispatch(ctx, attempt)
}

var errAccountLoginSenderUnavailable = errors.New("account login sender is unavailable")

func (slot *accountMailSlot) ConsumeLoginChallengeTx(ctx context.Context, tx pgx.Tx, input identity.LoginChallengeConsumeInput) (error, error) {
	generation := slot.acquire()
	if generation == nil || generation.parts.consumer == nil {
		if generation != nil {
			generation.inflight.Done()
		}
		return nil, errAccountLoginSenderUnavailable
	}
	defer generation.inflight.Done()
	return generation.parts.consumer.ConsumeLoginChallengeTx(ctx, tx, input)
}

func (slot *accountMailSlot) LoginChannelAvailable(channel string) bool {
	generation := slot.acquire()
	if generation == nil {
		return false
	}
	defer generation.inflight.Done()
	return generation.parts.consumer != nil && generation.parts.consumer.LoginChannelAvailable(channel)
}

// Channels reports which channels can carry a code now.
func (slot *accountMailSlot) Channels() (email, sms bool) {
	if slot == nil {
		return false, false
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.current == nil {
		return false, false
	}
	return slot.current.parts.email, slot.current.parts.sms
}

var _ http.Handler = (*accountMailSlot)(nil)
var _ notification.AnonymousDispatcher = (*accountMailSlot)(nil)
var _ identity.LoginChallengeConsumer = (*accountMailSlot)(nil)

// accountRecoverySlot holds the account recovery runtime of the auto mode.
// The runtime sends through the auto notification runtime (already hot), so
// only a recovery runtime that could not open is retried: on a revision
// change, or after accountMailRetryInterval.
type accountRecoverySlot struct {
	open   func(context.Context) (*accountRecoveryRuntime, error)
	logger *slog.Logger

	mu      sync.Mutex
	current *accountRecoveryRuntime
	failed  bool
	retryAt time.Time
}

func (slot *accountRecoverySlot) runtime() *accountRecoveryRuntime {
	if slot == nil {
		return nil
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	return slot.current
}

func (slot *accountRecoverySlot) apply(ctx context.Context, changed bool) {
	slot.mu.Lock()
	due := slot.current == nil && slot.failed && (changed || !time.Now().Before(slot.retryAt))
	slot.mu.Unlock()
	if !due {
		return
	}
	runtime, err := slot.open(ctx)
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if err != nil || runtime == nil {
		slot.retryAt = time.Now().Add(accountMailRetryInterval)
		if err != nil {
			slot.logger.Warn("account recovery runtime still unavailable", "error", err)
		}
		return
	}
	slot.current, slot.failed = runtime, false
	slot.logger.Info("account recovery runtime available")
}

func (slot *accountRecoverySlot) state() (string, string) {
	slot.mu.Lock()
	defer slot.mu.Unlock()
	switch {
	case slot.current != nil:
		return "ready", ""
	case slot.failed:
		return "degraded", "account_recovery_unavailable"
	default:
		return "not_configured", ""
	}
}

func (slot *accountRecoverySlot) Health() accountRecoveryHealthSnapshot {
	return slot.runtime().Health()
}

func (slot *accountRecoverySlot) Close() error {
	return slot.runtime().Close()
}

// accountMailRuntimes are the account flow slots the auto notification
// runtime rebuilds with its outbox worker (same 15 second revision check).
type accountMailRuntimes struct {
	slots    []*accountMailSlot
	recovery *accountRecoverySlot
}

func (runtimes *accountMailRuntimes) apply(ctx context.Context, config notificationRuntimeConfig, changed bool) {
	if runtimes == nil {
		return
	}
	for _, slot := range runtimes.slots {
		slot.apply(ctx, config, changed)
	}
	if runtimes.recovery != nil {
		runtimes.recovery.apply(ctx, changed)
	}
}

// health: state per flow and the first failed build's code.
func (runtimes *accountMailRuntimes) health() (map[string]string, string) {
	if runtimes == nil {
		return nil, ""
	}
	states := map[string]string{}
	var firstError string
	note := func(name, state, code string) {
		states[name] = state
		if firstError == "" && code != "" {
			firstError = code
		}
	}
	for _, slot := range runtimes.slots {
		state, code := slot.state()
		note(slot.name, state, code)
	}
	if runtimes.recovery != nil {
		state, code := runtimes.recovery.state()
		note("account_recovery", state, code)
	}
	return states, firstError
}

// accountRecoveryHealthSource is *accountRecoveryRuntime or the slot.
type accountRecoveryHealthSource interface {
	Health() accountRecoveryHealthSnapshot
}

// HandlerFactory mounts the slot (nil slot: the explicit mode's factory).
func (slot *accountMailSlot) HandlerFactory(explicit httpapi.MountedHandlerFactory) httpapi.MountedHandlerFactory {
	if slot == nil {
		return explicit
	}
	return func() (http.Handler, error) { return slot, nil }
}

// ChallengeHandler is the built-in registration challenge handler (nil
// slot: the explicit mode's handler).
func (slot *accountMailSlot) ChallengeHandler(explicit http.Handler) http.Handler {
	if slot == nil {
		return explicit
	}
	return slot
}

// SetLoginMethodsFallback: while the login slot is empty GET
// /v1/auth/login-methods answers as with no login runtime mounted. Called
// before the server serves.
func (slot *accountMailSlot) SetLoginMethodsFallback(disabled http.Handler) {
	if slot == nil || disabled == nil {
		return
	}
	slot.fallback = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/v1/auth/login-methods" {
			disabled.ServeHTTP(writer, request)
			return
		}
		slot.writeUnavailable(writer)
	})
}

func (slot *accountMailSlot) writeUnavailable(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusServiceUnavailable)
	_, _ = writer.Write([]byte(`{"error":{"code":"` + slot.name + `_unavailable"}}` + "\n"))
}

// registerBuiltInRegistrationAlone is RegisterAlone for a dispatcher that
// follows rebuilds (the built-in registration slot).
func registerBuiltInRegistrationAlone(ctx context.Context, dispatcher notification.AnonymousDispatcher,
	notifications accountRecoveryNotificationBridge) (accountRecoveryDispatcherRegistration, error) {
	mux, err := accountregistrationchallenge.NewAnonymousDispatchMux(dispatcher, dispatcher)
	if err != nil {
		return nil, err
	}
	return notifications.RegisterAnonymousDispatcher(ctx, mux)
}

// accountMailStartError: a flow without a configured sender at start is
// not configured, not failed.
func accountMailStartError(configured bool, err error) error {
	if !configured {
		return nil
	}
	return err
}
