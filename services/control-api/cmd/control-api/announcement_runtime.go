package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/announcementhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationcontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationhttp"
	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	announcementExternalChannelDisabled = "disabled"
	announcementFailureThreshold        = 3
	announcementStateReady              = "ready"
	announcementStateRunning            = "running"
	announcementStateFailed             = "failed"
	announcementStateBackoff            = "backoff"
	announcementStateStopped            = "stopped"
)

type announcementRuntimeConfig struct {
	Enabled          bool
	ExternalChannel  string
	PollInterval     time.Duration
	OperationTimeout time.Duration
	ShutdownTimeout  time.Duration
	StartupTimeout   time.Duration
	BatchSize        int
	CursorKeyring    announcement.CursorKeyring
	Now              func() time.Time
}

func (config *announcementRuntimeConfig) clearSecrets() {
	if config == nil {
		return
	}
	for keyID, key := range config.CursorKeyring.Keys {
		clear(key)
		delete(config.CursorKeyring.Keys, keyID)
	}
	config.CursorKeyring = announcement.CursorKeyring{}
}

type announcementRuntime struct {
	store               *announcement.Store
	publishDue          func(context.Context, int) ([]announcement.Announcement, error)
	notificationControl *notificationcontrol.Store
	config              announcementRuntimeConfig
	context             context.Context
	cancel              context.CancelFunc
	runMu               sync.Mutex
	done                chan struct{}
	closeOnce           sync.Once
	started             atomic.Bool
	running             bool
	closed              atomic.Bool
	state               atomic.Value
	lastErrorCode       atomic.Value
	published           atomic.Uint64
	publishAttempts     atomic.Uint64
	failures            atomic.Uint64
	consecutiveFail     atomic.Uint32
}

func buildNotificationHandlerFactory(pool *pgxpool.Pool, now func() time.Time, transports notificationcontrol.ChannelTransports) (httpapi.NotificationHandlerFactory, error) {
	if pool == nil || now == nil {
		return nil, errors.New("notification control HTTP dependencies are required")
	}
	control, err := notificationcontrol.NewStoreWithDependencies(pool, audit.New(pool), now)
	if err != nil {
		return nil, err
	}
	control.WithChannelTransports(transports)
	return func(authenticate notificationhttp.AuthenticateFunc) (http.Handler, error) {
		return notificationhttp.New(control, authenticate)
	}, nil
}

type announcementRuntimeHealth struct {
	Enabled         bool   `json:"enabled"`
	State           string `json:"state"`
	ExternalChannel string `json:"external_channel"`
	PublishedTotal  uint64 `json:"published_total"`
	FailureTotal    uint64 `json:"failure_total"`
	LastErrorCode   string `json:"last_error_code,omitempty"`
}

func loadAnnouncementRuntimeConfig(lookup func(string) (string, bool)) (announcementRuntimeConfig, error) {
	if lookup == nil {
		return announcementRuntimeConfig{}, errors.New("announcement environment lookup is required")
	}
	enabled := false
	if raw, ok := lookup("ANNOUNCEMENT_ENABLED"); ok && raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return announcementRuntimeConfig{}, errors.New("ANNOUNCEMENT_ENABLED must be a boolean")
		}
		enabled = parsed
	}
	if !enabled {
		return announcementRuntimeConfig{}, nil
	}
	channel, ok := lookup("ANNOUNCEMENT_EXTERNAL_CHANNEL")
	if !ok || channel != announcementExternalChannelDisabled {
		return announcementRuntimeConfig{}, errors.New("ANNOUNCEMENT_EXTERNAL_CHANNEL must explicitly be disabled until external delivery is configured")
	}
	interval, err := announcementDuration(lookup, "ANNOUNCEMENT_POLL_INTERVAL", 5*time.Second, time.Second, time.Minute)
	if err != nil {
		return announcementRuntimeConfig{}, err
	}
	operationTimeout, err := announcementDuration(lookup, "ANNOUNCEMENT_OPERATION_TIMEOUT", 3*time.Second, time.Second, 30*time.Second)
	if err != nil {
		return announcementRuntimeConfig{}, err
	}
	shutdownTimeout, err := announcementDuration(lookup, "ANNOUNCEMENT_SHUTDOWN_TIMEOUT", 5*time.Second, time.Second, 30*time.Second)
	if err != nil {
		return announcementRuntimeConfig{}, err
	}
	startupTimeout, err := announcementDuration(lookup, "ANNOUNCEMENT_STARTUP_TIMEOUT", 5*time.Second, time.Second, 30*time.Second)
	if err != nil {
		return announcementRuntimeConfig{}, err
	}
	batch := 100
	if raw, ok := lookup("ANNOUNCEMENT_BATCH_SIZE"); ok && raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			return announcementRuntimeConfig{}, errors.New("ANNOUNCEMENT_BATCH_SIZE must be between 1 and 1000")
		}
		batch = parsed
	}
	keyring, err := loadAnnouncementCursorKeyring(lookup)
	if err != nil {
		return announcementRuntimeConfig{}, err
	}
	return announcementRuntimeConfig{
		Enabled: true, ExternalChannel: channel, PollInterval: interval, OperationTimeout: operationTimeout,
		ShutdownTimeout: shutdownTimeout, StartupTimeout: startupTimeout, BatchSize: batch, CursorKeyring: keyring,
	}, nil
}

func announcementDuration(lookup func(string) (string, bool), name string, fallback, minimum, maximum time.Duration) (time.Duration, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be between %s and %s", name, minimum, maximum)
	}
	return parsed, nil
}

func loadAnnouncementCursorKeyring(lookup func(string) (string, bool)) (announcement.CursorKeyring, error) {
	active, ok := lookup("ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID")
	if !ok || !validAnnouncementKeyID(active) {
		return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID must be a valid key identifier")
	}
	raw, ok := lookup("ANNOUNCEMENT_CURSOR_KEYS_JSON")
	if !ok || strings.TrimSpace(raw) != raw {
		return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_KEYS_JSON must be a non-empty JSON object")
	}
	encoded, err := decodeAnnouncementCursorKeys(raw)
	if err != nil || len(encoded) == 0 || len(encoded) > 8 {
		return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_KEYS_JSON must be a non-empty JSON object with at most 8 keys")
	}
	keys := make(map[string][]byte, len(encoded))
	failed := true
	defer func() {
		if failed {
			for _, key := range keys {
				clear(key)
			}
		}
	}()
	for keyID, value := range encoded {
		if !validAnnouncementKeyID(keyID) {
			return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_KEYS_JSON contains an invalid key identifier")
		}
		key, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(key) < 32 || len(key) > 64 || base64.StdEncoding.EncodeToString(key) != value {
			return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_KEYS_JSON values must encode 32 to 64 bytes using canonical padded base64")
		}
		keys[keyID] = key
	}
	if _, ok := keys[active]; !ok {
		return announcement.CursorKeyring{}, errors.New("ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID must exist in ANNOUNCEMENT_CURSOR_KEYS_JSON")
	}
	failed = false
	return announcement.CursorKeyring{ActiveKID: active, Keys: keys}, nil
}

func decodeAnnouncementCursorKeys(raw string) (map[string]string, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("invalid cursor key object")
	}
	keys := make(map[string]string)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid cursor key identifier")
		}
		if _, duplicate := keys[key]; duplicate {
			return nil, errors.New("duplicate cursor key identifier")
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid cursor key value")
		}
		keys[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, errors.New("invalid cursor key object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid cursor key object")
	}
	return keys, nil
}

func validAnnouncementKeyID(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		alphaNumeric := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !(alphaNumeric || character == '.' || character == '_' || character == '-') || index == 0 && !alphaNumeric {
			return false
		}
	}
	return true
}

func loadAnnouncementRuntimeConfigFromEnv() (announcementRuntimeConfig, error) {
	return loadAnnouncementRuntimeConfigFromEnvEntries(os.Environ())
}

func loadAnnouncementRuntimeConfigFromEnvEntries(entries []string) (announcementRuntimeConfig, error) {
	allowed := map[string]struct{}{
		"ANNOUNCEMENT_ENABLED":              {},
		"ANNOUNCEMENT_EXTERNAL_CHANNEL":     {},
		"ANNOUNCEMENT_POLL_INTERVAL":        {},
		"ANNOUNCEMENT_OPERATION_TIMEOUT":    {},
		"ANNOUNCEMENT_SHUTDOWN_TIMEOUT":     {},
		"ANNOUNCEMENT_STARTUP_TIMEOUT":      {},
		"ANNOUNCEMENT_BATCH_SIZE":           {},
		"ANNOUNCEMENT_CURSOR_ACTIVE_KEY_ID": {},
		"ANNOUNCEMENT_CURSOR_KEYS_JSON":     {},
	}
	values := make(map[string]string)
	for _, entry := range entries {
		name, value, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(name, "ANNOUNCEMENT_") {
			continue
		}
		if _, ok := allowed[name]; !ok {
			return announcementRuntimeConfig{}, fmt.Errorf("unknown announcement environment variable %s", name)
		}
		if _, duplicate := values[name]; duplicate {
			return announcementRuntimeConfig{}, fmt.Errorf("duplicate announcement environment variable %s", name)
		}
		values[name] = value
	}
	return loadAnnouncementRuntimeConfig(func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	})
}

func openAnnouncementRuntime(ctx context.Context, pool *pgxpool.Pool, config announcementRuntimeConfig) (*announcementRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	defer config.clearSecrets()
	if ctx == nil || pool == nil || config.ExternalChannel != announcementExternalChannelDisabled ||
		config.PollInterval < time.Second || config.OperationTimeout < time.Second || config.ShutdownTimeout < time.Second ||
		config.StartupTimeout < time.Second || config.BatchSize < 1 {
		return nil, errors.New("announcement runtime configuration is incomplete")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	startupContext, cancelStartup := context.WithTimeout(ctx, config.StartupTimeout)
	defer cancelStartup()
	if err := probeAnnouncementSchema(startupContext, pool); err != nil {
		return nil, runtimeStageError{stage: "probe announcement schema", err: err}
	}
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize announcement notification store", err: err}
	}
	publicationOutbox, err := newAnnouncementNotificationOutbox(notificationStore)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize announcement notification outbox", err: err}
	}
	notificationControl, err := notificationcontrol.NewStoreWithDependencies(pool, audit.New(pool), now)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize notification control store", err: err}
	}
	authorizationService, err := rbacmanager.NewServiceWithDependencies(pool, audit.New(pool), announcementDisabledStepUpVerifier{}, now)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize announcement authorization", err: err}
	}
	authorizer := announcementRBACAuthorizer{service: authorizationService}
	store, err := announcement.NewStoreWithDependencies(
		pool, audit.New(pool), publicationOutbox, now, config.CursorKeyring, authorizer,
	)
	if err != nil {
		return nil, runtimeStageError{stage: "initialize announcement store", err: err}
	}
	runContext, cancel := context.WithCancel(ctx)
	runtime := &announcementRuntime{
		store: store, publishDue: store.PublishDue, notificationControl: notificationControl, config: config,
		context: runContext, cancel: cancel, done: make(chan struct{}),
	}
	runtime.state.Store(announcementStateReady)
	runtime.lastErrorCode.Store("")
	return runtime, nil
}

func probeAnnouncementSchema(ctx context.Context, pool *pgxpool.Pool) error {
	var ready bool
	err := pool.QueryRow(ctx, `SELECT
		to_regclass('announcements') IS NOT NULL AND
		to_regclass('announcement_versions') IS NOT NULL AND
		to_regclass('announcement_state_watermarks') IS NOT NULL AND
		to_regclass('announcement_state_facts') IS NOT NULL AND
		to_regclass('announcement_audience_users') IS NOT NULL AND
		to_regclass('announcement_audience_groups') IS NOT NULL AND
		to_regclass('announcement_recipient_snapshots') IS NOT NULL AND
		to_regclass('announcement_inbox_events') IS NOT NULL AND
		to_regclass('announcement_inbox_states') IS NOT NULL AND
		to_regclass('announcement_write_requests') IS NOT NULL AND
		to_regclass('platform_announcements_141') IS NOT NULL AND
		to_regclass('platform_announcement_recipients_141') IS NOT NULL AND
		to_regprocedure('next_announcement_state_watermark(uuid)') IS NOT NULL`).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("announcement schema 141 is unavailable")
	}
	return nil
}

func (runtime *announcementRuntime) HandlerFactory() httpapi.AnnouncementHandlerFactory {
	if runtime == nil || runtime.store == nil {
		return nil
	}
	return func(authenticate announcementhttp.AuthenticateFunc) (http.Handler, error) {
		if authenticate == nil {
			return nil, errors.New("announcement authentication is unavailable")
		}
		handler, err := announcementhttp.New(runtime.store, authenticate)
		if err != nil {
			return nil, errors.New("initialize announcement HTTP handler")
		}
		notificationHandler, err := notificationhttp.New(runtime.notificationControl, func(request *http.Request) (identity.AuthenticatedSession, error) {
			session, err := authenticate(request)
			return identity.AuthenticatedSession{SessionID: session.SessionID, Principal: session.Principal}, err
		})
		if err != nil {
			return nil, errors.New("initialize notification control HTTP handler")
		}
		mux := http.NewServeMux()
		mux.Handle("/v1/admin/notifications/", notificationHandler)
		mux.Handle("/v1/account/notification-subscriptions/", notificationHandler)
		mux.Handle("/", handler.Handler())
		return mux, nil
	}
}

func (runtime *announcementRuntime) Run(context.Context) error {
	if runtime == nil || runtime.store == nil || runtime.publishDue == nil {
		return errors.New("announcement runtime cannot be started")
	}
	// Only one Run at a time. After Run returned on a temporarily unavailable
	// database, runWithDBBackoff calls Run again with a fresh done channel;
	// Close ends this for good.
	runtime.runMu.Lock()
	if runtime.running || runtime.closed.Load() {
		runtime.runMu.Unlock()
		return errors.New("announcement runtime cannot be started")
	}
	if runtime.started.Load() {
		runtime.done = make(chan struct{})
	}
	runtime.started.Store(true)
	runtime.running = true
	done := runtime.done
	runtime.runMu.Unlock()
	defer func() {
		runtime.runMu.Lock()
		runtime.running = false
		close(done)
		runtime.runMu.Unlock()
	}()
	runtime.state.Store(announcementStateRunning)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-runtime.context.Done():
			runtime.state.Store(announcementStateStopped)
			return nil
		case <-timer.C:
			runtime.publishAttempts.Add(1)
			operationContext, cancel := context.WithTimeout(runtime.context, runtime.config.OperationTimeout)
			published, err := runtime.publishDue(operationContext, runtime.config.BatchSize)
			cancel()
			if runtime.context.Err() != nil {
				runtime.state.Store(announcementStateStopped)
				return nil
			}
			if err != nil {
				runtime.failures.Add(1)
				runtime.lastErrorCode.Store("publish_due_failed")
				if isTransientDBError(err) {
					// Not counted as a scheduler failure: the caller backs off
					// and runs the scheduler again.
					runtime.state.Store(announcementStateBackoff)
					return fmt.Errorf("announcement scheduler database unavailable: %w", err)
				}
				if runtime.consecutiveFail.Add(1) >= announcementFailureThreshold {
					runtime.state.Store(announcementStateFailed)
					return fmt.Errorf("announcement scheduler failed %d consecutive times: %w", announcementFailureThreshold, err)
				}
			} else {
				runtime.consecutiveFail.Store(0)
				runtime.lastErrorCode.Store("")
				runtime.published.Add(uint64(len(published)))
			}
			timer.Reset(runtime.config.PollInterval)
		}
	}
}

func (runtime *announcementRuntime) Ready() error {
	if runtime == nil || runtime.store == nil || runtime.closed.Load() {
		return errors.New("announcement runtime is not running")
	}
	state, _ := runtime.state.Load().(string)
	if state != announcementStateReady && state != announcementStateRunning {
		return errors.New("announcement runtime is not ready")
	}
	if runtime.config.ExternalChannel != announcementExternalChannelDisabled {
		return errors.New("announcement external channel is not explicitly disabled")
	}
	return nil
}

func (runtime *announcementRuntime) Health() announcementRuntimeHealth {
	if runtime == nil {
		return announcementRuntimeHealth{State: "disabled", ExternalChannel: announcementExternalChannelDisabled}
	}
	state, _ := runtime.state.Load().(string)
	snapshot := announcementRuntimeHealth{
		Enabled: runtime.config.Enabled, State: state, ExternalChannel: runtime.config.ExternalChannel,
		PublishedTotal: runtime.published.Load(), FailureTotal: runtime.failures.Load(),
	}
	if code, _ := runtime.lastErrorCode.Load().(string); code != "" {
		snapshot.LastErrorCode = code
	}
	return snapshot
}

func (runtime *announcementRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	var closeErr error
	runtime.closeOnce.Do(func() {
		runtime.closed.Store(true)
		runtime.cancel()
		runtime.runMu.Lock()
		started, done := runtime.started.Load(), runtime.done
		runtime.runMu.Unlock()
		if !started {
			runtime.state.Store(announcementStateStopped)
			return
		}
		timer := time.NewTimer(runtime.config.ShutdownTimeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			closeErr = errors.New("announcement runtime shutdown timed out")
		}
	})
	return closeErr
}

func runRequiredAnnouncementRuntime(ctx context.Context, runtime *announcementRuntime, failures chan<- error) {
	if runtime == nil {
		select {
		case failures <- errors.New("announcement runtime stopped: required worker is missing"):
		default:
		}
		return
	}
	// A temporarily unavailable database is retried instead of exiting the
	// process; other scheduler failures keep the consecutive-failure limit.
	err := runWithDBBackoff(ctx, slog.Default(), "announcement runtime", 5*time.Minute, runtime.Run)
	if ctx.Err() != nil {
		return
	}
	if err == nil {
		err = errors.New("required worker stopped unexpectedly")
	}
	select {
	case failures <- runtimeStageError{stage: "announcement runtime stopped", err: err}:
	default:
	}
}

func withAnnouncementRuntimeHealth(next http.Handler, runtime *announcementRuntime) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/health/announcements" {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(writer).Encode(runtime.Health())
			return
		}
		next.ServeHTTP(writer, request)
	})
}

type announcementTenantSessionAuthorizer interface {
	AuthorizeTenantSessionTx(
		context.Context,
		pgx.Tx,
		rbacmanager.AuthenticatedSessionReference,
		string,
	) (uuid.UUID, error)
}

type announcementRBACAuthorizer struct {
	service announcementTenantSessionAuthorizer
}

func (authorizer announcementRBACAuthorizer) Authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor announcement.Actor,
	permission string,
) error {
	if authorizer.service == nil {
		return announcement.ErrPermissionDenied
	}
	_, err := authorizer.service.AuthorizeTenantSessionTx(ctx, tx, rbacmanager.AuthenticatedSessionReference{
		UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID,
	}, permission)
	if errors.Is(err, rbacmanager.ErrPermissionDenied) {
		return announcement.ErrPermissionDenied
	}
	return err
}

type announcementDisabledStepUpVerifier struct{}

func (announcementDisabledStepUpVerifier) VerifyAndConsume(
	context.Context,
	pgx.Tx,
	rbacmanager.StepUpProof,
	rbacmanager.StepUpCheck,
) (rbacmanager.StepUpEvidence, error) {
	return rbacmanager.StepUpEvidence{}, rbacmanager.ErrStepUpRequired
}
