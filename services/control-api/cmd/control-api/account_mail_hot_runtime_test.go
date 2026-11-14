package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

// fakeAccountSender stands for one built sender: it records which SMTP
// account it was built for, and can hold a send until released.
type fakeAccountSender struct {
	user    string
	sent    *[]string
	mu      *sync.Mutex
	hold    chan struct{}
	started chan struct{}
	closed  atomic.Bool
}

func (sender *fakeAccountSender) Dispatch(context.Context, notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	if sender.started != nil {
		close(sender.started)
	}
	if sender.hold != nil {
		<-sender.hold
	}
	if sender.closed.Load() {
		return notification.AnonymousDispatchResult{Failure: &notification.Failure{Class: notification.FailurePermanent, Code: "closed"}}
	}
	sender.mu.Lock()
	*sender.sent = append(*sender.sent, sender.user)
	sender.mu.Unlock()
	return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchAccepted, Provider: "configured_email"}
}

func smtpConfigFor(user string) notificationRuntimeConfig {
	config := notificationRuntimeConfig{Enabled: true, Requested: true, Auto: true, EmailProvider: notificationEmailProviderSMTPTLS}
	config.SMTP.Username = user
	config.SMTP.Password = []byte("secret-of-" + user)
	return config
}

func TestAccountMailSlotLoginCodesUseNewSenderAfterSettingsChange(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	var built []*fakeAccountSender
	open := func(_ context.Context, config notificationRuntimeConfig) (*accountMailParts, error) {
		if !config.Enabled {
			return nil, nil
		}
		if string(config.SMTP.Password) != "secret-of-"+config.SMTP.Username {
			t.Errorf("open got the password %q for %q", config.SMTP.Password, config.SMTP.Username)
		}
		sender := &fakeAccountSender{user: config.SMTP.Username, sent: &sent, mu: &mu}
		built = append(built, sender)
		return &accountMailParts{dispatcher: sender, email: true, close: func() error { sender.closed.Store(true); return nil }}, nil
	}
	slot := newAccountMailSlot("account_login", slog.New(slog.NewTextHandler(io.Discard, nil)), open, nil, nil)
	slot.apply(context.Background(), smtpConfigFor("old@example.com"), true)
	if result := slot.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{}); result.Failure != nil {
		t.Fatalf("first code not sent: %+v", result.Failure)
	}

	// a code in flight on the old sender when the settings page saves a new one
	hold, started := make(chan struct{}), make(chan struct{})
	built[0].hold, built[0].started = hold, started
	done := make(chan notification.AnonymousDispatchResult, 1)
	go func() { done <- slot.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{}) }()
	<-started
	changed := smtpConfigFor("new@example.com")
	slot.apply(context.Background(), changed, true)
	// the caller (auto runtime) clears its configuration on the next rebuild
	changed.clearSecrets()
	if result := slot.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{}); result.Failure != nil {
		t.Fatalf("code after the change not sent: %+v", result.Failure)
	}
	if built[0].closed.Load() {
		t.Fatal("old sender closed while a code was still being sent")
	}
	close(hold)
	if result := <-done; result.Failure != nil {
		t.Fatalf("in-flight code did not finish on the old sender: %+v", result.Failure)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !built[0].closed.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !built[0].closed.Load() {
		t.Fatal("old sender not closed after its last send")
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"old@example.com", "new@example.com", "old@example.com"}; strings.Join(sent, ",") != strings.Join(want, ",") {
		t.Fatalf("senders used = %v, want %v", sent, want)
	}
	if state, _ := slot.state(); state != "ready" {
		t.Fatalf("state = %q, want ready", state)
	}
}

func TestAccountMailSlotFailedRebuildKeepsPreviousAndRetries(t *testing.T) {
	var sent []string
	var mu sync.Mutex
	fail := true
	open := func(_ context.Context, config notificationRuntimeConfig) (*accountMailParts, error) {
		if fail && config.SMTP.Username == "broken@example.com" {
			return nil, errors.New("dial tcp 192.0.2.10:465: connection refused")
		}
		return &accountMailParts{dispatcher: &fakeAccountSender{user: config.SMTP.Username, sent: &sent, mu: &mu}, email: true}, nil
	}
	slot := newAccountMailSlot("account_login", slog.New(slog.NewTextHandler(io.Discard, nil)), open, nil, nil)
	slot.apply(context.Background(), smtpConfigFor("good@example.com"), true)
	slot.apply(context.Background(), smtpConfigFor("broken@example.com"), true)
	if state, code := slot.state(); state != "degraded" || code != "account_login_unavailable" {
		t.Fatalf("state = %q/%q, want degraded/account_login_unavailable", state, code)
	}
	if result := slot.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{}); result.Failure != nil {
		t.Fatalf("previous sender not kept: %+v", result.Failure)
	}
	// no revision change and the retry time not come: nothing is rebuilt
	fail = false
	slot.apply(context.Background(), smtpConfigFor("broken@example.com"), false)
	if state, _ := slot.state(); state != "degraded" {
		t.Fatalf("retried before the retry time: %q", state)
	}
	slot.mu.Lock()
	slot.retryAt = time.Now().Add(-time.Second)
	slot.mu.Unlock()
	slot.apply(context.Background(), smtpConfigFor("broken@example.com"), false)
	if state, _ := slot.state(); state != "ready" {
		t.Fatalf("not rebuilt after the retry time: %q", state)
	}
	slot.Dispatch(context.Background(), notification.AnonymousDeliveryAttempt{})
	mu.Lock()
	defer mu.Unlock()
	if got := sent[len(sent)-1]; got != "broken@example.com" {
		t.Fatalf("retried sender not used: %q", got)
	}
}

func TestAccountMailSlotLoginMethodsRecoverWithoutRestart(t *testing.T) {
	loginMethods := func(email bool) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_ = json.NewEncoder(writer).Encode(map[string]any{"data": map[string]any{"email_enabled": email}})
		})
	}
	open := func(_ context.Context, config notificationRuntimeConfig) (*accountMailParts, error) {
		if !config.Enabled {
			return nil, nil
		}
		return &accountMailParts{handler: loginMethods(true), email: true}, nil
	}
	// start: no sender on the settings page, the login runtime is not built
	slot := newAccountMailSlot("account_login", slog.New(slog.NewTextHandler(io.Discard, nil)), open, nil, nil)
	slot.SetLoginMethodsFallback(loginMethods(false))
	read := func() bool {
		recorder := httptest.NewRecorder()
		slot.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/auth/login-methods", nil))
		var body struct {
			Data struct {
				EmailEnabled bool `json:"email_enabled"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || recorder.Code != http.StatusOK {
			t.Fatalf("login-methods = %d %s", recorder.Code, recorder.Body.String())
		}
		return body.Data.EmailEnabled
	}
	if read() {
		t.Fatal("code login offered without a sender")
	}
	recorder := httptest.NewRecorder()
	slot.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/auth/login-challenges", nil))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "account_login_unavailable") {
		t.Fatalf("challenge without a sender = %d %s", recorder.Code, recorder.Body.String())
	}
	// the settings page saves a complete SMTP sender
	slot.apply(context.Background(), smtpConfigFor("ops@example.com"), true)
	if !read() {
		t.Fatal("code login not offered again after the sender became available")
	}
	if email, _ := slot.Channels(); !email {
		t.Fatal("email channel not reported available")
	}
}

// Auto mode with the Turnstile registration configured mounts the registration slot instead of the built-in
// registration (main.go registrationMounted): while it has no sender, registration answers 503 and does not fall back.
func TestAccountMailSlotTurnstileRegistrationWithoutSenderIs503(t *testing.T) {
	served := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusCreated) })
	open := func(_ context.Context, config notificationRuntimeConfig) (*accountMailParts, error) {
		if !config.Enabled {
			return nil, nil
		}
		return &accountMailParts{handler: served, email: true}, nil
	}
	slot := newAccountMailSlot("account_registration", slog.New(slog.NewTextHandler(io.Discard, nil)), open, nil,
		accountMailStartError(true, errors.New("smtp sender unavailable")))
	register := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		slot.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/account/registrations", nil))
		return recorder
	}
	if recorder := register(); recorder.Code != http.StatusServiceUnavailable ||
		!strings.Contains(recorder.Body.String(), "account_registration_unavailable") {
		t.Fatalf("registration without a sender = %d %s", recorder.Code, recorder.Body.String())
	}
	slot.apply(context.Background(), smtpConfigFor("ops@example.com"), true)
	if recorder := register(); recorder.Code != http.StatusCreated {
		t.Fatalf("registration after the sender became available = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestNotificationChannelsHealthStates(t *testing.T) {
	ready := smtpConfigFor("ops@example.com")
	off := notificationRuntimeConfig{}
	incomplete := notificationRuntimeConfig{Requested: true, Auto: true}
	incomplete.unavailable("email", "SMTP lacks value.smtp_address")
	unreadable := notificationRuntimeConfig{Requested: true, Auto: true}
	unreadable.unavailable("settings", "read persisted system mail settings")
	nothing := notificationRuntimeConfig{Requested: true, Auto: true}
	switchedOff := &notification.ChannelSwitches{Email: false, SMS: true}
	for _, test := range []struct {
		name       string
		config     notificationRuntimeConfig
		running    bool
		switches   *notification.ChannelSwitches
		rebuilding bool
		want       notificationChannelHealth
	}{
		{"rebuilding", ready, true, nil, true, notificationChannelHealth{State: "rebuilding"}},
		{"off", off, false, nil, false, notificationChannelHealth{State: "disabled_by_env"}},
		{"incomplete", incomplete, false, nil, false, notificationChannelHealth{State: "degraded", Reason: "config_incomplete"}},
		{"unreadable", unreadable, false, nil, false, notificationChannelHealth{State: "degraded", Reason: "settings_unreadable"}},
		{"nothing", nothing, false, nil, false, notificationChannelHealth{State: "not_configured"}},
		{"switched off", ready, true, switchedOff, false, notificationChannelHealth{State: "degraded", Reason: "channel_switched_off"}},
		{"worker down", ready, false, nil, false, notificationChannelHealth{State: "degraded", Reason: "worker_not_running"}},
		{"ready", ready, true, &notification.ChannelSwitches{Email: true}, false, notificationChannelHealth{State: "ready"}},
	} {
		got := notificationChannelsHealth(test.config, test.running, test.switches, test.rebuilding)
		if got["email"] != test.want {
			t.Errorf("%s: email = %+v, want %+v", test.name, got["email"], test.want)
		}
		if _, ok := got["sms"]; !ok {
			t.Errorf("%s: sms state missing", test.name)
		}
	}
}

func TestHealthDetailCarriesNotificationWithoutSecrets(t *testing.T) {
	config := smtpConfigFor("ops@mail.example.com")
	config.SMTP.Address = "smtp.mail.example.com:465"
	health := notificationHealthSource(config, nil, nil)
	recorder := httptest.NewRecorder()
	withCacheControlRuntimeHealthDetail(http.NotFoundHandler(), nil, nil, nil, health).ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	var body struct {
		Notification notificationRuntimeHealthSnapshot `json:"notification"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Notification.Mode != "explicit" || body.Notification.Channels["email"].State != "degraded" ||
		body.Notification.Channels["email"].Reason != "worker_not_running" {
		t.Fatalf("notification = %+v", body.Notification)
	}
	for _, secret := range []string{"smtp.mail.example.com", "ops@mail.example.com", "secret-of-"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("health detail exposes %q: %s", secret, recorder.Body.String())
		}
	}
	// the notification runtime health route reads the same source
	recorder = httptest.NewRecorder()
	withNotificationRuntimeHealth(http.NotFoundHandler(), health).ServeHTTP(
		recorder, httptest.NewRequest(http.MethodGet, notificationRuntimeHealthAPIPath, nil))
	if !strings.Contains(recorder.Body.String(), `"mode":"explicit"`) {
		t.Fatalf("notification runtime health = %s", recorder.Body.String())
	}
}

func TestAccountMailRuntimesHealthReportsFlows(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	failing := newAccountMailSlot("account_login", logger, nil, nil, errors.New("not ready"))
	empty := newAccountMailSlot("registration_verification", logger, nil, nil, nil)
	recovery := &accountRecoverySlot{logger: logger, failed: true}
	states, code := (&accountMailRuntimes{slots: []*accountMailSlot{failing, empty}, recovery: recovery}).health()
	if states["account_login"] != "degraded" || states["registration_verification"] != "not_configured" ||
		states["account_recovery"] != "degraded" || code != "account_login_unavailable" {
		t.Fatalf("states = %v code = %q", states, code)
	}
}
