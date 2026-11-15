//go:build integration

package main

import (
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// liveTestChannels stands in for an accountMailSlot whose sender the auto
// notification runtime rebuilds.
type liveTestChannels struct {
	mu         sync.Mutex
	email, sms bool
}

func (channels *liveTestChannels) Channels() (bool, bool) {
	channels.mu.Lock()
	defer channels.mu.Unlock()
	return channels.email, channels.sms
}

func (channels *liveTestChannels) set(email, sms bool) {
	channels.mu.Lock()
	channels.email, channels.sms = email, sms
	channels.mu.Unlock()
}

func registrationReadyTestPool(t *testing.T) (*pgxpool.Pool, *systemusersettings.Service) {
	t.Helper()
	pool := openAnnouncementRuntimeDatabase(t, 668)
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	settings, err := systemusersettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return pool, settings
}

// saveRegistrationSettings writes the settings row as the settings page does
// (revision 1: no template published yet, so the flow default applies).
func saveRegistrationSettings(t *testing.T, pool *pgxpool.Pool, edit func(*systemusersettings.Settings)) {
	t.Helper()
	value := systemusersettings.DefaultSettings()
	value.RegistrationEnabled = true
	edit(&value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_at)
		SELECT id,1,$1,now() FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ON CONFLICT (platform_scope_id) DO UPDATE SET settings=EXCLUDED.settings`, string(encoded)); err != nil {
		t.Fatal(err)
	}
}

func setEmailSwitch(t *testing.T, pool *pgxpool.Pool, on bool) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE notification_channel_settings SET email_enabled=$1,revision=revision+1,updated_at=now()
		WHERE singleton`, on); err != nil {
		t.Fatal(err)
	}
}

func readRegistrationReadiness(t *testing.T, source *registrationConfigSource) (bool, []string) {
	t.Helper()
	config, err := source.RegistrationConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	reasons, err := source.RegistrationReasons(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if config.Reasons != nil {
		t.Fatalf("RegistrationConfig carried reasons %v", config.Reasons)
	}
	return config.Ready, reasons
}

// A fresh install with 开放注册 on and every other setting at its default
// signs up at once: no verification is required, so no sender is needed.
func TestRegistrationConfigDefaultsSignUpWithoutSender(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(*systemusersettings.Settings) {})
	source := newRegistrationConfigSource(pool, settings, accountRegistrationRuntimeConfig{}, false,
		&accountregistration.BuiltInService{}, &liveTestChannels{}, registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})
	config, err := source.RegistrationConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Ready || config.Mode != "builtin" || config.HumanCheck != "builtin_captcha" || config.Email.Required || config.SMS.Required {
		t.Fatalf("default sign-up: %+v", config)
	}
	if _, reasons := readRegistrationReadiness(t, source); len(reasons) != 0 {
		t.Fatalf("default sign-up reasons: %v", reasons)
	}
}

// Password recovery offers the channels with a template whose notification
// channel switch is on.
func TestRegistrationConfigRecoveryFollowsChannelSwitches(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(*systemusersettings.Settings) {})
	recovery := accountRecoveryRuntimeConfig{Enabled: true, Templates: map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "r", Version: 1, Channel: notification.ChannelEmail},
		notification.ChannelSMS:   {ID: "r", Version: 1, Channel: notification.ChannelSMS}}}
	setEmailSwitch(t, pool, true)
	view := registrationNotificationView{requested: true}
	source := newRegistrationConfigSource(pool, settings, accountRegistrationRuntimeConfig{}, false,
		&accountregistration.BuiltInService{}, &liveTestChannels{email: true}, view, recovery)
	config, err := source.RegistrationConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Recovery.Enabled || !slices.Equal(config.Recovery.Channels, []string{"email"}) {
		t.Fatalf("recovery: %+v", config.Recovery)
	}
}

// The built-in flow: email verification is in effect only while
// 要求邮箱验证 and the email notification channel are both on; otherwise
// sign-up goes on without a code. Each change shows on the same source,
// without a restart.
func TestRegistrationConfigFollowsSettingsWithoutRestart(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.EmailRequired, value.EmailVerificationRequired = true, true
	})
	channels := &liveTestChannels{}
	source := newRegistrationConfigSource(pool, settings, accountRegistrationRuntimeConfig{}, false,
		&accountregistration.BuiltInService{}, channels, registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})

	steps := []struct {
		name        string
		apply       func()
		wantReady   bool
		wantReasons []string
	}{
		{"nothing configured, switch off: no code", func() {}, true, []string{}},
		{"SMTP saved, switch still off: no code", func() { channels.set(true, false) }, true, []string{}},
		{"email switch on: code required and sendable", func() { setEmailSwitch(t, pool, true) }, true, []string{}},
		{"sender gone while in effect", func() { channels.set(false, false) }, false, []string{"email_sender_unavailable"}},
		{"email switch off again: no code", func() { setEmailSwitch(t, pool, false) }, true, []string{}},
	}
	for _, step := range steps {
		step.apply()
		ready, reasons := readRegistrationReadiness(t, source)
		if ready != step.wantReady || !slices.Equal(reasons, step.wantReasons) {
			t.Fatalf("%s: ready=%v reasons=%v, want %v %v", step.name, ready, reasons, step.wantReady, step.wantReasons)
		}
	}
	// in effect only with both on
	setEmailSwitch(t, pool, true)
	channels.set(true, false)
	if config, err := source.RegistrationConfig(t.Context()); err != nil || !config.Email.Required || !config.Email.Available {
		t.Fatalf("both on: %+v %v", config.Email, err)
	}
	setEmailSwitch(t, pool, false)
	if config, err := source.RegistrationConfig(t.Context()); err != nil || config.Email.Required {
		t.Fatalf("switch off: %+v %v", config.Email, err)
	}
}

// The Turnstile flow: until its site key and secret are both set the built-in
// image CAPTCHA guards sending a code (sign-up stays open); the values saved
// on the page apply on the same source; a non-empty environment site key wins
// over the page value.
func TestRegistrationConfigTurnstileFromSettingsPage(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	t.Setenv("ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY", "")
	saveRegistrationSettings(t, pool, func(*systemusersettings.Settings) {})
	setEmailSwitch(t, pool, true)
	registration := accountRegistrationRuntimeConfig{Enabled: true, TermsVersion: "terms-1",
		Templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: builtInRegistrationTemplates[notification.ChannelEmail]}}
	registration.Turnstile.SecretFunc = turnstileSecretUnset
	channels := &liveTestChannels{email: true}
	source := newRegistrationConfigSource(pool, settings, registration, true, nil, channels,
		registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})

	if ready, reasons := readRegistrationReadiness(t, source); !ready ||
		!slices.Equal(reasons, []string{"turnstile_not_configured"}) {
		t.Fatalf("before the page: ready=%v reasons=%v", ready, reasons)
	}
	if config, err := source.RegistrationConfig(t.Context()); err != nil || config.Mode != "verified" ||
		config.HumanCheck != "builtin_captcha" || config.TurnstileSiteKey != "" {
		t.Fatalf("before the page: %+v %v", config, err)
	}
	if ready, err := source.TurnstileReady(t.Context()); err != nil || ready {
		t.Fatalf("TurnstileReady before the page = %v %v", ready, err)
	}
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) { value.CaptchaTurnstileSiteKey = "0x4AAAAAAAPageKey" })
	if _, reasons := readRegistrationReadiness(t, source); !slices.Equal(reasons, []string{"turnstile_not_configured"}) {
		t.Fatalf("site key without secret: reasons=%v", reasons)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE platform_system_user_settings SET secrets_key_id='k1',
		secrets_ciphertext=decode(repeat('00',29),'hex'),secrets_fingerprints='{"captcha_turnstile_secret":"0123456789abcdef"}'`); err != nil {
		t.Fatal(err)
	}
	config, err := source.RegistrationConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !config.Ready || config.Mode != "verified" || config.HumanCheck != "turnstile" || config.TurnstileSiteKey != "0x4AAAAAAAPageKey" {
		t.Fatalf("after the page: %+v", config)
	}
	if ready, err := source.TurnstileReady(t.Context()); err != nil || !ready {
		t.Fatalf("TurnstileReady after the page = %v %v", ready, err)
	}
	t.Setenv("ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY", "0x4AAAAAAAEnvKey")
	envSource := newRegistrationConfigSource(pool, settings, registration, true, nil, channels,
		registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})
	if config, err := envSource.RegistrationConfig(t.Context()); err != nil || config.TurnstileSiteKey != "0x4AAAAAAAEnvKey" {
		t.Fatalf("environment site key did not win: %+v %v", config, err)
	}

	// a Turnstile runtime that failed to open is not "verified": the built-in
	// flow serves and no Turnstile key is asked for
	fallback := newRegistrationConfigSource(pool, settings, registration, false, &accountregistration.BuiltInService{}, channels,
		registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})
	if config, err := fallback.RegistrationConfig(t.Context()); err != nil || config.Mode != "builtin" || config.HumanCheck != "builtin_captcha" {
		t.Fatalf("fallback flow: %+v %v", config, err)
	}
}

// Template checks: a flow default that does not exist, and a native SMS
// provider without a mapping for the template, keep the channel unavailable.
func TestRegistrationConfigTemplateReasons(t *testing.T) {
	pool, settings := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.PhoneRequired, value.PhoneVerificationRequired = true, true
	})
	if _, err := pool.Exec(t.Context(), `UPDATE notification_channel_settings SET sms_enabled=true,revision=revision+1 WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	channels := &liveTestChannels{sms: true}
	unmapped := registrationNotificationView{requested: true,
		smsTemplateMapped: func(string) (bool, bool) { return true, false }}
	source := newRegistrationConfigSource(pool, settings, accountRegistrationRuntimeConfig{}, false,
		&accountregistration.BuiltInService{}, channels, unmapped, accountRecoveryRuntimeConfig{})
	if ready, reasons := readRegistrationReadiness(t, source); ready || !slices.Equal(reasons, []string{"sms_template_unmapped"}) {
		t.Fatalf("unmapped SMS template: ready=%v reasons=%v", ready, reasons)
	}

	t.Setenv("ACCOUNT_REGISTRATION_TURNSTILE_SITE_KEY", "0x4AAAAAAAEnvKey")
	registration := accountRegistrationRuntimeConfig{Enabled: true, TermsVersion: "terms-1",
		Templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelSMS: {ID: "registration_sms_not_seeded", Version: 7, Channel: notification.ChannelSMS}}}
	registration.Turnstile.Secret = "turnstile-secret-from-environment"
	missing := newRegistrationConfigSource(pool, settings, registration, true, nil, channels,
		registrationNotificationView{requested: true}, accountRecoveryRuntimeConfig{})
	if ready, reasons := readRegistrationReadiness(t, missing); ready ||
		!slices.Equal(reasons, []string{"sms_template_missing", "verification_channel_unavailable"}) {
		t.Fatalf("missing template: ready=%v reasons=%v", ready, reasons)
	}
}
