package main

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
)

// every reason code an administrator can be shown.
func TestRegistrationReasons(t *testing.T) {
	ready := registrationChannelState{send: true}
	required := httpapi.RegistrationChannel{Required: true}
	tests := []struct {
		name                                    string
		state                                   registrationState
		verified, notificationsOn, senderFailed bool
		want                                    []string
	}{
		{name: "registration off", state: registrationState{}, notificationsOn: true,
			want: []string{"registration_disabled"}},
		{name: "nothing missing", state: registrationState{policyEnabled: true, email: ready,
			config: httpapi.RegistrationConfig{Email: httpapi.RegistrationChannel{Required: true, Available: true}}},
			notificationsOn: true, want: []string{}},
		{name: "no email sender", state: registrationState{policyEnabled: true,
			config: httpapi.RegistrationConfig{Email: required}},
			notificationsOn: true, want: []string{"email_sender_unavailable"}},
		{name: "notification runtime forced off", state: registrationState{policyEnabled: true,
			config: httpapi.RegistrationConfig{Email: required}},
			want: []string{"notification_runtime_disabled", "email_sender_unavailable"}},
		{name: "sender rebuild failed", state: registrationState{policyEnabled: true, email: ready,
			config: httpapi.RegistrationConfig{Email: httpapi.RegistrationChannel{Required: true, Available: true}}},
			notificationsOn: true, senderFailed: true, want: []string{"sender_build_failed"}},
		{name: "SMS template missing", state: registrationState{policyEnabled: true,
			sms: registrationChannelState{send: true, templateMissing: true}, config: httpapi.RegistrationConfig{SMS: required}},
			notificationsOn: true, want: []string{"sms_template_missing"}},
		{name: "SMS template not mapped", state: registrationState{policyEnabled: true,
			sms: registrationChannelState{send: true, smsUnmapped: true}, config: httpapi.RegistrationConfig{SMS: required}},
			notificationsOn: true, want: []string{"sms_template_unmapped"}},
		{name: "SMS not configured, email not required", state: registrationState{policyEnabled: true, email: ready,
			config: httpapi.RegistrationConfig{SMS: required}},
			notificationsOn: true, want: []string{"sms_sender_unavailable"}},
		{name: "Turnstile without site key, secret and channel", state: registrationState{policyEnabled: true},
			verified: true, notificationsOn: true,
			want: []string{"email_sender_unavailable", "sms_sender_unavailable", "turnstile_not_configured", "verification_channel_unavailable"}},
		{name: "Turnstile not configured, channel ready (built-in CAPTCHA stands in)", state: registrationState{policyEnabled: true, email: ready,
			config: httpapi.RegistrationConfig{Email: httpapi.RegistrationChannel{Available: true}}},
			verified: true, notificationsOn: true, want: []string{"turnstile_not_configured"}},
		{name: "Turnstile ready", state: registrationState{policyEnabled: true, email: ready, turnstile: true,
			config: httpapi.RegistrationConfig{TurnstileSiteKey: "0x4AAAAAAA", Email: httpapi.RegistrationChannel{Available: true}}},
			verified: true, notificationsOn: true, want: []string{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := registrationReasons(test.state, test.verified, test.notificationsOn, test.senderFailed)
			if !slices.Equal(got, test.want) {
				t.Fatalf("reasons = %v, want %v", got, test.want)
			}
		})
	}
}

// nativeSMSTemplateMapped only speaks for the native providers.
func TestNativeSMSTemplateMapped(t *testing.T) {
	config := notificationRuntimeConfig{SMSProvider: notificationSMSProviderAliyun,
		NativeSMS: nativeSMSConfig{Templates: map[string]nativeSMSTemplate{"platform_user_registration_verification": {Code: "SMS_1"}}}}
	if native, mapped := nativeSMSTemplateMapped(config, "platform_user_registration_verification"); !native || !mapped {
		t.Fatalf("mapped template: native=%v mapped=%v", native, mapped)
	}
	if native, mapped := nativeSMSTemplateMapped(config, "account_registration_verification"); !native || mapped {
		t.Fatalf("unmapped template: native=%v mapped=%v", native, mapped)
	}
	if native, _ := nativeSMSTemplateMapped(notificationRuntimeConfig{SMSProvider: notificationSMSProviderHTTPSJSON}, "x"); native {
		t.Fatal("the HTTPS JSON provider needs no mapping")
	}
}

// ACCOUNT_REGISTRATION_TURNSTILE_SECRET is optional now: without it the
// Turnstile flow reads the secret saved on the settings page; with it the
// environment wins.
func TestLoadAccountRegistrationTurnstileSecretSource(t *testing.T) {
	trusted := accountRecoveryRuntimeConfig{Enabled: true, DigestKey: make([]byte, 32)}
	environment := validAccountRegistrationEnvironment()
	fromEnv, err := loadAccountRegistrationRuntimeConfigFromEnv(trusted, mapAccountRegistrationEnv(environment))
	if err != nil || !fromEnv.turnstileSecretFromEnv() {
		t.Fatalf("environment secret: fromEnv=%v err=%v", fromEnv.turnstileSecretFromEnv(), err)
	}
	fromEnv.clearSecrets()
	delete(environment, "ACCOUNT_REGISTRATION_TURNSTILE_SECRET")
	fromPage, err := loadAccountRegistrationRuntimeConfigFromEnv(trusted, mapAccountRegistrationEnv(environment))
	if err != nil || fromPage.turnstileSecretFromEnv() || fromPage.Turnstile.SecretFunc == nil || fromPage.Turnstile.Secret != "" {
		t.Fatalf("page secret: %#v err=%v", fromPage.Turnstile, err)
	}
	if _, err := fromPage.Turnstile.SecretFunc(t.Context()); err == nil {
		t.Fatal("the placeholder secret source must report no secret until main wires the page")
	}
	fromPage.clearSecrets()
}
