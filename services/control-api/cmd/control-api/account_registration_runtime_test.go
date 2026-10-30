package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

func TestLoadAccountRegistrationRuntimeConfigSupportsDedicatedTurnstileCA(t *testing.T) {
	server, caFile := newAccountRegistrationTurnstileServer(t)
	environment := validAccountRegistrationEnvironment()
	environment["ACCOUNT_REGISTRATION_TURNSTILE_ENDPOINT"] = server.URL
	environment["ACCOUNT_REGISTRATION_TURNSTILE_CA_FILE"] = caFile
	trusted := accountRecoveryRuntimeConfig{Enabled: true, DigestKey: make([]byte, 32)}
	config, err := loadAccountRegistrationRuntimeConfigFromEnv(trusted, mapAccountRegistrationEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled || config.Turnstile.Endpoint != server.URL || config.Turnstile.CAFile != caFile ||
		config.Turnstile.Secret != environment["ACCOUNT_REGISTRATION_TURNSTILE_SECRET"] {
		t.Fatalf("loaded Turnstile config = %#v", config.Turnstile)
	}
	config.clearSecrets()
	if len(config.DigestKey) != 0 || config.Turnstile.Secret != "" {
		t.Fatalf("clearSecrets retained registration secrets: %#v", config)
	}
}

func TestLoadAccountRegistrationRuntimeConfigKeepsDefaultTurnstileSystemTrust(t *testing.T) {
	environment := validAccountRegistrationEnvironment()
	trusted := accountRecoveryRuntimeConfig{Enabled: true, DigestKey: make([]byte, 32)}
	config, err := loadAccountRegistrationRuntimeConfigFromEnv(trusted, mapAccountRegistrationEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.clearSecrets)
	if config.Turnstile.Endpoint != "" || config.Turnstile.CAFile != "" {
		t.Fatalf("default Turnstile trust was overridden: %#v", config.Turnstile)
	}
}

func TestLoadAccountRegistrationRuntimeConfigRejectsUnsafeTurnstileCABindingWithoutLeak(t *testing.T) {
	server, validCA := newAccountRegistrationTurnstileServer(t)
	const secretPath = "/missing/turnstile-ca-private-marker.pem"
	for _, test := range []struct {
		name     string
		endpoint string
		caFile   string
	}{
		{name: "CA without explicit endpoint", caFile: validCA},
		{name: "missing CA", endpoint: server.URL, caFile: secretPath},
		{name: "whitespace CA", endpoint: server.URL, caFile: validCA + " "},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := validAccountRegistrationEnvironment()
			if test.endpoint != "" {
				environment["ACCOUNT_REGISTRATION_TURNSTILE_ENDPOINT"] = test.endpoint
			}
			environment["ACCOUNT_REGISTRATION_TURNSTILE_CA_FILE"] = test.caFile
			trusted := accountRecoveryRuntimeConfig{Enabled: true, DigestKey: make([]byte, 32)}
			config, err := loadAccountRegistrationRuntimeConfigFromEnv(trusted, mapAccountRegistrationEnv(environment))
			config.clearSecrets()
			if err == nil || strings.Contains(err.Error(), secretPath) ||
				strings.Contains(err.Error(), environment["ACCOUNT_REGISTRATION_TURNSTILE_SECRET"]) {
				t.Fatalf("unsafe Turnstile CA error = %v", err)
			}
		})
	}
}

func TestLoadAccountRegistrationTemplatesAcceptsConfiguredChannelSet(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		wantEmail   bool
		wantSMS     bool
	}{
		{name: "email only", environment: map[string]string{
			"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_ID":      "registration_email",
			"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_VERSION": "1",
		}, wantEmail: true},
		{name: "SMS only", environment: map[string]string{
			"ACCOUNT_REGISTRATION_SMS_TEMPLATE_ID":      "registration_sms",
			"ACCOUNT_REGISTRATION_SMS_TEMPLATE_VERSION": "2",
		}, wantSMS: true},
		{name: "both", environment: map[string]string{
			"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_ID":      "registration_email",
			"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_VERSION": "3",
			"ACCOUNT_REGISTRATION_SMS_TEMPLATE_ID":        "registration_sms",
			"ACCOUNT_REGISTRATION_SMS_TEMPLATE_VERSION":   "4",
		}, wantEmail: true, wantSMS: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			templates, err := loadAccountRegistrationTemplates(mapAccountRegistrationEnv(test.environment))
			if err != nil {
				t.Fatal(err)
			}
			_, email := templates[notification.ChannelEmail]
			_, sms := templates[notification.ChannelSMS]
			if email != test.wantEmail || sms != test.wantSMS || len(templates) != boolCount(test.wantEmail, test.wantSMS) {
				t.Fatalf("templates = %#v", templates)
			}
		})
	}
}

func TestLoadAccountRegistrationTemplatesRejectsZeroOrPartialChannel(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment map[string]string
		want        string
	}{
		{name: "zero", environment: map[string]string{}, want: "at least one account registration notification template is required"},
		{name: "email version missing", environment: map[string]string{
			"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_ID": "registration_email",
		}, want: "ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_VERSION"},
		{name: "SMS ID missing", environment: map[string]string{
			"ACCOUNT_REGISTRATION_SMS_TEMPLATE_VERSION": "1",
		}, want: "ACCOUNT_REGISTRATION_SMS_TEMPLATE_ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadAccountRegistrationTemplates(mapAccountRegistrationEnv(test.environment))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOpenAccountRegistrationProviderTransportsUsesOnlyConfiguredChannels(t *testing.T) {
	for _, test := range []struct {
		name         string
		templates    map[notification.Channel]notification.TemplateRef
		config       notificationRuntimeConfig
		wantEmail    int32
		wantSMS      int32
		wantStartTLS bool
	}{
		{name: "implicit TLS email only", templates: registrationTemplates(notification.ChannelEmail),
			config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}, wantEmail: 1},
		{name: "STARTTLS email only", templates: registrationTemplates(notification.ChannelEmail),
			config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPSTARTTLS,
				SMTP: smtpTLSConfig{StartTLS: true}}, wantEmail: 1, wantStartTLS: true},
		{name: "SMS only", templates: registrationTemplates(notification.ChannelSMS),
			config: notificationRuntimeConfig{SMSProvider: notificationSMSProviderHTTPSJSON}, wantSMS: 1},
		{name: "both", templates: registrationTemplates(notification.ChannelEmail, notification.ChannelSMS),
			config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS,
				SMSProvider: notificationSMSProviderHTTPSJSON}, wantEmail: 1, wantSMS: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			var emailCalls, smsCalls atomic.Int32
			email, sms := newRegistrationTestTransport(), newRegistrationTestTransport()
			providers, err := openAccountRegistrationProviderTransports(
				t.Context(), test.templates, registrationProviderConfig(test.config),
				func(config smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
					emailCalls.Add(1)
					if config.StartTLS != test.wantStartTLS {
						t.Fatalf("SMTP StartTLS = %t", config.StartTLS)
					}
					return email, nil
				},
				func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
					smsCalls.Add(1)
					return sms, nil
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if emailCalls.Load() != test.wantEmail || smsCalls.Load() != test.wantSMS ||
				email.readyCalls.Load() != test.wantEmail || sms.readyCalls.Load() != test.wantSMS ||
				len(providers) != int(test.wantEmail+test.wantSMS) {
				t.Fatalf("calls email=(%d,%d) sms=(%d,%d) providers=%#v",
					emailCalls.Load(), email.readyCalls.Load(), smsCalls.Load(), sms.readyCalls.Load(), providers)
			}
			closeNotificationProviders(providers, time.Second)
		})
	}
}

func TestOpenAccountRegistrationProviderTransportsFailsClosedOnProviderMismatch(t *testing.T) {
	tests := []struct {
		name      string
		templates map[notification.Channel]notification.TemplateRef
		config    notificationRuntimeConfig
	}{
		{name: "zero channels", config: notificationRuntimeConfig{}},
		{name: "email template without provider", templates: registrationTemplates(notification.ChannelEmail),
			config: notificationRuntimeConfig{}},
		{name: "email provider without template", templates: registrationTemplates(notification.ChannelSMS),
			config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS,
				SMSProvider: notificationSMSProviderHTTPSJSON}},
		{name: "unknown email provider", templates: registrationTemplates(notification.ChannelEmail),
			config: notificationRuntimeConfig{EmailProvider: "smtp"}},
		{name: "unknown SMS provider", templates: registrationTemplates(notification.ChannelSMS),
			config: notificationRuntimeConfig{SMSProvider: "sms_http"}},
		{name: "unknown template channel", templates: registrationTemplates(notification.Channel("push")),
			config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var factoryCalls atomic.Int32
			_, err := openAccountRegistrationProviderTransports(
				t.Context(), test.templates, registrationProviderConfig(test.config),
				func(smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
					factoryCalls.Add(1)
					return newRegistrationTestTransport(), nil
				},
				func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
					factoryCalls.Add(1)
					return newRegistrationTestTransport(), nil
				},
			)
			if err == nil || factoryCalls.Load() != 0 {
				t.Fatalf("providers mismatch error=%v factory_calls=%d", err, factoryCalls.Load())
			}
		})
	}
}

func TestOpenAccountRegistrationProviderTransportsClosesPartialStartup(t *testing.T) {
	templates := registrationTemplates(notification.ChannelEmail, notification.ChannelSMS)
	config := registrationProviderConfig(notificationRuntimeConfig{
		EmailProvider: notificationEmailProviderSMTPTLS, SMSProvider: notificationSMSProviderHTTPSJSON,
	})

	t.Run("constructor failure", func(t *testing.T) {
		email := newRegistrationTestTransport()
		providers, err := openAccountRegistrationProviderTransports(
			t.Context(), templates, config,
			func(smtpTLSConfig) (notificationruntime.ProviderTransport, error) { return email, nil },
			func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) {
				return nil, errors.New("sms constructor secret")
			},
		)
		if providers != nil || err == nil || email.closeCalls.Load() != 1 {
			t.Fatalf("constructor failure providers=%#v error=%v email_close=%d", providers, err, email.closeCalls.Load())
		}
	})

	t.Run("readiness failure", func(t *testing.T) {
		email, sms := newRegistrationTestTransport(), newRegistrationTestTransport()
		sms.readyErr = errors.New("sms readiness secret")
		providers, err := openAccountRegistrationProviderTransports(
			t.Context(), templates, config,
			func(smtpTLSConfig) (notificationruntime.ProviderTransport, error) { return email, nil },
			func(smsHTTPSJSONConfig) (notificationruntime.ProviderTransport, error) { return sms, nil },
		)
		if providers != nil || err == nil || email.closeCalls.Load() != 1 || sms.closeCalls.Load() != 1 {
			t.Fatalf("readiness failure providers=%#v error=%v closes=(%d,%d)",
				providers, err, email.closeCalls.Load(), sms.closeCalls.Load())
		}
	})
}

func TestAccountRegistrationProviderRendersPublishedVerificationTemplate(t *testing.T) {
	fallback := notification.TemplateRef{ID: "registration_template", Version: 1, Channel: notification.ChannelEmail}
	transport := &registrationCaptureTransport{}
	provider := &accountRegistrationContactProvider{
		catalog: notification.NewCatalog(),
		templates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: fallback,
		},
		providers: map[notification.Channel]notificationruntime.ProviderTransport{
			notification.ChannelEmail: transport,
		},
		timeout: time.Second,
	}
	result := provider.SendRegistrationVerification(t.Context(), accountregistrationchallenge.ContactDelivery{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail,
		Template: notification.TemplateRef{
			ID: "platform_user_registration_verification", Version: 3, Channel: notification.ChannelEmail,
		},
		Destination: "user@example.test", OTP: "123456", Subject: "验证码 {{.captcha}}",
		Body: "<p>当前验证码：{{.captcha}}</p>", IdempotencyKey: "notification-v1-registration",
		AttemptNumber: 1,
	})
	if result.Disposition != notification.SendAccepted || transport.message.Subject != "验证码 123456" ||
		transport.message.Body != "<p>当前验证码：123456</p>" || strings.Contains(transport.message.Body, "{{") {
		t.Fatalf("rendered registration delivery=(%#v,%#v)", result, transport.message)
	}
}

func TestAccountVerificationProvidersObserveEmailAndSMSCalls(t *testing.T) {
	started := time.Date(2026, 9, 28, 10, 0, 0, 654321000, time.UTC)
	for _, test := range []struct {
		name, contact string
		channel       notification.Channel
		login         bool
	}{
		{name: "registration email", contact: "user@example.test", channel: notification.ChannelEmail},
		{name: "registration sms", contact: "+8613800001234", channel: notification.ChannelSMS},
		{name: "login email", contact: "owner@example.test", channel: notification.ChannelEmail, login: true},
		{name: "login sms", contact: "+8613900001234", channel: notification.ChannelSMS, login: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &registrationCaptureTransport{}
			ref := notification.TemplateRef{ID: "verification_template", Version: 1, Channel: test.channel}
			provider := &accountRegistrationContactProvider{
				catalog: notification.NewCatalog(), templates: map[notification.Channel]notification.TemplateRef{test.channel: ref},
				providers: map[notification.Channel]notificationruntime.ProviderTransport{test.channel: transport},
				timeout:   time.Second, now: func() time.Time { return started },
			}
			subject, body, otp := "验证码 {{.captcha}}", "<p>{{.captcha}}</p>", "123456"
			if test.channel == notification.ChannelSMS {
				subject, body = "", "验证码 {{.captcha}}"
			}
			if test.login {
				otp = "654321"
			}
			result := func() notification.SendResult {
				if test.login {
					return provider.SendLoginVerification(t.Context(), accountloginchallenge.ContactDelivery{
						OutboxID: uuid.New(), Channel: test.channel, Template: ref, Destination: test.contact, OTP: otp,
						Subject: subject, Body: body, IdempotencyKey: "verification-observation", AttemptNumber: 1,
					})
				}
				return provider.SendRegistrationVerification(t.Context(), accountregistrationchallenge.ContactDelivery{
					OutboxID: uuid.New(), Channel: test.channel, Template: ref, Destination: test.contact, OTP: otp,
					Subject: subject, Body: body, IdempotencyKey: "verification-observation", AttemptNumber: 1,
				})
			}()
			if result.Disposition != notification.SendAccepted || !reflect.DeepEqual(result.Observation, notification.NewDispatchObservation(test.channel, test.contact, started)) {
				t.Fatalf("verification result=%+v", result)
			}
		})
	}
}

func registrationProviderConfig(config notificationRuntimeConfig) notificationRuntimeConfig {
	config.Enabled = true
	config.SendTimeout = time.Second
	config.StartupTimeout = time.Second
	config.ShutdownTimeout = time.Second
	return config
}

func registrationTemplates(channels ...notification.Channel) map[notification.Channel]notification.TemplateRef {
	templates := make(map[notification.Channel]notification.TemplateRef, len(channels))
	for index, channel := range channels {
		templates[channel] = notification.TemplateRef{ID: "registration_template", Version: uint64(index + 1), Channel: channel}
	}
	return templates
}

func mapAccountRegistrationEnv(values map[string]string) accountRecoveryEnvLookup {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}

type registrationTestTransport struct {
	readyErr   error
	readyCalls atomic.Int32
	closeCalls atomic.Int32
}

type registrationCaptureTransport struct {
	message notificationruntime.ProviderMessage
}

func (*registrationCaptureTransport) Ready(context.Context) error { return nil }

func (transport *registrationCaptureTransport) Send(
	_ context.Context,
	message notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	transport.message = message
	return notificationruntime.ProviderResult{
		Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: "delivery-1",
	}, nil
}

func (*registrationCaptureTransport) Close(context.Context) error { return nil }

func newRegistrationTestTransport() *registrationTestTransport { return &registrationTestTransport{} }

func (transport *registrationTestTransport) Ready(context.Context) error {
	transport.readyCalls.Add(1)
	return transport.readyErr
}

func (*registrationTestTransport) Send(
	context.Context,
	notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted}, nil
}

func (transport *registrationTestTransport) Close(context.Context) error {
	transport.closeCalls.Add(1)
	return nil
}

var _ notificationruntime.ProviderTransport = (*registrationTestTransport)(nil)

func validAccountRegistrationEnvironment() map[string]string {
	return map[string]string{
		"ACCOUNT_REGISTRATION_ENABLED":                    "true",
		"ACCOUNT_REGISTRATION_HMAC_KEY_BASE64":            canonicalAccountRecoveryTestKey(0x31),
		"ACCOUNT_REGISTRATION_DISPATCH_KEK_ACTIVE_KEY_ID": "primary",
		"ACCOUNT_REGISTRATION_DISPATCH_KEK_KEYS_JSON":     `{"primary":"` + canonicalAccountRecoveryTestKey(0x32) + `"}`,
		"ACCOUNT_REGISTRATION_PROOF_KEK_ACTIVE_KEY_ID":    "primary",
		"ACCOUNT_REGISTRATION_PROOF_KEK_KEYS_JSON":        `{"primary":"` + canonicalAccountRecoveryTestKey(0x33) + `"}`,
		"ACCOUNT_REGISTRATION_TERMS_VERSION":              "terms_v1",
		"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_ID":          "registration_email",
		"ACCOUNT_REGISTRATION_EMAIL_TEMPLATE_VERSION":     "1",
		"ACCOUNT_REGISTRATION_TURNSTILE_SECRET":           "turnstile-secret-value",
		"ACCOUNT_REGISTRATION_TURNSTILE_HOSTNAME":         "register.example",
		"ACCOUNT_REGISTRATION_TURNSTILE_ACTION":           "register",
	}
}

func newAccountRegistrationTurnstileServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "turnstile-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return server, caFile
}
