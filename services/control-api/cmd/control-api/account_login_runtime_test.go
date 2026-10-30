package main

import (
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountloginchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
)

func TestAccountLoginTemplatesFollowConfiguredProviders(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		config             notificationRuntimeConfig
		wantEmail, wantSMS bool
	}{
		"none":  {},
		"email": {config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}, wantEmail: true},
		"sms":   {config: notificationRuntimeConfig{SMSProvider: notificationSMSProviderHTTPSJSON}, wantSMS: true},
		"both":  {config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPSTARTTLS, SMSProvider: notificationSMSProviderHTTPSJSON}, wantEmail: true, wantSMS: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			templates := accountLoginTemplates(test.config)
			_, hasEmail := templates[notification.ChannelEmail]
			_, hasSMS := templates[notification.ChannelSMS]
			if hasEmail != test.wantEmail || hasSMS != test.wantSMS || len(templates) != boolCount(test.wantEmail, test.wantSMS) {
				t.Fatalf("templates=%+v", templates)
			}
		})
	}
}

func TestAccountLoginProviderRendersPublishedVerificationTemplate(t *testing.T) {
	t.Parallel()

	fallback := notification.TemplateRef{ID: "login_template", Version: 1, Channel: notification.ChannelEmail}
	transport := &registrationCaptureTransport{}
	provider := &accountRegistrationContactProvider{
		catalog:   notification.NewCatalog(),
		templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: fallback},
		providers: map[notification.Channel]notificationruntime.ProviderTransport{notification.ChannelEmail: transport},
		timeout:   time.Second,
	}
	result := provider.SendLoginVerification(t.Context(), accountloginchallenge.ContactDelivery{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail,
		Template:    notification.TemplateRef{ID: "platform_user_verification", Version: 2, Channel: notification.ChannelEmail},
		Destination: "owner@example.test", OTP: "654321", Subject: "登录验证码 {{.captcha}}",
		Body: "<p>验证码：{{.captcha}}</p>", IdempotencyKey: "notification-v1-login", AttemptNumber: 1,
	})
	if result.Disposition != notification.SendAccepted || transport.message.Subject != "登录验证码 654321" ||
		transport.message.Body != "<p>验证码：654321</p>" {
		t.Fatalf("rendered login delivery=(%#v,%#v)", result, transport.message)
	}
}

func TestAccountRecoveryConfigDerivesLoginDispatchKeyring(t *testing.T) {
	environment := validAccountRecoveryEnvironment()
	config, err := loadAccountRecoveryRuntimeConfigFromEnv(mapAccountRecoveryEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	if config.DispatchKeys == nil || config.LoginDispatchKeys == nil {
		t.Fatalf("dispatch keyrings recovery=%v login=%v", config.DispatchKeys, config.LoginDispatchKeys)
	}
}

func TestAccountLoginCaptchaSecretsComeFromTheRuntimeEnvironment(t *testing.T) {
	lookup := func(values map[string]string) accountRecoveryEnvLookup {
		return func(key string) (string, bool) { value, ok := values[key]; return value, ok }
	}
	secrets, err := loadAccountLoginCaptchaSecrets(lookup(nil))
	if err != nil {
		t.Fatalf("absent captcha secrets must leave external CAPTCHA failing closed, not block startup: %v", err)
	}
	if _, ok := secrets.ResolveSecret("vault://captcha/app-secret"); ok {
		t.Fatal("absent captcha secrets resolved a reference")
	}
	secrets, err = loadAccountLoginCaptchaSecrets(lookup(map[string]string{
		"ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON": `{"vault://captcha/app-secret":"app-secret-value-0123456789"}`,
	}))
	if value, ok := secrets.ResolveSecret("vault://captcha/app-secret"); err != nil || !ok || value != "app-secret-value-0123456789" {
		t.Fatalf("configured captcha secret=(%q,%t,%v)", value, ok, err)
	}
	_, err = loadAccountLoginCaptchaSecrets(lookup(map[string]string{"ACCOUNT_LOGIN_CAPTCHA_SECRETS_JSON": `{"plain":"app-secret-value"}`}))
	if err == nil || strings.Contains(err.Error(), "app-secret-value") {
		t.Fatalf("invalid captcha secrets error=%v", err)
	}
}
