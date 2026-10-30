package main

import (
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
)

func TestNotificationRuntimeConfigIsDisabledByDefaultAndIgnoresProviderSecrets(t *testing.T) {
	config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(map[string]string{
		"NOTIFICATION_SMTP_PASSWORD":  "ignored-secret\n",
		"NOTIFICATION_SMTP_ADDRESS":   "smtp://user:ignored-secret@example.test",
		"NOTIFICATION_SMS_AUTH_TOKEN": "ignored-sms-secret\n",
	}))
	if err != nil || config.Enabled || len(config.SMTP.Password) != 0 || len(config.SMS.AuthToken) != 0 {
		t.Fatalf("disabled notification runtime config = (%#v, %v)", config, err)
	}
}

func TestNotificationRuntimeConfigRequiresEveryProductionBoundary(t *testing.T) {
	valid := validNotificationRuntimeEnvironment()
	required := []string{
		"NOTIFICATION_WORKER_BATCH_SIZE", "NOTIFICATION_WORKER_LEASE_DURATION",
		"NOTIFICATION_WORKER_LEASE_SAFETY_MARGIN", "NOTIFICATION_WORKER_MAX_ATTEMPTS",
		"NOTIFICATION_WORKER_BASE_DELAY", "NOTIFICATION_WORKER_MAX_DELAY",
		"NOTIFICATION_RUNTIME_IDLE_WAIT", "NOTIFICATION_RUNTIME_ERROR_BACKOFF_BASE",
		"NOTIFICATION_RUNTIME_ERROR_BACKOFF_MAX", "NOTIFICATION_RUNTIME_MAX_CONSECUTIVE_FAILURES",
		"NOTIFICATION_RUNTIME_SEND_TIMEOUT", "NOTIFICATION_RUNTIME_STARTUP_TIMEOUT",
		"NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT", "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID",
		"ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION", "NOTIFICATION_EMAIL_PROVIDER",
		"NOTIFICATION_SMTP_ADDRESS", "NOTIFICATION_SMTP_SERVER_NAME",
		"NOTIFICATION_SMTP_USERNAME", "NOTIFICATION_SMTP_PASSWORD", "NOTIFICATION_SMTP_FROM",
	}
	for _, name := range required {
		t.Run(name, func(t *testing.T) {
			environment := cloneNotificationRuntimeEnv(valid)
			delete(environment, name)
			_, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("missing %s error = %v", name, err)
			}
		})
	}
}

func TestNotificationRuntimeConfigRedactsInvalidProviderConfiguration(t *testing.T) {
	const secret = "smtp-visible-secret"
	environment := validNotificationRuntimeEnvironment()
	environment["NOTIFICATION_SMTP_ADDRESS"] = "user:" + secret + "@smtp.example.test:465"
	environment["NOTIFICATION_SMTP_PASSWORD"] = secret
	_, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
	if err == nil || !strings.Contains(err.Error(), "NOTIFICATION_SMTP_ADDRESS") || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe SMTP configuration error = %v", err)
	}

	const smsSecret = "sms-visible-secret"
	environment = validNotificationSMSRuntimeEnvironment()
	environment["NOTIFICATION_SMS_ENDPOINT"] = "https://" + smsSecret + "@sms.example.test/v1/messages"
	environment["NOTIFICATION_SMS_AUTH_TOKEN"] = smsSecret
	_, err = loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
	if err == nil || !strings.Contains(err.Error(), "NOTIFICATION_SMS_ENDPOINT") || strings.Contains(err.Error(), smsSecret) {
		t.Fatalf("unsafe SMS configuration error = %v", err)
	}
}

func TestNotificationRuntimeConfigLoadsExplicitSMTPAndWorkerSettings(t *testing.T) {
	config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(validNotificationRuntimeEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.clearSecrets)
	if !config.Enabled || config.EmailProvider != notificationEmailProviderSMTPTLS ||
		config.Worker.BatchSize != 4 || config.Worker.LeaseDuration != 30*time.Second ||
		config.Worker.LeaseSafetyMargin != 5*time.Second || config.Worker.MaxAttempts != 5 ||
		config.Worker.BaseDelay != time.Second || config.Worker.MaxDelay != time.Minute ||
		config.IdleWait != 100*time.Millisecond || config.ErrorBackoffBase != 200*time.Millisecond ||
		config.ErrorBackoffMax != 2*time.Second || config.MaxConsecutiveFailures != 4 ||
		config.SendTimeout != 5*time.Second || config.StartupTimeout != 3*time.Second ||
		config.ShutdownTimeout != 2*time.Second || config.SMTP.Address != "smtp.example.test:465" ||
		config.SMTP.ServerName != "smtp.example.test" || config.SMTP.Username != "mailer" ||
		string(config.SMTP.Password) != "smtp-password" || config.SMTP.From != "notifications@example.test" ||
		config.RecoveryTemplates[notification.ChannelEmail].ID != "account_recovery" {
		t.Fatalf("loaded notification runtime config = %#v", config)
	}
	config.clearSecrets()
	if len(config.SMTP.Password) != 0 {
		t.Fatal("clearSecrets retained SMTP password")
	}
}

func TestNotificationRuntimeConfigLoadsExternalSecretReferences(t *testing.T) {
	environment := validNotificationRuntimeEnvironment()
	environment["NOTIFICATION_SMTP_PASSWORD_REFERENCE"] = "vault://smtp/password"
	config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.clearSecrets)
	if config.SMTPPasswordReference != "vault://smtp/password" {
		t.Fatalf("SMTP secret reference = %q", config.SMTPPasswordReference)
	}
	for _, reference := range []string{"plaintext", "vault://", " kms-envelope://sms/key", "kms-envelope://"} {
		environment := validNotificationRuntimeEnvironment()
		environment["NOTIFICATION_SMTP_PASSWORD_REFERENCE"] = reference
		if _, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment)); err == nil {
			t.Fatalf("accepted invalid secret reference %q", reference)
		}
	}
}

func TestNotificationRuntimeConfigLoadsExplicitSTARTTLSAndRejectsUnknownEmailProvider(t *testing.T) {
	environment := validNotificationRuntimeEnvironment()
	environment["NOTIFICATION_EMAIL_PROVIDER"] = "smtp_starttls"
	environment["NOTIFICATION_SMTP_ADDRESS"] = "smtp.example.test:587"
	config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.clearSecrets)
	if config.EmailProvider != notificationEmailProviderSMTPSTARTTLS || !config.SMTP.StartTLS ||
		config.SMTP.Address != "smtp.example.test:587" {
		t.Fatalf("loaded STARTTLS config = %#v", config)
	}

	for _, provider := range []string{"smtp", "starttls", "SMTP_STARTTLS", "smtp_starttls "} {
		t.Run(provider, func(t *testing.T) {
			environment := validNotificationRuntimeEnvironment()
			environment["NOTIFICATION_EMAIL_PROVIDER"] = provider
			_, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
			if err == nil || !strings.Contains(err.Error(), "NOTIFICATION_EMAIL_PROVIDER") {
				t.Fatalf("provider %q error = %v", provider, err)
			}
		})
	}
}

func TestNotificationRuntimeConfigLoadsSMSOnlyAndBothProviders(t *testing.T) {
	smsOnly, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(validNotificationSMSRuntimeEnvironment()))
	if err != nil {
		t.Fatal(err)
	}
	if !smsOnly.Enabled || smsOnly.SMSProvider != notificationSMSProviderHTTPSJSON ||
		smsOnly.EmailProvider != "" || len(smsOnly.SMTP.Password) != 0 ||
		smsOnly.SMS.Endpoint != "https://sms.example.test/v1/messages" ||
		smsOnly.SMS.ReadyEndpoint != "https://sms.example.test/ready" ||
		string(smsOnly.SMS.AuthToken) != "sms-auth-token" ||
		smsOnly.RecoveryTemplates[notification.ChannelSMS].ID != "account_recovery_sms" {
		t.Fatalf("loaded SMS-only config = %#v", smsOnly)
	}
	smsOnly.clearSecrets()
	if len(smsOnly.SMS.AuthToken) != 0 {
		t.Fatal("clearSecrets retained SMS auth token")
	}

	bothEnvironment := validNotificationRuntimeEnvironment()
	for name, value := range validNotificationSMSRuntimeEnvironment() {
		if name == "NOTIFICATION_RUNTIME_ENABLED" || strings.HasPrefix(name, "NOTIFICATION_WORKER_") ||
			strings.HasPrefix(name, "NOTIFICATION_RUNTIME_") {
			continue
		}
		bothEnvironment[name] = value
	}
	both, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(bothEnvironment))
	if err != nil {
		t.Fatal(err)
	}
	if both.EmailProvider != notificationEmailProviderSMTPTLS ||
		both.SMSProvider != notificationSMSProviderHTTPSJSON || len(both.RecoveryTemplates) != 2 {
		t.Fatalf("loaded dual-provider config = %#v", both)
	}
	both.clearSecrets()
	if len(both.SMTP.Password) != 0 || len(both.SMS.AuthToken) != 0 {
		t.Fatal("clearSecrets retained dual-provider secrets")
	}
}

func TestNotificationRuntimeConfigRequiresEverySMSBoundary(t *testing.T) {
	valid := validNotificationSMSRuntimeEnvironment()
	for _, name := range []string{
		"ACCOUNT_RECOVERY_SMS_TEMPLATE_ID", "ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION",
		"NOTIFICATION_SMS_PROVIDER", "NOTIFICATION_SMS_ENDPOINT",
		"NOTIFICATION_SMS_READY_ENDPOINT", "NOTIFICATION_SMS_AUTH_TOKEN",
	} {
		t.Run(name, func(t *testing.T) {
			environment := cloneNotificationRuntimeEnv(valid)
			delete(environment, name)
			_, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("missing %s error = %v", name, err)
			}
		})
	}
}

func validNotificationRuntimeEnvironment() map[string]string {
	return map[string]string{
		"NOTIFICATION_RUNTIME_ENABLED":                  "true",
		"NOTIFICATION_WORKER_BATCH_SIZE":                "4",
		"NOTIFICATION_WORKER_LEASE_DURATION":            "30s",
		"NOTIFICATION_WORKER_LEASE_SAFETY_MARGIN":       "5s",
		"NOTIFICATION_WORKER_MAX_ATTEMPTS":              "5",
		"NOTIFICATION_WORKER_BASE_DELAY":                "1s",
		"NOTIFICATION_WORKER_MAX_DELAY":                 "1m",
		"NOTIFICATION_RUNTIME_IDLE_WAIT":                "100ms",
		"NOTIFICATION_RUNTIME_ERROR_BACKOFF_BASE":       "200ms",
		"NOTIFICATION_RUNTIME_ERROR_BACKOFF_MAX":        "2s",
		"NOTIFICATION_RUNTIME_MAX_CONSECUTIVE_FAILURES": "4",
		"NOTIFICATION_RUNTIME_SEND_TIMEOUT":             "5s",
		"NOTIFICATION_RUNTIME_STARTUP_TIMEOUT":          "3s",
		"NOTIFICATION_RUNTIME_SHUTDOWN_TIMEOUT":         "2s",
		"ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID":            "account_recovery",
		"ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION":       "1",
		"NOTIFICATION_EMAIL_PROVIDER":                   "smtp_tls",
		"NOTIFICATION_SMTP_ADDRESS":                     "smtp.example.test:465",
		"NOTIFICATION_SMTP_SERVER_NAME":                 "smtp.example.test",
		"NOTIFICATION_SMTP_USERNAME":                    "mailer",
		"NOTIFICATION_SMTP_PASSWORD":                    "smtp-password",
		"NOTIFICATION_SMTP_FROM":                        "notifications@example.test",
	}
}

func validNotificationSMSRuntimeEnvironment() map[string]string {
	environment := validNotificationRuntimeEnvironment()
	delete(environment, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_ID")
	delete(environment, "ACCOUNT_RECOVERY_EMAIL_TEMPLATE_VERSION")
	delete(environment, "NOTIFICATION_EMAIL_PROVIDER")
	delete(environment, "NOTIFICATION_SMTP_ADDRESS")
	delete(environment, "NOTIFICATION_SMTP_SERVER_NAME")
	delete(environment, "NOTIFICATION_SMTP_USERNAME")
	delete(environment, "NOTIFICATION_SMTP_PASSWORD")
	delete(environment, "NOTIFICATION_SMTP_FROM")
	environment["ACCOUNT_RECOVERY_SMS_TEMPLATE_ID"] = "account_recovery_sms"
	environment["ACCOUNT_RECOVERY_SMS_TEMPLATE_VERSION"] = "2"
	environment["NOTIFICATION_SMS_PROVIDER"] = "https_json"
	environment["NOTIFICATION_SMS_ENDPOINT"] = "https://sms.example.test/v1/messages"
	environment["NOTIFICATION_SMS_READY_ENDPOINT"] = "https://sms.example.test/ready"
	environment["NOTIFICATION_SMS_AUTH_TOKEN"] = "sms-auth-token"
	return environment
}

func mapNotificationRuntimeEnv(values map[string]string) notificationRuntimeEnvLookup {
	return func(name string) (string, bool) {
		value, exists := values[name]
		return value, exists
	}
}

func cloneNotificationRuntimeEnv(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for name, value := range source {
		clone[name] = value
	}
	return clone
}
