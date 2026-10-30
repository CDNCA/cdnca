package main

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

func TestMergePersistedNotificationMailSettings(t *testing.T) {
	base := notificationRuntimeConfig{
		Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS,
		SMTPPasswordReference: "vault://smtp/password",
		SMTP:                  smtpTLSConfig{Address: "old.example:465", ServerName: "old.example", Username: "old-user"},
	}
	settings := systemmailsettings.RuntimeSettings{
		Configured: true,
		Revision:   2,
		Value: systemmailsettings.Settings{
			SMTPAddress:           "smtp.example.com",
			SMTPSSL:               false,
			SMTPPort:              587,
			SMTPUser:              "persisted-user",
			SMTPPasswordReference: "vault://smtp/password",
		},
	}
	if err := mergePersistedNotificationMailSettings(&base, settings); err != nil {
		t.Fatal(err)
	}
	if base.SMTP.Address != "smtp.example.com:587" || base.SMTP.ServerName != "smtp.example.com" ||
		base.SMTP.Username != "persisted-user" || !base.SMTP.StartTLS || base.EmailProvider != notificationEmailProviderSMTPSTARTTLS {
		t.Fatalf("merged config = %+v", base)
	}
}

func TestMergePersistedNotificationMailSettingsFailsOnSecretReferenceMismatch(t *testing.T) {
	config := notificationRuntimeConfig{SMTPPasswordReference: "vault://runtime/password"}
	settings := systemmailsettings.RuntimeSettings{
		Configured: true,
		Value: systemmailsettings.Settings{
			SMTPAddress:           "smtp.example.com",
			SMTPSSL:               true,
			SMTPPort:              465,
			SMTPUser:              "sender",
			SMTPPasswordReference: "vault://stored/password",
		},
	}
	if err := mergePersistedNotificationMailSettings(&config, settings); err == nil {
		t.Fatal("secret reference mismatch was accepted")
	}
}

func TestMergePersistedNotificationMailSettingsLeavesUnconfiguredDefaults(t *testing.T) {
	config := notificationRuntimeConfig{SMTP: smtpTLSConfig{Address: "env.example:465"}}
	if err := mergePersistedNotificationMailSettings(&config, systemmailsettings.RuntimeSettings{}); err != nil {
		t.Fatal(err)
	}
	if config.SMTP.Address != "env.example:465" {
		t.Fatalf("unconfigured settings changed runtime address to %q", config.SMTP.Address)
	}
}

func TestMergePersistedNotificationMailSettingsAppliesSMSMetadataAndReference(t *testing.T) {
	config := notificationRuntimeConfig{
		Enabled:               true,
		SMSProvider:           notificationSMSProviderHTTPSJSON,
		SMSAuthTokenReference: "vault://sms/token",
	}
	settings := systemmailsettings.RuntimeSettings{
		Configured: true,
		Value: systemmailsettings.Settings{
			SMSProvider:           notificationSMSProviderHTTPSJSON,
			SMSAccessKeyID:        "sms-access-id",
			SMSAccessKeyReference: "vault://sms/token",
			SMSSignatureName:      "CDNCA",
		},
	}
	if err := mergePersistedNotificationMailSettings(&config, settings); err != nil {
		t.Fatal(err)
	}
	if config.SMS.AccessKeyID != "sms-access-id" || config.SMS.SignatureName != "CDNCA" {
		t.Fatalf("SMS metadata = %+v", config.SMS)
	}
}

func TestMergePersistedNotificationMailSettingsRejectsSMSReferenceMismatch(t *testing.T) {
	config := notificationRuntimeConfig{SMSProvider: notificationSMSProviderHTTPSJSON, SMSAuthTokenReference: "vault://runtime/token"}
	settings := systemmailsettings.RuntimeSettings{Configured: true, Value: systemmailsettings.Settings{
		SMSProvider: notificationSMSProviderHTTPSJSON, SMSAccessKeyID: "sms-access-id",
		SMSAccessKeyReference: "vault://stored/token",
	}}
	if err := mergePersistedNotificationMailSettings(&config, settings); err == nil {
		t.Fatal("SMS secret reference mismatch was accepted")
	}
}
