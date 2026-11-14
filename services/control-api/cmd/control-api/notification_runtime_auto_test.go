package main

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// NOTIFICATION_RUNTIME_ENABLED unset, auto
// or false is auto (the page decides), off forces the runtime off, true is
// the explicit environment configuration.
func TestNotificationRuntimeSwitchPrecedence(t *testing.T) {
	for _, value := range []string{"", "auto", "false"} {
		environment := map[string]string{}
		if value != "" {
			environment["NOTIFICATION_RUNTIME_ENABLED"] = value
		}
		config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(environment))
		if err != nil || !config.Auto || !config.Requested || config.Enabled ||
			config.EmailProvider != notificationEmailProviderSettings || config.Worker.BatchSize != 16 ||
			config.RecoveryTemplates[notification.ChannelEmail] != accountLoginFallbackTemplates[notification.ChannelEmail] {
			t.Fatalf("%q: auto config = (%+v, %v)", value, config, err)
		}
	}
	off, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(map[string]string{
		"NOTIFICATION_RUNTIME_ENABLED": "off", "NOTIFICATION_SMTP_PASSWORD": "ignored"}))
	if err != nil || off.Requested || off.Enabled || off.Auto || len(off.SMTP.Password) != 0 {
		t.Fatalf("off config = (%+v, %v)", off, err)
	}
	// forced off wins over a complete page: nothing is resolved, no test mail
	off.SMTP = smtpTLSConfig{Address: "smtp.example.com:465", Username: "mailer", Password: []byte("p"), From: "noreply@example.com"}
	off.EmailProvider = notificationEmailProviderSMTPTLS
	resolveNotificationRuntime(&off)
	if off.Enabled || newSystemMailTestSender(off, nil) != nil {
		t.Fatal("NOTIFICATION_RUNTIME_ENABLED=off was overridden by the page")
	}
	if _, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(map[string]string{
		"NOTIFICATION_RUNTIME_ENABLED": "yes"})); err == nil || !strings.Contains(err.Error(), "NOTIFICATION_RUNTIME_ENABLED") {
		t.Fatalf("invalid switch err = %v", err)
	}
	explicit := validNotificationRuntimeEnvironment()
	delete(explicit, "NOTIFICATION_SMTP_PASSWORD")
	delete(explicit, "NOTIFICATION_SMTP_FROM")
	config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(explicit))
	if err != nil || !config.Enabled || config.Auto || config.EmailProvider != notificationEmailProviderSMTPTLS {
		t.Fatalf("explicit without SMTP password/sender = (%+v, %v)", config, err)
	}
}

// A complete page sender turns the auto runtime on; the sender address falls
// back to the SMTP user (an address), then the environment.
func TestAutoNotificationRuntimeFollowsThePage(t *testing.T) {
	page := func(user, from string) systemmailsettings.RuntimeSettings {
		return systemmailsettings.RuntimeSettings{Configured: true, Value: systemmailsettings.Settings{
			SMTPAddress: "smtp.example.com", SMTPPort: 465, SMTPSSL: true, SMTPUser: user, SMTPFrom: from, SMTPFromName: "CDNCA"}}
	}
	auto := func() notificationRuntimeConfig {
		config, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(map[string]string{}))
		if err != nil {
			t.Fatal(err)
		}
		return config
	}

	config := auto()
	if err := mergePersistedNotificationMailSettings(&config, page("mailer@example.com", "")); err != nil {
		t.Fatal(err)
	}
	if config.SMTP.From != "mailer@example.com" || config.SMTP.FromName != "CDNCA" || config.EmailProvider != notificationEmailProviderSMTPTLS {
		t.Fatalf("merged = %+v", config.SMTP)
	}
	config.SMTP.Password = []byte("saved on the page") // what OpenSMTPPassword returns at start
	resolveNotificationRuntime(&config)
	if !config.Enabled || !notificationEmailConfigured(config) || len(config.Unavailable) != 0 {
		t.Fatalf("complete page did not enable the runtime: %+v", config)
	}

	config = auto()
	if err := mergePersistedNotificationMailSettings(&config, page("mailer", "sender@example.com")); err != nil ||
		config.SMTP.From != "sender@example.com" {
		t.Fatalf("explicit sender = %q err %v", config.SMTP.From, err)
	}

	// No sender anywhere: email stays off with a reason naming the field,
	// the start does not fail.
	config = auto()
	if err := mergePersistedNotificationMailSettings(&config, page("mailer", "")); err != nil {
		t.Fatal(err)
	}
	config.SMTP.Password = []byte("saved on the page")
	resolveNotificationRuntime(&config)
	if config.Enabled || config.EmailProvider != "" || !strings.Contains(config.Unavailable["email"], "value.smtp_from") {
		t.Fatalf("missing sender: enabled=%v reason=%q", config.Enabled, config.Unavailable["email"])
	}

	// Nothing saved on the page: auto stays off with a reason.
	config = auto()
	resolveNotificationRuntime(&config)
	if config.Enabled || config.Unavailable["email"] == "" {
		t.Fatalf("empty page: %+v", config)
	}
}

// The test mail with a complete page needs nothing from the environment; an
// incomplete page answers which fields are missing.
func TestSystemMailTestSenderWithThePageOnly(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	base, err := loadNotificationRuntimeConfigFromEnv(mapNotificationRuntimeEnv(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	base.SMTP.CAFile = server.caFile
	send := newSystemMailTestSender(base, nil)
	_, portText, _ := net.SplitHostPort(server.listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	value := systemmailsettings.DefaultSettings()
	value.SMTPAddress, value.SMTPPort, value.SMTPUser, value.SMTPSSL = "localhost", port, "mailer", true

	var missing *systemmailsettings.MissingError
	_, err = send(t.Context(), systemmailsettings.TestTarget{Value: value, To: "ops@example.com"})
	if !errors.As(err, &missing) || !reflect.DeepEqual(missing.Fields, []string{"smtp_password", "value.smtp_from"}) {
		t.Fatalf("incomplete page err = %v", err)
	}
	value.SMTPFrom, value.SMTPFromName = "notifications@example.test", "运维中心"
	if _, err := send(t.Context(), systemmailsettings.TestTarget{Value: value, SMTPPassword: []byte("smtp-password"),
		To: "ops@example.com"}); err != nil {
		t.Fatalf("complete page err = %v", err)
	}
	messages := server.messages()
	if len(messages) != 1 || !strings.Contains(messages[0], "<notifications@example.test>") || !strings.Contains(messages[0], "=?UTF-8?b?") {
		t.Fatalf("messages = %q", messages)
	}
}
