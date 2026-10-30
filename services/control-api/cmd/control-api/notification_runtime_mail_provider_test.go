package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/pluginproviders"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/google/uuid"
)

func officialMailSettings(provider string) systemmailsettings.Settings {
	value := systemmailsettings.DefaultSettings()
	value.MailProvider, value.MailFrom, value.MailFromName = provider, "noreply@example.com", "CDNCA"
	if provider == systemmailsettings.MailProviderAliyun {
		value.MailAccessKeyID = "LTAI-id"
	}
	return value
}

func openSecret(secret string) func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(secret), nil }
}

// The saved mail_provider decides the email transport; the SMTP config
// loaded from the environment is left as it was.
func TestMergePersistedMailProviderChoosesOneSender(t *testing.T) {
	smtp := smtpTLSConfig{Address: "smtp.example.com:465", ServerName: "smtp.example.com", Username: "u", Password: []byte("p"), From: "a@example.com"}
	official := notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS, SMTP: smtp}
	if err := mergePersistedMailProvider(&official, officialMailSettings("sendgrid"), openSecret("SG.key")); err != nil {
		t.Fatal(err)
	}
	if official.EmailProvider != notificationEmailProviderService || official.Mail.Service.Provider != "sendgrid" ||
		official.Mail.Service.AccessKeySecret != "SG.key" || official.SMTP.Address != smtp.Address || !notificationEmailConfigured(official) {
		t.Fatalf("official merge %+v", official)
	}
	plugin := notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSettings}
	value := systemmailsettings.DefaultSettings()
	value.MailProvider = "plugin:com.example.mail"
	if err := mergePersistedMailProvider(&plugin, value, nil); err != nil {
		t.Fatal(err)
	}
	if plugin.EmailProvider != notificationEmailProviderPlugin || plugin.Mail.PluginID != "com.example.mail" || !notificationEmailConfigured(plugin) {
		t.Fatalf("plugin merge %+v", plugin)
	}
	kept := notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSMTPSTARTTLS, SMTP: smtpTLSConfig{StartTLS: true}}
	if err := mergePersistedMailProvider(&kept, systemmailsettings.DefaultSettings(), nil); err != nil ||
		kept.EmailProvider != notificationEmailProviderSMTPSTARTTLS {
		t.Fatalf("smtp choice changed the transport: %+v %v", kept, err)
	}
	dormant := notificationRuntimeConfig{Enabled: true}
	if err := mergePersistedMailProvider(&dormant, officialMailSettings("aliyun"), openSecret("s")); err != nil || dormant.EmailProvider != "" {
		t.Fatalf("email disabled but provider applied: %+v %v", dormant, err)
	}
}

func TestMergePersistedMailProviderFailsClosed(t *testing.T) {
	cases := map[string]struct {
		config notificationRuntimeConfig
		value  systemmailsettings.Settings
		open   func() ([]byte, error)
	}{
		"settings mode with smtp": {notificationRuntimeConfig{EmailProvider: notificationEmailProviderSettings}, systemmailsettings.DefaultSettings(), nil},
		"credential unavailable": {notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}, officialMailSettings("aliyun"),
			func() ([]byte, error) { return nil, errors.New("no key") }},
		"no keyring": {notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}, officialMailSettings("aliyun"), nil},
	}
	for name, c := range cases {
		config := c.config
		if err := mergePersistedMailProvider(&config, c.value, c.open); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestLoadNotificationEmailProviderSettingsModeNeedsNoSMTPEnvironment(t *testing.T) {
	config := notificationRuntimeConfig{}
	lookup := func(name string) (string, bool) {
		if name == "NOTIFICATION_EMAIL_PROVIDER" {
			return notificationEmailProviderSettings, true
		}
		return "", false
	}
	if err := loadNotificationEmailProvider(lookup, &config); err != nil || config.EmailProvider != notificationEmailProviderSettings {
		t.Fatalf("settings mode %+v %v", config, err)
	}
	if notificationEmailConfigured(config) {
		t.Fatal("settings mode without a persisted provider counts as configured")
	}
}

func TestNewConfiguredEmailTransportPicksTheChosenSender(t *testing.T) {
	smtpCalls := 0
	newSMTP := func(smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
		smtpCalls++
		return &fakeEmailTransport{}, nil
	}
	smtp := notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS}
	if _, err := newConfiguredEmailTransport(smtp, newSMTP, nil, nil); err != nil || smtpCalls != 1 {
		t.Fatalf("smtp transport %v calls=%d", err, smtpCalls)
	}
	official := notificationRuntimeConfig{EmailProvider: notificationEmailProviderService,
		Mail: notificationMailChoice{Service: mail.ServiceConfig{Provider: "sendgrid", AccessKeySecret: "SG.k", From: "a@example.com"}}}
	transport, err := newConfiguredEmailTransport(official, newSMTP, nil, nil)
	if _, ok := transport.(*officialMailTransport); err != nil || !ok || smtpCalls != 1 {
		t.Fatalf("official transport %T %v calls=%d", transport, err, smtpCalls)
	}
	plugin := notificationRuntimeConfig{EmailProvider: notificationEmailProviderPlugin, Mail: notificationMailChoice{PluginID: "com.example.mail"}}
	transport, err = newConfiguredEmailTransport(plugin, newSMTP, nil, nil)
	if chosen, ok := transport.(pluginproviders.MailTransport); err != nil || !ok || chosen.PluginID != "com.example.mail" || smtpCalls != 1 {
		t.Fatalf("plugin transport %T %v", transport, err)
	}
}

type fakeEmailTransport struct{}

func (*fakeEmailTransport) Ready(context.Context) error { return nil }
func (*fakeEmailTransport) Send(context.Context, notificationruntime.ProviderMessage) (notificationruntime.ProviderResult, error) {
	return notificationruntime.ProviderResult{Disposition: notificationruntime.ProviderAccepted}, nil
}
func (*fakeEmailTransport) Close(context.Context) error { return nil }

// An official service failure is recorded on the message; it never falls
// back to SMTP.
func TestOfficialMailTransportMapsFailures(t *testing.T) {
	cases := map[int]notificationruntime.ProviderDisposition{
		http.StatusAccepted: notificationruntime.ProviderAccepted, http.StatusUnauthorized: notificationruntime.ProviderPermanentFailure,
		http.StatusTooManyRequests: notificationruntime.ProviderRateLimited, http.StatusBadGateway: notificationruntime.ProviderTemporaryFailure,
	}
	for status, want := range cases {
		var body string
		server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			raw := make([]byte, 4096)
			n, _ := request.Body.Read(raw)
			body = string(raw[:n])
			writer.WriteHeader(status)
		}))
		transport, err := newOfficialMailTransport(mail.ServiceConfig{Provider: "sendgrid", AccessKeySecret: "SG.k", From: "a@example.com",
			Endpoint: server.URL, HTTPClient: server.Client()}, nil)
		if err != nil {
			t.Fatal(err)
		}
		result, err := transport.Send(t.Context(), notificationruntime.ProviderMessage{OutboxID: uuid.New(), Channel: notification.ChannelEmail,
			Contact: "user@example.com", Subject: "s", Body: "b", ActionURL: "https://console.example.com/x", IdempotencyKey: "k", AttemptNumber: 1})
		server.Close()
		if err != nil || result.Disposition != want {
			t.Errorf("%d: %+v %v", status, result, err)
		}
		if !strings.Contains(body, `b\n\nhttps://console.example.com/x`) {
			t.Errorf("%d: body %s", status, body)
		}
	}
}

func TestSystemMailTestSenderUsesThePageProvider(t *testing.T) {
	var got string
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		got = request.Header.Get("Authorization")
		writer.Header().Set("X-Message-Id", "sg-test")
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	if newSystemMailTestSender(notificationRuntimeConfig{Enabled: true}, nil) != nil {
		t.Fatal("test sender without email enabled")
	}
	send := newSystemMailTestSender(notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSettings}, nil)
	// SMTP without an environment password cannot be tested.
	if _, err := send(t.Context(), systemmailsettings.TestTarget{Value: systemmailsettings.DefaultSettings(), To: "ops@example.com"}); mail.ErrorOf(err) == nil ||
		mail.ErrorOf(err).Code != mail.CodeInvalidConfig {
		t.Fatalf("smtp without password err=%v", err)
	}
	value := officialMailSettings("sendgrid")
	value.MailRegion = ""
	previous := mailServiceEndpointOverride
	mailServiceEndpointOverride = func(config *mail.ServiceConfig) { config.Endpoint, config.HTTPClient = server.URL, server.Client() }
	defer func() { mailServiceEndpointOverride = previous }()
	id, err := send(t.Context(), systemmailsettings.TestTarget{Value: value, Secret: []byte("SG.page"), To: "ops@example.com"})
	if err != nil || id != "sg-test" || got != "Bearer SG.page" {
		t.Fatalf("official test id=%q err=%v auth=%q", id, err, got)
	}
}

// A channel the runtime cannot send with is not offered
// on the customer subscription page (sms_supported / email_supported).
func TestNotificationChannelTransportsFollowConfiguration(t *testing.T) {
	for name, tc := range map[string]struct {
		config     notificationRuntimeConfig
		sms, email bool
	}{
		"runtime off":      {config: notificationRuntimeConfig{EmailProvider: notificationEmailProviderSMTPTLS, SMSProvider: notificationSMSProviderHTTPSJSON}},
		"nothing chosen":   {config: notificationRuntimeConfig{Enabled: true}},
		"settings no mail": {config: notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSettings}},
		"email only":       {config: notificationRuntimeConfig{Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS}, email: true},
		"sms only":         {config: notificationRuntimeConfig{Enabled: true, SMSProvider: notificationSMSProviderHTTPSJSON}, sms: true},
	} {
		got := notificationChannelTransports(tc.config)
		if got.SMS != tc.sms || got.Email != tc.email {
			t.Fatalf("%s: transports = %+v", name, got)
		}
	}
}

// An official mail service sends only while the lease grants its module
// (module.mail.<provider>); a revoked module fails the send permanently on
// the outbox without reaching the provider.
func TestOfficialMailTransportNeedsItsModule(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		hits++
		writer.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	asked := ""
	granted := false
	config := notificationRuntimeConfig{EmailProvider: notificationEmailProviderService, Mail: notificationMailChoice{
		Service: mail.ServiceConfig{Provider: "sendgrid", AccessKeySecret: "SG.k", From: "a@example.com", Endpoint: server.URL, HTTPClient: server.Client()},
		Granted: func(_ context.Context, module string) (bool, error) { asked = module; return granted, nil }}}
	transport, err := newConfiguredEmailTransport(config, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	message := notificationruntime.ProviderMessage{OutboxID: uuid.New(), Channel: notification.ChannelEmail,
		Contact: "user@example.com", Subject: "s", Body: "b", IdempotencyKey: "k", AttemptNumber: 1}
	result, err := transport.Send(t.Context(), message)
	if err != nil || result.Disposition != notificationruntime.ProviderPermanentFailure || result.Code != "mail_module_not_licensed" ||
		hits != 0 || asked != "module.mail.sendgrid" {
		t.Fatalf("revoked: %+v %v hits=%d asked=%q", result, err, hits, asked)
	}
	granted = true
	if result, err = transport.Send(t.Context(), message); err != nil || result.Disposition != notificationruntime.ProviderAccepted || hits != 1 {
		t.Fatalf("granted: %+v %v hits=%d", result, err, hits)
	}
	config.Mail.Granted = func(context.Context, string) (bool, error) { return false, errors.New("lease read failed") }
	failing, _ := newConfiguredEmailTransport(config, nil, nil, nil)
	if _, err := failing.Send(t.Context(), message); err == nil || hits != 1 {
		t.Fatalf("lease error: %v hits=%d (want a retryable error, no send)", err, hits)
	}
}
