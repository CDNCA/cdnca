package main

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
)

// the built-in SMTP transport accepts after DATA 250 with no provider
// delivery id; the code sender recorded that as permanent_failed provider_contract_invalid and the visitor
// never got a code. An empty id is accepted as is (not invented), a provider's id passes through, a malformed
// one is still refused.
func TestAccountRegistrationAcceptsSMTPWithoutProviderDeliveryID(t *testing.T) {
	accepted := func(id string) notification.SendResult {
		return mapAccountRegistrationProviderResult(notification.ChannelEmail, notificationruntime.ProviderResult{
			Disposition: notificationruntime.ProviderAccepted, ProviderDeliveryID: id})
	}
	if result := accepted(""); result.Disposition != notification.SendAccepted || result.ProviderDeliveryID != "" ||
		result.Provider != "configured_email" {
		t.Fatalf("SMTP accept without an id: %+v", result)
	}
	if result := accepted("msg-0001@mail.example"); result.Disposition != notification.SendAccepted ||
		result.ProviderDeliveryID != "msg-0001@mail.example" {
		t.Fatalf("provider id: %+v", result)
	}
	for _, bad := range []string{"bad\nid", "bad\x7fid", strings.Repeat("x", 257)} {
		if result := accepted(bad); result.Disposition == notification.SendAccepted || result.Failure == nil || result.Failure.Code != "provider_contract_invalid" {
			t.Fatalf("%q accepted: %+v", bad, result)
		}
	}
}

// The same through the real TLS SMTP transport (DATA 250, no provider id): the registration code mail is
// accepted, reaches the server and carries the code.
func TestAccountRegistrationCodeOverRealSMTPIsAccepted(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	transport, err := newSMTPTLSTransport(server.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transport.Close(t.Context()) }()
	provider := &accountRegistrationContactProvider{
		catalog:   notification.NewCatalog(),
		templates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: {ID: "registration_template", Version: 1, Channel: notification.ChannelEmail}},
		providers: map[notification.Channel]notificationruntime.ProviderTransport{notification.ChannelEmail: transport},
		timeout:   5 * time.Second,
	}
	result := provider.SendRegistrationVerification(t.Context(), accountregistrationchallenge.ContactDelivery{
		OutboxID: uuid.New(), Channel: notification.ChannelEmail,
		Template:    notification.TemplateRef{ID: "platform_user_registration_verification", Version: 3, Channel: notification.ChannelEmail},
		Destination: "visitor@example.test", OTP: "482915", Subject: "验证码 {{.captcha}}",
		Body: "当前验证码：{{.captcha}}", IdempotencyKey: "notification-v1-registration-smtp", AttemptNumber: 1,
	})
	if result.Disposition != notification.SendAccepted || result.Failure != nil || result.ProviderDeliveryID != "" {
		t.Fatalf("registration code over SMTP = %+v", result)
	}
	if messages := server.messages(); len(messages) != 1 || !strings.Contains(messages[0], "482915") {
		t.Fatalf("SMTP server received %d messages", len(messages))
	}
}
