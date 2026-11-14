package main

import (
	"net"
	"strconv"
	"testing"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// The test mail authenticates with the SMTP password
// saved on the settings page (TestTarget.SMTPPassword) instead of the
// environment one, and a stale reference on the page does not block it.
func TestSystemMailTestSenderUsesTheSavedSMTPPassword(t *testing.T) {
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	base := server.clientConfig()
	base.Password = []byte("wrong-environment-password")
	config := notificationRuntimeConfig{Enabled: true, Requested: true, EmailProvider: notificationEmailProviderSMTPTLS, SMTP: base,
		SMTPPasswordReference: "vault://runtime/password"}
	send := newSystemMailTestSender(config, nil)
	_, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	value := systemmailsettings.DefaultSettings()
	value.SMTPAddress, value.SMTPPort, value.SMTPUser, value.SMTPSSL = "localhost", port, "mailer", true
	value.SMTPPasswordReference = "vault://stale/password"

	if _, err := send(t.Context(), systemmailsettings.TestTarget{Value: value, To: "ops@example.com"}); mail.ErrorOf(err) == nil {
		t.Fatal("stale reference with the environment password was accepted")
	}
	id, err := send(t.Context(), systemmailsettings.TestTarget{Value: value, SMTPPassword: []byte("smtp-password"), To: "ops@example.com"})
	if err != nil || len(server.messages()) != 1 {
		t.Fatalf("saved password test id=%q err=%v messages=%d", id, err, len(server.messages()))
	}
	if string(config.SMTP.Password) != "wrong-environment-password" {
		t.Fatal("test send changed the runtime environment password")
	}
}
