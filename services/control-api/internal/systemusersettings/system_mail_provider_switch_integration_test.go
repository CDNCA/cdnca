package systemusersettings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// mail-plugin: one field (mail_provider) picks the system mail sender. The
// SMTP fields survive every switch; an official credential is encrypted,
// returned only as a fingerprint, reused only for its own provider and kept
// while SMTP or a plugin sends.
func TestPostgresSystemMailProviderSwitch(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	save := func(revision int64, value systemmailsettings.Settings, secret, key string) (systemmailsettings.Document, error) {
		return service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: revision, Value: value,
			MailSecret: secret, RequestID: key, IdempotencyKey: key})
	}
	smtp := systemmailsettings.DefaultSettings()
	smtp.SMTPAddress, smtp.SMTPUser, smtp.SMTPPort, smtp.SMTPSSL = "smtp.example.com", "mailer", 587, false
	saved, err := save(0, smtp, "", "mail-provider-1")
	if err != nil || saved.Value.MailProvider != "" || saved.MailSecretConfigured {
		t.Fatalf("smtp save=(%+v,%v)", saved, err)
	}

	// Official provider without its credential is refused; nothing changes.
	aliyun := smtp
	aliyun.MailProvider, aliyun.MailAccessKeyID, aliyun.MailFrom = "aliyun", "LTAI-mail", "noreply@mail.example.com"
	if _, err := save(1, aliyun, "", "mail-provider-2"); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
		t.Fatalf("aliyun without secret accepted: %v", err)
	}
	if current := mustGetMail(t, service, actor); current.Revision != 1 || current.Value.MailProvider != "" {
		t.Fatalf("rejected switch changed settings: %+v", current)
	}
	const secret = "aliyun-mail-secret"
	switched, err := save(1, aliyun, secret, "mail-provider-3")
	if err != nil || switched.Revision != 2 || switched.Value.MailProvider != "aliyun" || !switched.MailSecretConfigured ||
		switched.MailSecretProvider != "aliyun" || len(switched.MailSecretFingerprint) != 16 {
		t.Fatalf("switch to aliyun=(%+v,%v)", switched, err)
	}
	if switched.Value.SMTPAddress != "smtp.example.com" || switched.Value.SMTPUser != "mailer" || switched.Value.SMTPPort != 587 {
		t.Fatalf("smtp fields lost on switch: %+v", switched.Value)
	}
	var stored []byte
	var settingsJSON, receipts string
	if err := pool.QueryRow(t.Context(), `SELECT mail_secret_ciphertext,settings::text FROM platform_system_mail_settings
		WHERE platform_scope_id=$1`, scopeID).Scan(&stored, &settingsJSON); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(response_body::text,'') FROM platform_system_mail_settings_write_requests
		WHERE target_scope_id=$1`, scopeID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(mustGetMail(t, service, actor))
	if bytes.Contains(stored, []byte(secret)) || strings.Contains(settingsJSON, secret) || strings.Contains(receipts, secret) ||
		strings.Contains(string(encoded), secret) {
		t.Fatal("mail secret stored or returned in plaintext")
	}
	runtimeSettings, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtimeSettings.OpenMailSecret(xorCipher{})
	if err != nil || string(opened) != secret {
		t.Fatalf("open mail secret=%q err=%v", opened, err)
	}

	// Back to SMTP: the credential stays (switching back again needs no
	// re-entry) but the runtime does not open it for SMTP.
	back := aliyun
	back.MailProvider = ""
	reverted, err := save(2, back, "", "mail-provider-4")
	if err != nil || reverted.Value.MailProvider != "" || reverted.MailSecretProvider != "aliyun" {
		t.Fatalf("switch back=(%+v,%v)", reverted, err)
	}
	if runtimeSettings, _ = systemmailsettings.ReadRuntime(t.Context(), pool); func() bool {
		_, err := runtimeSettings.OpenMailSecret(xorCipher{})
		return err == nil
	}() {
		t.Fatal("official credential opened while SMTP is chosen")
	}
	again, err := save(3, aliyun, "", "mail-provider-5")
	if err != nil || again.Value.MailProvider != "aliyun" || again.MailSecretFingerprint != switched.MailSecretFingerprint {
		t.Fatalf("switch to aliyun again=(%+v,%v)", again, err)
	}

	// Another official provider never inherits the aliyun credential.
	sendgrid := aliyun
	sendgrid.MailProvider, sendgrid.MailAccessKeyID = "sendgrid", ""
	if _, err := save(4, sendgrid, "", "mail-provider-6"); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
		t.Fatalf("sendgrid reused the aliyun secret: %v", err)
	}
	// A plugin is chosen by id; unknown providers are refused.
	plugin := aliyun
	plugin.MailProvider = "plugin:com.example.mail"
	if chosen, err := save(4, plugin, "", "mail-provider-7"); err != nil || chosen.Value.MailProvider != "plugin:com.example.mail" {
		t.Fatalf("plugin choice=(%+v,%v)", chosen, err)
	}
	unknown := aliyun
	unknown.MailProvider = "ses"
	if _, err := save(5, unknown, "", "mail-provider-8"); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
		t.Fatalf("unknown provider accepted: %v", err)
	}
	var payload string
	if err := pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events WHERE request_id='mail-provider-3'`).Scan(&payload); err != nil ||
		!strings.Contains(payload, `"mail_provider": "aliyun"`) && !strings.Contains(payload, `"mail_provider":"aliyun"`) ||
		strings.Contains(payload, secret) {
		t.Fatalf("audit payload %q err %v", payload, err)
	}
}

// The test mail uses the provider on the page; the stored credential is
// opened only for its own provider and never reaches the audit trail.
func TestPostgresSystemMailTestSend(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	aliyun := systemmailsettings.DefaultSettings()
	aliyun.MailProvider, aliyun.MailAccessKeyID, aliyun.MailFrom = "aliyun", "LTAI-mail", "noreply@mail.example.com"
	const secret = "stored-aliyun-secret"
	if _, err := service.Save(t.Context(), actor, systemmailsettings.SaveRequest{Value: aliyun, MailSecret: secret,
		RequestID: "mail-test-save", IdempotencyKey: "mail-test-save"}); err != nil {
		t.Fatal(err)
	}
	var seen systemmailsettings.TestTarget
	send := func(_ context.Context, target systemmailsettings.TestTarget) (string, error) {
		seen = target
		seen.Secret = append([]byte(nil), target.Secret...)
		return "env-1", nil
	}
	result, err := service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: aliyun, To: "ops@example.com",
		RequestID: "mail-test-1"}, send)
	if err != nil || !result.OK || result.MessageID != "env-1" || string(seen.Secret) != secret || seen.To != "ops@example.com" {
		t.Fatalf("stored credential test=(%+v,%v) seen=%+v", result, err, seen)
	}
	sendgrid := aliyun
	sendgrid.MailProvider, sendgrid.MailAccessKeyID = "sendgrid", ""
	if _, err := service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: sendgrid, To: "ops@example.com",
		RequestID: "mail-test-2"}, send); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
		t.Fatalf("sendgrid test reused the aliyun credential: %v", err)
	}
	failing := func(context.Context, systemmailsettings.TestTarget) (string, error) {
		return "", &mail.Error{Disposition: mail.Permanent, Code: mail.CodeSenderRejected}
	}
	result, err = service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: sendgrid, MailSecret: "SG.page",
		To: "ops@example.com", RequestID: "mail-test-3"}, failing)
	if err != nil || result.OK || result.Code != mail.CodeSenderRejected {
		t.Fatalf("failing test=(%+v,%v)", result, err)
	}
	var payloads string
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(result || ':' || payload::text, ' ') FROM audit_events
		WHERE action='system_mail_settings.test'`).Scan(&payloads); err != nil ||
		!strings.Contains(payloads, "success:") || !strings.Contains(payloads, "failure:") ||
		strings.Contains(payloads, secret) || strings.Contains(payloads, "SG.page") {
		t.Fatalf("test audit %q err %v", payloads, err)
	}
	if current := mustGetMail(t, service, actor); current.Revision != 1 || current.Value.MailProvider != "aliyun" {
		t.Fatalf("test changed the saved settings: %+v", current)
	}
}
