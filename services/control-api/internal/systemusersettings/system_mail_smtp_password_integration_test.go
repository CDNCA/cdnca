package systemusersettings

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// The SMTP password typed on the settings page is
// encrypted like the official mail credential and never returned; omitted
// keeps it, "" clears it, a reference still works but never next to a
// stored password, and the test mail gets the decrypted password.
func TestPostgresSystemMailSMTPPassword(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	save := func(revision int64, value systemmailsettings.Settings, password *string, key string) (systemmailsettings.Document, error) {
		return service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: revision, Value: value,
			SMTPPassword: password, RequestID: key, IdempotencyKey: key})
	}
	text := func(value string) *string { return &value }
	refused := func(err error, field string) bool {
		located, ok := fielderr.As(err)
		return errors.Is(err, systemmailsettings.ErrInvalidInput) && ok && located.Field == field
	}
	smtp := systemmailsettings.DefaultSettings()
	smtp.SMTPAddress, smtp.SMTPUser = "smtp.example.com", "mailer"

	// 1. Plaintext password: saved encrypted, only a fingerprint comes back.
	const password = "plain SMTP p@ss"
	saved, err := save(0, smtp, text(password), "smtp-password-1")
	if err != nil || saved.Revision != 1 || !saved.SMTPPasswordConfigured || len(saved.SMTPPasswordFingerprint) != 16 {
		t.Fatalf("plaintext save=(%+v,%v)", saved, err)
	}
	var stored []byte
	var settingsJSON, receipts string
	if err := pool.QueryRow(t.Context(), `SELECT smtp_password_ciphertext,settings::text FROM platform_system_mail_settings
		WHERE platform_scope_id=$1`, scopeID).Scan(&stored, &settingsJSON); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(request_digest::text || coalesce(response_body::text,''),'')
		FROM platform_system_mail_settings_write_requests WHERE target_scope_id=$1`, scopeID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	got := mustGetMail(t, service, actor)
	encoded, _ := json.Marshal(got)
	if len(stored) == 0 || bytes.Contains(stored, []byte(password)) || strings.Contains(settingsJSON, password) ||
		strings.Contains(receipts, password) || strings.Contains(string(encoded), password) {
		t.Fatal("SMTP password stored or returned in plaintext")
	}
	if !got.SMTPPasswordConfigured || got.SMTPPasswordFingerprint != saved.SMTPPasswordFingerprint {
		t.Fatalf("get after save: %+v", got)
	}
	// The audit log redacts the smtp_password key itself (as it does mail_secret), so only the redaction shows.
	var payload string
	if err := pool.QueryRow(t.Context(), `SELECT payload::text FROM audit_events WHERE request_id='smtp-password-1'`).Scan(&payload); err != nil ||
		!strings.Contains(payload, `"smtp_password": "[REDACTED]"`) || strings.Contains(payload, password) {
		t.Fatalf("audit payload %q err %v", payload, err)
	}
	runtimeSettings, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil || !runtimeSettings.HasSMTPPassword() {
		t.Fatalf("runtime=(%+v,%v)", runtimeSettings, err)
	}
	if opened, err := runtimeSettings.OpenSMTPPassword(xorCipher{}); err != nil || string(opened) != password {
		t.Fatalf("open SMTP password=%q err=%v", opened, err)
	}

	// 2. The test mail gets the decrypted stored password.
	var seen []byte
	send := func(_ context.Context, target systemmailsettings.TestTarget) (string, error) {
		seen = append([]byte(nil), target.SMTPPassword...)
		return "smtp-1", nil
	}
	if result, err := service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: smtp, To: "ops@example.com",
		RequestID: "smtp-password-test-1"}, send); err != nil || !result.OK || string(seen) != password {
		t.Fatalf("test send=(%+v,%v) password %q", result, err, seen)
	}

	// 3. Omitted keeps it, even when other SMTP fields change.
	changed := smtp
	changed.SMTPPort = 587
	kept, err := save(1, changed, nil, "smtp-password-2")
	if err != nil || !kept.SMTPPasswordConfigured || kept.SMTPPasswordFingerprint != saved.SMTPPasswordFingerprint {
		t.Fatalf("omitted password=(%+v,%v)", kept, err)
	}

	// 4. A reference next to a password is refused either way.
	referenced := changed
	referenced.SMTPPasswordReference = "vault://smtp/password"
	if _, err := save(2, referenced, text("other"), "smtp-password-3"); !refused(err, "smtp_password") {
		t.Fatalf("password with reference: %v", err)
	}
	if _, err := save(2, referenced, nil, "smtp-password-4"); !refused(err, "value.smtp_password_reference") {
		t.Fatalf("reference while a password is stored: %v", err)
	}

	// 5. "" clears it; then the reference alone is accepted as before.
	cleared, err := save(2, changed, text(""), "smtp-password-5")
	if err != nil || cleared.SMTPPasswordConfigured || cleared.SMTPPasswordFingerprint != "" {
		t.Fatalf("clear=(%+v,%v)", cleared, err)
	}
	var keyID *string
	if err := pool.QueryRow(t.Context(), `SELECT smtp_password_key_id FROM platform_system_mail_settings WHERE platform_scope_id=$1`,
		scopeID).Scan(&keyID); err != nil || keyID != nil {
		t.Fatalf("cleared row key=%v err=%v", keyID, err)
	}
	withReference, err := save(3, referenced, nil, "smtp-password-6")
	if err != nil || withReference.Value.SMTPPasswordReference != "vault://smtp/password" || withReference.SMTPPasswordConfigured {
		t.Fatalf("reference save=(%+v,%v)", withReference, err)
	}
	seen = []byte("unset")
	if result, err := service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: referenced, To: "ops@example.com",
		RequestID: "smtp-password-test-2"}, send); err != nil || !result.OK || seen != nil {
		t.Fatalf("test without stored password=(%+v,%v) password %q", result, err, seen)
	}

	// An incomplete page comes back as config_incomplete naming the fields.
	incomplete := func(context.Context, systemmailsettings.TestTarget) (string, error) {
		return "", &systemmailsettings.MissingError{Fields: []string{"smtp_password", "value.smtp_from"}}
	}
	if result, err := service.Test(t.Context(), actor, systemmailsettings.TestRequest{Value: referenced, To: "ops@example.com",
		RequestID: "smtp-password-test-3"}, incomplete); err != nil || result.OK || result.Code != systemmailsettings.CodeConfigIncomplete ||
		strings.Join(result.Missing, ",") != "smtp_password,value.smtp_from" {
		t.Fatalf("incomplete test=(%+v,%v)", result, err)
	}

	// smtp_from must be an address; smtp_from_name a plain display name.
	badFrom := smtp
	badFrom.SMTPFrom = "not an address"
	if _, err := save(4, badFrom, nil, "smtp-password-8"); !refused(err, "value.smtp_from") {
		t.Fatalf("bad sender address: %v", err)
	}
	withFrom := smtp
	withFrom.SMTPFrom, withFrom.SMTPFromName = "noreply@example.com", "CDNCA 运维"
	if saved, err := save(4, withFrom, nil, "smtp-password-9"); err != nil || saved.Value.SMTPFrom != "noreply@example.com" ||
		saved.Value.SMTPFromName != "CDNCA 运维" {
		t.Fatalf("sender save=(%+v,%v)", saved, err)
	}

	// A plaintext reference is still refused with the reference field.
	plainReference := smtp
	plainReference.SMTPPasswordReference = "secret"
	if _, err := save(5, plainReference, nil, "smtp-password-7"); !refused(err, "value.smtp_password_reference") {
		t.Fatalf("plaintext reference: %v", err)
	}
}
