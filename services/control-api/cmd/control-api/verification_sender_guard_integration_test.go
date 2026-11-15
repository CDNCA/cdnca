//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/jackc/pgx/v5"
)

// A mail settings save that would leave email verification in
// effect (required + email channel on) without a sender is refused; with the
// channel off, or verification not required, it saves.
func TestMailSettingsSaveKeepsSenderOfVerificationInEffect(t *testing.T) {
	pool, _ := registrationReadyTestPool(t)
	saveRegistrationSettings(t, pool, func(value *systemusersettings.Settings) {
		value.EmailRequired, value.EmailVerificationRequired = true, true
	})
	cfg := config.Config{DNSCredentialKeyID: "hi10", DNSCredentialKey: bytes.Repeat([]byte{7}, 32)}
	auto := newNotificationAutoRuntime(notificationRuntimeConfig{Requested: true, Auto: true, EmailProvider: notificationEmailProviderSettings},
		notificationRuntimeConfig{Requested: true, Auto: true, Enabled: true, EmailProvider: notificationEmailProviderSMTPTLS},
		cfg, pool, notificationRuntimeDependencies{})
	guard := auto.VerificationSenderGuard()
	// the save clears the sender: the page keeps no SMTP address
	encoded, err := json.Marshal(systemmailsettings.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	attempt := func() error {
		t.Helper()
		var guardErr error
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(t.Context(), `INSERT INTO platform_system_mail_settings(platform_scope_id,revision,settings,updated_at)
				SELECT id,1,$1,now() FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`, string(encoded)); err != nil {
				return err
			}
			guardErr = guard(t.Context(), tx)
			return errors.New("roll back")
		})
		if err == nil || err.Error() != "roll back" {
			t.Fatal(err)
		}
		return guardErr
	}
	if err := attempt(); err != nil {
		t.Fatalf("email channel off: %v", err)
	}
	setEmailSwitch(t, pool, true)
	if err := attempt(); !errors.Is(err, systemmailsettings.ErrEmailVerificationSender) {
		t.Fatalf("verification in effect, sender cleared = %v", err)
	}
	saveRegistrationSettings(t, pool, func(*systemusersettings.Settings) {})
	if err := attempt(); err != nil {
		t.Fatalf("verification not required: %v", err)
	}
}
