package accountregistrationchallenge

import (
	"bytes"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
)

// with the username optional and left empty, the code is
// sent and verified for the username registration generates from the same
// contacts, so the built-in registration (email and SMS codes, no username)
// consumes both proofs and stores that username; required, the empty
// username is refused when the code is requested.
func TestBuiltInRegistrationGeneratedUsernamePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	scope := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_channel_settings SET email_enabled=true,sms_enabled=true WHERE singleton`); err != nil {
		t.Fatal(err)
	}
	digestKey := bytes.Repeat([]byte{0x41}, 32)
	keys := func(id string, value byte) *EnvelopeKeyring {
		keyring, err := NewEnvelopeKeyring(id, map[string][]byte{id: bytes.Repeat([]byte{value}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		return keyring
	}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelEmail},
		notification.ChannelSMS:   {ID: "account_registration_verification", Version: 1, Channel: notification.ChannelSMS},
	}
	sender, err := NewNotificationContactSender(store, keys("dispatch-v1", 0x42), templates)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{DigestKey: digestKey})
	if err != nil {
		t.Fatal(err)
	}
	settings := systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true, EmailVerificationRequired: true,
		PhoneRequired: true, PhoneVerificationRequired: true, TermsVersion: "terms-2026-08"}
	policy := &fixedPolicy{settings}
	challenges, err := NewService(pool, &acceptHuman{}, sender, authority, keys("proof-v1", 0x43),
		Config{DigestKey: digestKey, PublicSettings: policy, Entropy: zeroEntropy{}})
	if err != nil {
		t.Fatal(err)
	}
	const email, phone, source = "generated@example.com", "+8613812345678", "203.0.113.9"
	prove := func(channel string) string {
		t.Helper()
		created, err := challenges.Create(ctx, CreateInput{ScopeID: scope, Email: email, Phone: phone,
			Channel: channel, Source: source, HumanToken: CaptchaTokenPrefix + uuid.NewString() + ":AB2CD",
			IdempotencyKey: "generated-create-" + channel, RequestID: "generated-create-" + channel})
		if err != nil {
			t.Fatalf("create %s: %v", channel, err)
		}
		verified, err := challenges.Verify(ctx, VerifyInput{ScopeID: scope, ChallengeID: created.ChallengeID,
			Email: email, Phone: phone, Channel: channel, Source: source, Binding: created.Binding, OTP: "000000",
			IdempotencyKey: "generated-verify-" + channel, RequestID: "generated-verify-" + channel})
		if err != nil {
			t.Fatalf("verify %s: %v", channel, err)
		}
		return verified.Reference
	}
	registrations, err := accountregistration.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	builtIn, err := accountregistration.NewBuiltInService(registrations, policy, unusedCaptcha{}, digestKey)
	if err != nil {
		t.Fatal(err)
	}
	builtIn.EnableContactVerification(authority)
	input := accountregistration.BuiltInInput{RegisterInput: accountregistration.RegisterInput{
		Password: "Correct-horse-battery-staple", Email: email, Phone: phone, TermsAccepted: true,
		TermsVersion: "terms-2026-08", IdempotencyKey: "generated-register", RequestID: "generated-register", Source: source,
		ProofReferences: map[string]string{accountregistration.VerificationEmail: prove(accountregistration.VerificationEmail),
			accountregistration.VerificationSMS: prove(accountregistration.VerificationSMS)},
	}}
	result, err := builtIn.Register(ctx, input)
	want := accountregistration.DerivedUsername(digestKey, email, phone)
	if err != nil || !result.Accepted || result.Username != want {
		t.Fatalf("result=%#v err=%v want %q", result, err, want)
	}
	var stored, display string
	if err := pool.QueryRow(ctx, `SELECT username,display_name FROM users WHERE email=$1`, email).Scan(&stored, &display); err != nil ||
		stored != want || display != want {
		t.Fatalf("stored=%q display=%q err=%v", stored, display, err)
	}
	policy.settings.UsernameRequired = true
	if _, err := challenges.Create(ctx, CreateInput{ScopeID: scope, Email: "other@example.com", Phone: "+8613812345679",
		Channel: accountregistration.VerificationEmail, Source: source, HumanToken: CaptchaTokenPrefix + uuid.NewString() + ":AB2CD",
		IdempotencyKey: "required-create", RequestID: "required-create"}); err == nil {
		t.Fatal("an empty username was accepted while required")
	}
}
