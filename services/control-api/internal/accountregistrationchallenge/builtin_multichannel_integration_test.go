package accountregistrationchallenge

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type outboxSpy struct {
	inner RegistrationDispatchEnqueuer
	err   error
}

func (spy *outboxSpy) EnqueueDispatchTx(ctx context.Context, tx pgx.Tx, request notification.DispatchEnqueueRequest) (notification.EnqueueResult, error) {
	result, err := spy.inner.EnqueueDispatchTx(ctx, tx, request)
	spy.err = err
	return result, err
}

type zeroEntropy struct{}

func (zeroEntropy) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

type fixedPolicy struct {
	settings systemusersettings.PublicSettings
}

func (policy fixedPolicy) GetPublic(context.Context, uuid.UUID) (systemusersettings.PublicSettings, error) {
	return policy.settings, nil
}

type acceptHuman struct{ calls int }

func (human *acceptHuman) Verify(context.Context, HumanVerification) error { human.calls++; return nil }

type unusedCaptcha struct{}

func (unusedCaptcha) ConsumeCaptcha(context.Context, identity.LoginCaptchaProof) error {
	return errors.New("the CAPTCHA must not be asked for at registration")
}

// with email and phone verification both on, built-in
// registration needs both proofs. One missing fails; the retry with the same
// idempotency key replays the consumed email proof and succeeds once the SMS
// code is verified too. Uses migration 660's default templates.
func TestBuiltInRegistrationBothChannelsPostgres(t *testing.T) {
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
	outbox := &outboxSpy{inner: store}
	sender, err := NewNotificationContactSender(outbox, keys("dispatch-v1", 0x42), templates)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := accountregistrationproof.NewAuthority(pool, accountregistrationproof.Config{DigestKey: digestKey})
	if err != nil {
		t.Fatal(err)
	}
	policy := fixedPolicy{systemusersettings.PublicSettings{RegistrationEnabled: true, EmailRequired: true,
		EmailVerificationRequired: true, PhoneRequired: true, PhoneVerificationRequired: true, TermsVersion: "terms-2026-08"}}
	human := &acceptHuman{}
	challenges, err := NewService(pool, human, sender, authority, keys("proof-v1", 0x43),
		Config{DigestKey: digestKey, PublicSettings: policy, Entropy: zeroEntropy{}})
	if err != nil {
		t.Fatal(err)
	}
	const username, email, phone, source = "both-channels", "both@example.com", "+8613812345678", "203.0.113.9"
	prove := func(channel string) string {
		t.Helper()
		created, err := challenges.Create(ctx, CreateInput{ScopeID: scope, Username: username, Email: email, Phone: phone,
			Channel: channel, Source: source, HumanToken: CaptchaTokenPrefix + uuid.NewString() + ":AB2CD",
			IdempotencyKey: "create-" + channel, RequestID: "request-create-" + channel})
		if err != nil {
			t.Fatalf("create %s: %v (outbox: %v)", channel, err, outbox.err)
		}
		verify := func(binding, key string) (VerifyResult, error) {
			// the code is checked through another CDN edge than it was sent through
			return challenges.Verify(ctx, VerifyInput{ScopeID: scope, ChallengeID: created.ChallengeID, Username: username,
				Email: email, Phone: phone, Channel: channel, Source: "162.159.2.20", Binding: binding, OTP: "000000",
				IdempotencyKey: key, RequestID: "request-verify-" + channel})
		}
		// without the browser binding cookie, or with another challenge's, the right code is refused
		for name, binding := range map[string]string{"no cookie": "", "other cookie": challenges.browserBinding(uuid.New())} {
			if _, err := verify(binding, "verify-"+channel+"-"+strings.ReplaceAll(name, " ", "-")); !errors.Is(err, ErrOTPInvalid) {
				t.Fatalf("verify %s with %s: %v", channel, name, err)
			}
		}
		verified, err := verify(created.Binding, "verify-"+channel)
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
		Username: username, Password: "Correct-horse-battery-staple", DisplayName: "Both", Email: email, Phone: phone,
		TermsAccepted: true, TermsVersion: "terms-2026-08", IdempotencyKey: "register-both", RequestID: "request-register",
		Source: "104.23.1.10", // the sign-up comes through yet another edge
	}}
	input.ProofReferences = map[string]string{accountregistration.VerificationEmail: prove(accountregistration.VerificationEmail)}
	if _, err := builtIn.Register(ctx, input); !errors.Is(err, accountregistration.ErrProofInvalid) {
		t.Fatalf("email proof alone: %v", err)
	}
	input.ProofReferences[accountregistration.VerificationSMS] = prove(accountregistration.VerificationSMS)
	result, err := builtIn.Register(ctx, input)
	if err != nil || !result.Accepted {
		t.Fatalf("both proofs: %#v %v", result, err)
	}
	var users, queued int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE username=$1`, username).Scan(&users); err != nil || users != 1 {
		t.Fatalf("users=%d err=%v", users, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_outbox WHERE template_id='account_registration_verification'`).Scan(&queued); err != nil || queued != 2 {
		t.Fatalf("queued codes=%d err=%v", queued, err)
	}
	if human.calls != 2 {
		t.Fatalf("human checks=%d", human.calls)
	}
}
