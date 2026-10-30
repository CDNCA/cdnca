package accountregistrationchallenge

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistration"
	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationproof"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

var (
	_                HumanVerifier                    = (*TurnstileVerifier)(nil)
	_                ContactSender                    = (*NotificationContactSender)(nil)
	_                notification.AnonymousDispatcher = (*Dispatcher)(nil)
	_                ProofIssuer                      = (*accountregistrationproof.Authority)(nil)
	challengeTestKey                                  = bytes.Repeat([]byte{0x31}, 32)
	challengeTestNow                                  = time.Date(2026, 8, 8, 9, 0, 0, 0, time.UTC)
)

func TestNormalizeCreateInputBindsCanonicalRegistrationSubject(t *testing.T) {
	t.Parallel()

	input := CreateInput{
		ScopeID: uuid.New(), Username: " Owner_1 ", Email: " OWNER@EXAMPLE.COM ", Phone: "+8613812345678",
		Channel: accountregistration.VerificationEmail, Source: "2001:db8::1", HumanToken: strings.Repeat("a", 32),
		IdempotencyKey: "challenge-1", RequestID: "request-1",
	}
	normalized, err := normalizeCreateInput(input, challengeTestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Username != "owner_1" || normalized.Email != "owner@example.com" ||
		normalized.Phone != input.Phone || normalized.Destination != "owner@example.com" ||
		normalized.Source != "2001:db8::1" || normalized.SubjectDigest == ([32]byte{}) {
		t.Fatalf("normalized input = %+v", normalized)
	}

	changed := input
	changed.Username = "owner_2"
	second, err := normalizeCreateInput(changed, challengeTestKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if second.SubjectDigest == normalized.SubjectDigest {
		t.Fatal("username is not bound into registration subject digest")
	}
}

func TestNormalizeCreateInputRejectsUnsafeBindings(t *testing.T) {
	t.Parallel()

	valid := CreateInput{
		ScopeID: uuid.New(), Username: "owner_1", Email: "owner@example.com", Phone: "+8613812345678",
		Channel: accountregistration.VerificationEmail, Source: "192.0.2.9", HumanToken: strings.Repeat("a", 32),
		IdempotencyKey: "challenge-1", RequestID: "request-1",
	}
	for name, mutate := range map[string]func(*CreateInput){
		"scope":         func(input *CreateInput) { input.ScopeID = uuid.Nil },
		"username":      func(input *CreateInput) { input.Username = "bad space" },
		"email":         func(input *CreateInput) { input.Email = "bad" },
		"phone":         func(input *CreateInput) { input.Phone = "123" },
		"channel":       func(input *CreateInput) { input.Channel = "push" },
		"mapped source": func(input *CreateInput) { input.Source = "::ffff:192.0.2.9" },
		"human token":   func(input *CreateInput) { input.HumanToken = "short" },
		"idempotency":   func(input *CreateInput) { input.IdempotencyKey = "contains space" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input := valid
			mutate(&input)
			if _, err := normalizeCreateInput(input, challengeTestKey, ""); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestEnvelopeKeyringSealsRegistrationSecretsWithAAD(t *testing.T) {
	t.Parallel()

	keyring, err := NewEnvelopeKeyring("key-v1", map[string][]byte{"key-v1": bytes.Repeat([]byte{0x55}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keyring.Seal([]byte("destination-and-otp"), []byte("challenge-aad"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, []byte("destination-and-otp")) {
		t.Fatal("sealed claim contains plaintext")
	}
	opened, err := keyring.Open(sealed, []byte("challenge-aad"))
	if err != nil || string(opened) != "destination-and-otp" {
		t.Fatalf("open = %q, %v", opened, err)
	}
	if _, err := keyring.Open(sealed, []byte("other-aad")); err == nil {
		t.Fatal("AAD mismatch accepted")
	}
}

func TestChallengeSourceHasDurableSingleWinnerAndUnknownFences(t *testing.T) {
	t.Parallel()

	serviceSource, err := os.ReadFile("service.go")
	if err != nil {
		t.Fatal(err)
	}
	contactSource, err := os.ReadFile("contact.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(serviceSource) + string(contactSource)
	for _, required := range []string{
		"account_registration_challenge_writes_163", "human_verifying", "human_verified", "human_unknown",
		"account_registration_challenges_163", "account_registration_challenge_verify_receipts_163",
		"pgx.BeginTxFunc", "pgx.Serializable", "FOR UPDATE", "pg_advisory_xact_lock",
		"failed_attempts=failed_attempts+1",
		"subtle.ConstantTimeCompare", ".Issue(ctx", "account_registration_challenge_dispatch_claims_163",
		"EventTypeAccountRegistrationVerification", "AnonymousDispatchUnknown", "AnonymousDispatchReference",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("challenge source missing %q", required)
		}
	}
	for _, forbidden := range []string{"otp text", "destination text", "log.", "slog."} {
		if strings.Contains(text, forbidden) {
			t.Errorf("challenge source contains forbidden marker %q", forbidden)
		}
	}
}

func TestSelectContactTemplateUsesPublishedOverrideAndPreservesFallback(t *testing.T) {
	fallback := notification.TemplateRef{ID: "registration_email", Version: 1, Channel: notification.ChannelEmail}
	published := notification.TemplateRef{
		ID: "platform_user_registration_verification", Version: 8, Channel: notification.ChannelEmail,
	}
	templates := map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: fallback}
	if selected, ok := selectContactTemplate(templates, ContactRequest{Channel: notification.ChannelEmail}); !ok || selected != fallback {
		t.Fatalf("fallback selection=(%#v,%t)", selected, ok)
	}
	if selected, ok := selectContactTemplate(templates, ContactRequest{
		Channel: notification.ChannelEmail, Template: published,
	}); !ok || selected != published {
		t.Fatalf("published selection=(%#v,%t)", selected, ok)
	}
	if _, ok := selectContactTemplate(templates, ContactRequest{
		Channel:  notification.ChannelEmail,
		Template: notification.TemplateRef{ID: published.ID, Version: published.Version, Channel: notification.ChannelSMS},
	}); ok {
		t.Fatal("cross-channel template override was accepted")
	}
}

type rejectingHumanVerifier struct{}

func (rejectingHumanVerifier) Verify(context.Context, HumanVerification) error {
	return ErrHumanInvalid
}
