package systemusersettings

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// turnstileTestCipher reverses and masks the plaintext (enough to prove the
// stored bytes are not the secret).
type turnstileTestCipher struct{}

func (turnstileTestCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	out := make([]byte, len(plaintext))
	for index, value := range plaintext {
		out[len(plaintext)-1-index] = value ^ 0x3c
	}
	return "turnstile-test-key", out, nil
}

func (turnstileTestCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID != "turnstile-test-key" {
		return nil, errors.New("unknown key")
	}
	_, out, _ := turnstileTestCipher{}.Encrypt(ciphertext)
	return out, nil
}

func TestTurnstileSecretFieldErrors(t *testing.T) {
	text := func(value string) *string { return &value }
	for _, test := range []struct {
		name   string
		secret *string
		reason string
	}{
		{"not sent", nil, ""},
		{"clear", text(""), ""},
		{"valid", text("0x4AAAAAAAturnstile-secret"), ""},
		{"too short", text("short"), fielderr.TooShort},
		{"too long", text(strings.Repeat("a", 1025)), fielderr.TooLong},
		{"line break", text("0x4AAAAAAAturnstile\nsecret"), fielderr.InvalidFormat},
		{"inner space", text("0x4AAAAAAA turnstile-secret"), fielderr.InvalidFormat},
	} {
		secrets := map[string]*string{SecretCaptchaTurnstileSecret: test.secret}
		err := secretsFieldError(DefaultSettings(), secrets, nil)
		located, ok := fielderr.As(err)
		switch {
		case test.reason == "" && err != nil:
			t.Fatalf("%s: unexpected %v", test.name, err)
		case test.reason != "" && (!ok || located.Field != "captcha_turnstile_secret" || located.Reason != test.reason):
			t.Fatalf("%s: got %v want %s", test.name, err, test.reason)
		}
	}
	for _, key := range []string{"", "0x4AAAAAAAABcdEf_-"} {
		if err := turnstileSiteKeyFieldError(key); err != nil {
			t.Fatalf("site key %q refused: %v", key, err)
		}
	}
	if located, ok := fielderr.As(turnstileSiteKeyFieldError("<script>")); !ok || located.Field != "value.captcha_turnstile_site_key" {
		t.Fatalf("unsafe site key accepted: %v", located)
	}
}

// The Turnstile secret shares the page secrets envelope, bound to its scope.
func TestTurnstileSecretSealOpen(t *testing.T) {
	keyID, sealed, err := sealSecrets(turnstileTestCipher{}, "scope-a", map[string]string{SecretCaptchaTurnstileSecret: "0x4AAAAAAAturnstile-secret"})
	if err != nil || strings.Contains(string(sealed), "turnstile-secret") {
		t.Fatalf("sealed=%q err=%v", sealed, err)
	}
	opened, err := openSecrets(turnstileTestCipher{}, "scope-a", keyID, sealed)
	if err != nil || opened[SecretCaptchaTurnstileSecret] != "0x4AAAAAAAturnstile-secret" {
		t.Fatalf("opened=%q err=%v", opened, err)
	}
	if _, err := openSecrets(turnstileTestCipher{}, "scope-b", keyID, sealed); err == nil {
		t.Fatal("envelope opened under another scope")
	}
}

// Save stores the secret write-only: the document only says it is set, a
// later save without the field keeps it, "" clears it, and the runtime reads
// it back for the Turnstile check.
func TestPostgresTurnstileSecretWriteOnly(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	secret := "0x4AAAAAAAturnstile-secret"
	settings := DefaultSettings()
	settings.CaptchaTurnstileSiteKey = "0x4AAAAAAAsite"
	if _, err := service.Save(t.Context(), actor, SaveRequest{Value: settings, Secrets: map[string]*string{SecretCaptchaTurnstileSecret: &secret},
		IdempotencyKey: "turnstile-no-cipher", RequestID: "turnstile-no-cipher"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("save without a keyring = %v", err)
	}
	service.WithSecretCipher(turnstileTestCipher{})
	saved, err := service.Save(t.Context(), actor, SaveRequest{Value: settings, Secrets: map[string]*string{SecretCaptchaTurnstileSecret: &secret},
		IdempotencyKey: "turnstile-set", RequestID: "turnstile-set"})
	if err != nil || !saved.CaptchaTurnstileSecretConfigured || saved.CaptchaTurnstileSecretFingerprint == "" {
		t.Fatalf("saved=(%#v,%v)", saved, err)
	}
	if configured, err := TurnstileSecretConfigured(t.Context(), pool); err != nil || !configured {
		t.Fatalf("configured=(%v,%v)", configured, err)
	}
	opened, err := OpenTurnstileSecret(t.Context(), pool, turnstileTestCipher{})
	if err != nil || string(opened) != secret {
		t.Fatalf("opened=(%q,%v)", opened, err)
	}
	read, err := service.Get(t.Context(), actor)
	if err != nil || !read.CaptchaTurnstileSecretConfigured || read.Value.CaptchaTurnstileSiteKey != "0x4AAAAAAAsite" {
		t.Fatalf("read=(%#v,%v)", read, err)
	}
	public, err := service.GetPublic(t.Context(), scopeID)
	if err != nil || public.CaptchaTurnstileSiteKey != "0x4AAAAAAAsite" {
		t.Fatalf("public=(%#v,%v)", public, err)
	}
	kept, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: saved.Revision, Value: settings,
		IdempotencyKey: "turnstile-keep", RequestID: "turnstile-keep"})
	if err != nil || !kept.CaptchaTurnstileSecretConfigured || kept.CaptchaTurnstileSecretFingerprint != saved.CaptchaTurnstileSecretFingerprint {
		t.Fatalf("kept=(%#v,%v)", kept, err)
	}
	empty := ""
	cleared, err := service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: kept.Revision, Value: settings,
		Secrets: map[string]*string{SecretCaptchaTurnstileSecret: &empty}, IdempotencyKey: "turnstile-clear", RequestID: "turnstile-clear"})
	if err != nil || cleared.CaptchaTurnstileSecretConfigured {
		t.Fatalf("cleared=(%#v,%v)", cleared, err)
	}
	if _, err := OpenTurnstileSecret(t.Context(), pool, turnstileTestCipher{}); !errors.Is(err, ErrTurnstileSecretUnset) {
		t.Fatalf("open after clear = %v", err)
	}
}
