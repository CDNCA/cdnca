package systemmailsettings

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

type reverseCipher struct{}

func (reverseCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	out := make([]byte, len(plaintext))
	for index, value := range plaintext {
		out[len(plaintext)-1-index] = value ^ 0x5a
	}
	return "test-key", out, nil
}

func (reverseCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID != "test-key" {
		return nil, errors.New("unknown key")
	}
	_, out, _ := reverseCipher{}.Encrypt(ciphertext)
	return out, nil
}

func TestSMTPPasswordFieldError(t *testing.T) {
	text := func(value string) *string { return &value }
	withReference := DefaultSettings()
	withReference.SMTPPasswordReference = "vault://smtp/password"
	for name, tc := range map[string]struct {
		value    Settings
		password *string
		stored   bool
		field    string
	}{
		"omitted":                  {value: DefaultSettings()},
		"omitted keeps stored":     {value: DefaultSettings(), stored: true},
		"plaintext":                {value: DefaultSettings(), password: text("p@ss word")},
		"clear":                    {value: withReference, password: text(""), stored: true},
		"reference alone":          {value: withReference},
		"plaintext with reference": {value: withReference, password: text("p"), field: "smtp_password"},
		"reference next to stored": {value: withReference, stored: true, field: "value.smtp_password_reference"},
		"line break":               {value: DefaultSettings(), password: text("a\nb"), field: "smtp_password"},
		"too long":                 {value: DefaultSettings(), password: text(strings.Repeat("x", 1025)), field: "smtp_password"},
	} {
		err := smtpPasswordFieldError(tc.value, tc.password, tc.stored)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field):
			t.Errorf("%s: %v, want field %s", name, err, tc.field)
		}
	}
}

// The password is sealed to the scope, opened back through RuntimeSettings,
// and never reaches the request digest in plaintext.
func TestSMTPPasswordSealOpenAndDigest(t *testing.T) {
	scope := uuid.New()
	const password = "plain-smtp-password"
	keyID, sealed, err := sealSMTPPassword(reverseCipher{}, scope.String(), password)
	if err != nil || bytes.Contains(sealed, []byte(password)) {
		t.Fatalf("seal=(%q,%v)", sealed, err)
	}
	settings := RuntimeSettings{Configured: true, scopeID: scope, smtpKeyID: &keyID, smtpCiphertext: sealed}
	if !settings.HasSMTPPassword() {
		t.Fatal("stored password not reported")
	}
	opened, err := settings.OpenSMTPPassword(reverseCipher{})
	if err != nil || string(opened) != password {
		t.Fatalf("open=(%q,%v)", opened, err)
	}
	if _, err := openSMTPPassword(reverseCipher{}, uuid.NewString(), keyID, sealed); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opened under another scope: %v", err)
	}
	if _, err := (RuntimeSettings{}).OpenSMTPPassword(reverseCipher{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opened without a stored password: %v", err)
	}
	if len(smtpPasswordFingerprint(password)) != 16 || smtpPasswordFingerprint(password) == mailSecretFingerprint(password) {
		t.Fatal("fingerprint is not domain separated")
	}

	request := SaveRequest{Value: DefaultSettings(), IdempotencyKey: "k", RequestID: "r"}
	omitted, _ := requestDigest(request)
	empty := ""
	request.SMTPPassword = &empty
	cleared, _ := requestDigest(request)
	value := password
	request.SMTPPassword = &value
	replaced, _ := requestDigest(request)
	if omitted == cleared || cleared == replaced || omitted == replaced {
		t.Fatal("omitted, cleared and replaced share a request digest")
	}
}
