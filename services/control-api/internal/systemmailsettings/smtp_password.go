package systemmailsettings

import (
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The SMTP password typed on the settings page is stored like MailSecret:
// one envelope under the control-api credential keyring, bound to the
// platform scope, never returned (only whether it is set and a fingerprint).
// smtp_password_reference stays for operators whose secret manager holds the
// password; a row has at most one of the two.
const smtpPasswordDomain = "cdnca-system-mail-smtp-password/v1\x00"

// smtpPasswordFieldError checks the write-only password (nil: not sent) and
// that it does not meet a reference. stored reports a password already kept.
func smtpPasswordFieldError(value Settings, password *string, stored bool) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, name, reason) }
	switch {
	case password == nil:
		if stored && value.SMTPPasswordReference != "" {
			// clear the saved password before switching to a reference
			return field("value.smtp_password_reference", fielderr.Invalid)
		}
		return nil
	case len(*password) > 1024:
		return field("smtp_password", fielderr.TooLong)
	case strings.ContainsAny(*password, "\r\n\x00"):
		return field("smtp_password", fielderr.InvalidFormat)
	case *password != "" && value.SMTPPasswordReference != "":
		return field("smtp_password", fielderr.Invalid)
	}
	return nil
}

func smtpPasswordFingerprint(password string) string {
	return smsSecretFingerprint(smtpPasswordDomain + password)
}

func sealSMTPPassword(cipher SecretCipher, scope, password string) (string, []byte, error) {
	plaintext := []byte(smtpPasswordDomain + scope + "\x00" + password)
	defer clear(plaintext)
	keyID, ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	return keyID, ciphertext, nil
}

func openSMTPPassword(cipher SecretCipher, scope, keyID string, ciphertext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrUnavailable
	}
	plaintext, err := cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plaintext)
	prefix := smtpPasswordDomain + scope + "\x00"
	if !strings.HasPrefix(string(plaintext), prefix) || len(plaintext) == len(prefix) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), plaintext[len(prefix):]...), nil
}
