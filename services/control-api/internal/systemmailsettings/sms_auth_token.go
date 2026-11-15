package systemmailsettings

import (
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The HTTPS SMS gateway token (provider https_json) typed on the settings page
// is stored like the SMTP password: one envelope under the control-api
// credential keyring, bound to the platform scope, never returned. It replaces
// NOTIFICATION_SMS_AUTH_TOKEN at runtime. sms_access_key_reference stays for
// operators whose secret manager holds the token; a row has at most one of the
// two. The native providers keep their own credential (sms_access_key_secret).
const smsAuthTokenDomain = "cdnca-system-mail-sms-auth-token/v1\x00"

// smsAuthTokenFieldError checks the write-only token (nil: not sent) and that
// it does not meet a reference. stored reports a token already kept.
func smsAuthTokenFieldError(value Settings, token *string, stored bool) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, name, reason) }
	switch {
	case token == nil:
		if stored && value.SMSAccessKeyReference != "" {
			// clear the saved token before switching to a reference
			return field("value.sms_access_key_reference", fielderr.Invalid)
		}
		return nil
	case *token != "" && NativeSMSProvider(value.SMSProvider):
		return field("sms_auth_token", fielderr.Invalid)
	case len(*token) > 4096:
		return field("sms_auth_token", fielderr.TooLong)
	case strings.ContainsAny(*token, "\r\n\x00"):
		return field("sms_auth_token", fielderr.InvalidFormat)
	case *token != "" && value.SMSAccessKeyReference != "":
		return field("sms_auth_token", fielderr.Invalid)
	}
	return nil
}

func smsAuthTokenFingerprint(token string) string {
	return smsSecretFingerprint(smsAuthTokenDomain + token)
}

func sealSMSAuthToken(cipher SecretCipher, scope, token string) (string, []byte, error) {
	plaintext := []byte(smsAuthTokenDomain + scope + "\x00" + token)
	defer clear(plaintext)
	keyID, ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	return keyID, ciphertext, nil
}

func openSMSAuthToken(cipher SecretCipher, scope, keyID string, ciphertext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrUnavailable
	}
	plaintext, err := cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plaintext)
	prefix := smsAuthTokenDomain + scope + "\x00"
	if !strings.HasPrefix(string(plaintext), prefix) || len(plaintext) == len(prefix) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), plaintext[len(prefix):]...), nil
}

// HasSMSAuthToken reports whether the settings page stored an HTTPS SMS
// gateway token.
func (settings RuntimeSettings) HasSMSAuthToken() bool { return settings.smsTokenKeyID != nil }

// OpenSMSAuthToken decrypts the stored HTTPS SMS gateway token. The caller
// must clear the returned bytes.
func (settings RuntimeSettings) OpenSMSAuthToken(cipher SecretCipher) ([]byte, error) {
	if settings.smsTokenKeyID == nil {
		return nil, ErrUnavailable
	}
	return openSMSAuthToken(cipher, settings.scopeID.String(), *settings.smsTokenKeyID, settings.smsTokenCiphertext)
}

func (document *Document) setSMSAuthToken(fingerprint *string) {
	if fingerprint != nil {
		document.SMSAuthTokenConfigured, document.SMSAuthTokenFingerprint = true, *fingerprint
	}
}
