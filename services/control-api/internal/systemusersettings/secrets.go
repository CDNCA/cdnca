package systemusersettings

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

// The CAPTCHA secrets, the Turnstile secret and the KYC provider credentials
// typed on the settings page are stored like the SMTP password: one AES-GCM envelope under the
// control-api credential keyring holds all saved secrets as a JSON object,
// bound to the platform scope; reads return only whether each is set and a
// fingerprint. The CAPTCHA secrets keep their *_reference field for operators
// whose secret manager holds the value (at most one of the two); the KYC
// provider credentials and object store keys fall back to
// IDENTITY_VERIFICATION_KYC_* / IDENTITY_VERIFICATION_OBJECT_* instead.
const secretsDomain = "cdnca-system-user-settings-secrets/v1\x00"

const (
	SecretCaptchaSecretID  = "captcha_secret_id"
	SecretCaptchaSecretKey = "captcha_secret_key"
	SecretCaptchaAppSecret = "captcha_app_secret"
	// SecretCaptchaTurnstileSecret is the Cloudflare Turnstile secret of the
	// registration flow; ACCOUNT_REGISTRATION_TURNSTILE_SECRET, when set,
	// wins over it.
	SecretCaptchaTurnstileSecret = "captcha_turnstile_secret"
	// SecretKYCAPIKey / SecretKYCCallbackHMACKey replace
	// IDENTITY_VERIFICATION_KYC_API_KEY / _CALLBACK_HMAC_BASE64 (the latter in
	// the same canonical padded base64 of 32-128 bytes).
	SecretKYCAPIKey          = "kyc_api_key"
	SecretKYCCallbackHMACKey = "kyc_callback_hmac_key"
	// The KYC private object store keys replace
	// IDENTITY_VERIFICATION_OBJECT_ACCESS_KEY_ID / _SECRET_ACCESS_KEY /
	// _SESSION_TOKEN (migration 671).
	SecretKYCObjectAccessKeyID     = "kyc_object_access_key_id"
	SecretKYCObjectSecretAccessKey = "kyc_object_secret_access_key"
	SecretKYCObjectSessionToken    = "kyc_object_session_token"
)

var secretNames = []string{SecretCaptchaSecretID, SecretCaptchaSecretKey, SecretCaptchaAppSecret,
	SecretCaptchaTurnstileSecret, SecretKYCAPIKey, SecretKYCCallbackHMACKey,
	SecretKYCObjectAccessKeyID, SecretKYCObjectSecretAccessKey, SecretKYCObjectSessionToken}

// secretMaxLength is the longest value a page secret may have.
func secretMaxLength(name string) int {
	if name == SecretKYCObjectSessionToken {
		return 4096
	}
	return 1024
}

// secretReference is the reference field paired with a page secret.
func secretReference(value Settings, name string) string {
	switch name {
	case SecretCaptchaSecretID:
		return value.CaptchaSecretIDReference
	case SecretCaptchaSecretKey:
		return value.CaptchaSecretKeyReference
	case SecretCaptchaAppSecret:
		return value.CaptchaAppSecretReference
	}
	return ""
}

// secretReason refuses a Turnstile secret or KYC credential its consumer
// would not accept.
func secretReason(name, secret string) string {
	switch name {
	case SecretCaptchaTurnstileSecret:
		// accountregistrationchallenge.NewTurnstileVerifier refuses shorter secrets
		if len(secret) < 16 {
			return fielderr.TooShort
		}
		if strings.ContainsAny(secret, " \t") {
			return fielderr.InvalidFormat
		}
	case SecretKYCAPIKey:
		if len(secret) < 16 {
			return fielderr.TooShort
		}
		if len(secret) > 512 {
			return fielderr.TooLong
		}
	case SecretKYCCallbackHMACKey:
		decoded, err := base64.StdEncoding.Strict().DecodeString(secret)
		defer clear(decoded)
		if err != nil || len(decoded) < 32 || len(decoded) > 128 || base64.StdEncoding.EncodeToString(decoded) != secret {
			return fielderr.InvalidFormat
		}
	case SecretKYCObjectAccessKeyID:
		return lengthReason(secret, 3, 256)
	case SecretKYCObjectSecretAccessKey:
		return lengthReason(secret, 8, 512)
	}
	return ""
}

func lengthReason(value string, min, max int) string {
	switch {
	case len(value) < min:
		return fielderr.TooShort
	case len(value) > max:
		return fielderr.TooLong
	}
	return ""
}

// secretsFieldError checks the write-only secrets of a save (nil: not sent)
// and that none meets its reference. stored lists the secrets already kept.
func secretsFieldError(value Settings, secrets map[string]*string, stored []string) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, name, reason) }
	for name := range secrets {
		if !slices.Contains(secretNames, name) {
			return field(name, fielderr.Invalid)
		}
	}
	for _, name := range secretNames {
		secret, reference := secrets[name], secretReference(value, name)
		switch {
		case secret == nil:
			if reference != "" && slices.Contains(stored, name) {
				// clear the saved secret before switching to a reference
				return field("value."+name+"_reference", fielderr.Invalid)
			}
		case len(*secret) > secretMaxLength(name):
			return field(name, fielderr.TooLong)
		case strings.ContainsAny(*secret, "\r\n\x00") || strings.TrimSpace(*secret) != *secret:
			return field(name, fielderr.InvalidFormat)
		case *secret != "" && reference != "":
			return field(name, fielderr.Invalid)
		case *secret != "" && secretReason(name, *secret) != "":
			return field(name, secretReason(name, *secret))
		}
	}
	return nil
}

// nextSecrets applies a save to the stored secrets and reports, per name,
// replaced / cleared / unchanged for the audit event.
func nextSecrets(current map[string]string, request map[string]*string) (map[string]string, map[string]string) {
	next := make(map[string]string, len(current))
	for name, secret := range current {
		next[name] = secret
	}
	changes := make(map[string]string, len(secretNames))
	for _, name := range secretNames {
		changes[name] = "unchanged"
		secret := request[name]
		_, kept := next[name]
		switch {
		case secret == nil:
		case *secret != "":
			next[name], changes[name] = *secret, "replaced"
		case kept:
			delete(next, name)
			changes[name] = "cleared"
		}
	}
	return next, changes
}

// secretsChange reports whether a save touches the stored secrets at all.
func secretsChange(request map[string]*string, stored []string) bool {
	for name, secret := range request {
		if secret != nil && (*secret != "" || slices.Contains(stored, name)) {
			return true
		}
	}
	return false
}

func secretFingerprint(name, secret string) string {
	sum := sha256.Sum256([]byte(secretsDomain + name + "\x00" + secret))
	return hex.EncodeToString(sum[:8])
}

func secretFingerprints(secrets map[string]string) map[string]string {
	result := make(map[string]string, len(secrets))
	for name, secret := range secrets {
		result[name] = secretFingerprint(name, secret)
	}
	return result
}

// decodeFingerprints reads the stored fingerprint object (NULL: none) and
// returns it with the sorted list of stored secret names.
func decodeFingerprints(raw []byte) (map[string]string, []string, error) {
	if raw == nil {
		return nil, nil, nil
	}
	var result map[string]string
	if json.Unmarshal(raw, &result) != nil {
		return nil, nil, ErrUnavailable
	}
	names := make([]string, 0, len(result))
	for name := range result {
		if !slices.Contains(secretNames, name) {
			return nil, nil, ErrUnavailable
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return result, names, nil
}

func sealSecrets(cipher SecretCipher, scope string, secrets map[string]string) (string, []byte, error) {
	if cipher == nil {
		return "", nil, ErrInvalidInput
	}
	encoded, err := json.Marshal(secrets)
	if err != nil {
		return "", nil, ErrInvalidInput
	}
	plaintext := append([]byte(secretsDomain+scope+"\x00"), encoded...)
	clear(encoded)
	defer clear(plaintext)
	keyID, ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	return keyID, ciphertext, nil
}

func openSecrets(cipher SecretCipher, scope, keyID string, ciphertext []byte) (map[string]string, error) {
	if cipher == nil {
		return nil, ErrUnavailable
	}
	plaintext, err := cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plaintext)
	prefix := secretsDomain + scope + "\x00"
	if !strings.HasPrefix(string(plaintext), prefix) {
		return nil, ErrUnavailable
	}
	var secrets map[string]string
	if json.Unmarshal(plaintext[len(prefix):], &secrets) != nil {
		return nil, ErrUnavailable
	}
	for name := range secrets {
		if !slices.Contains(secretNames, name) {
			return nil, ErrUnavailable
		}
	}
	return secrets, nil
}

func (document *Document) setSecrets(fingerprints map[string]string) {
	print := func(name string) (bool, string) {
		value, ok := fingerprints[name]
		return ok, value
	}
	document.CaptchaSecretIDConfigured, document.CaptchaSecretIDFingerprint = print(SecretCaptchaSecretID)
	document.CaptchaSecretKeyConfigured, document.CaptchaSecretKeyFingerprint = print(SecretCaptchaSecretKey)
	document.CaptchaAppSecretConfigured, document.CaptchaAppSecretFingerprint = print(SecretCaptchaAppSecret)
	document.CaptchaTurnstileSecretConfigured, document.CaptchaTurnstileSecretFingerprint = print(SecretCaptchaTurnstileSecret)
	document.KYCAPIKeyConfigured, document.KYCAPIKeyFingerprint = print(SecretKYCAPIKey)
	document.KYCCallbackHMACKeyConfigured, document.KYCCallbackHMACKeyFingerprint = print(SecretKYCCallbackHMACKey)
	document.KYCObjectAccessKeyIDConfigured, document.KYCObjectAccessKeyIDFingerprint = print(SecretKYCObjectAccessKeyID)
	document.KYCObjectSecretAccessKeyConfigured, document.KYCObjectSecretAccessKeyFingerprint = print(SecretKYCObjectSecretAccessKey)
	document.KYCObjectSessionTokenConfigured, document.KYCObjectSessionTokenFingerprint = print(SecretKYCObjectSessionToken)
}
