package systemmailsettings

import (
	"regexp"
	"strings"

	"github.com/cdnca/cdnca/libs/mail"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

const mailSecretDomain = "cdnca-system-mail-provider-secret/v1\x00"

var mailPluginIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)+$`)

// MailProviderKind is smtp, official or plugin ("" for an unknown value).
func MailProviderKind(provider string) string {
	switch {
	case provider == "" || provider == MailProviderSMTP:
		return MailKindSMTP
	case mail.Official(provider):
		return MailKindOfficial
	case strings.HasPrefix(provider, MailPluginPrefix):
		if _, ok := MailPluginID(provider); ok {
			return MailKindPlugin
		}
	}
	return ""
}

// MailPluginID returns the plugin of a "plugin:<id>" provider.
func MailPluginID(provider string) (string, bool) {
	id, ok := strings.CutPrefix(provider, MailPluginPrefix)
	return id, ok && len(id) <= 128 && mailPluginIDPattern.MatchString(id)
}

// validMailProvider checks the chosen provider has what it needs. A secret
// is accepted only for an official provider.
func validMailProvider(value Settings, secret string) bool {
	return mailProviderFieldError(value, secret) == nil
}

// mailProviderFieldError names the refused field (value.<field> or
// mail_secret, fix-fielderr-be2). The official fields are well formed whether
// or not an official provider is chosen (they stay saved while SMTP or a
// plugin sends).
func mailProviderFieldError(value Settings, secret string) error {
	field := func(name, reason string) error { return fielderr.New(ErrInvalidInput, name, reason) }
	regionKnown := value.MailRegion == ""
	for _, provider := range mail.Providers {
		for _, region := range mail.Regions(provider) {
			regionKnown = regionKnown || region == value.MailRegion
		}
	}
	official := MailProviderKind(value.MailProvider) == MailKindOfficial
	switch {
	case MailProviderKind(value.MailProvider) == "":
		return field("value.mail_provider", fielderr.Invalid)
	case !regionKnown:
		return field("value.mail_region", fielderr.Invalid)
	case value.MailFrom != "" && !mail.ValidAddress(value.MailFrom):
		return field("value.mail_from", fielderr.InvalidFormat)
	case !mail.ValidName(value.MailFromName):
		return field("value.mail_from_name", fielderr.InvalidFormat)
	case value.MailAccessKeyID != "" && !mail.ValidCredential(value.MailAccessKeyID, 256):
		return field("value.mail_access_key_id", fielderr.InvalidFormat)
	case secret != "" && !mail.ValidCredential(secret, 512):
		return field("mail_secret", fielderr.InvalidFormat)
	case !official && secret != "":
		return field("mail_secret", fielderr.Invalid)
	case !official:
		return nil
	}
	if _, ok := mail.Endpoint(value.MailProvider, value.MailRegion); !ok {
		return field("value.mail_region", fielderr.Invalid)
	}
	switch {
	case value.MailFrom == "":
		return field("value.mail_from", fielderr.Required)
	case value.MailProvider == MailProviderAliyun && value.MailAccessKeyID == "":
		return field("value.mail_access_key_id", fielderr.Required)
	case value.MailProvider != MailProviderAliyun && value.MailAccessKeyID != "":
		return field("value.mail_access_key_id", fielderr.Invalid)
	}
	return nil
}

// mailSecretDecision: keep reports whether the stored credential stays; ok
// is false when an official provider would have no credential of its own.
func mailSecretDecision(storedProvider, provider string, newSecret bool) (keep, ok bool) {
	switch {
	case newSecret:
		return false, true
	case MailProviderKind(provider) == MailKindOfficial:
		return true, storedProvider == provider
	default:
		return true, true
	}
}

func mailSecretFingerprint(secret string) string {
	return smsSecretFingerprint(mailSecretDomain + secret)
}

// sealMailSecret binds the envelope to the platform scope and the provider.
func sealMailSecret(cipher SecretCipher, scope, provider, secret string) (string, []byte, error) {
	plaintext := []byte(mailSecretDomain + scope + "\x00" + provider + "\x00" + secret)
	defer clear(plaintext)
	keyID, ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		return "", nil, ErrUnavailable
	}
	return keyID, ciphertext, nil
}

func openMailSecret(cipher SecretCipher, scope, provider, keyID string, ciphertext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrUnavailable
	}
	plaintext, err := cipher.Decrypt(keyID, ciphertext)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(plaintext)
	prefix := mailSecretDomain + scope + "\x00" + provider + "\x00"
	if !strings.HasPrefix(string(plaintext), prefix) || len(plaintext) == len(prefix) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), plaintext[len(prefix):]...), nil
}
