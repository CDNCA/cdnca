package systemmailsettings

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func saveWithoutStore(t *testing.T, request SaveRequest) error {
	t.Helper()
	defer func() {
		if recover() != nil {
			t.Fatal("invalid mail provider reached storage")
		}
	}()
	request.RequestID, request.IdempotencyKey = "mail-provider-validation", "mail-provider-validation"
	_, err := (&Service{cipher: testCipher{}}).Save(context.Background(),
		Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}, request)
	return err
}

type testCipher struct{}

func (testCipher) Encrypt(plaintext []byte) (string, []byte, error)    { return "k", plaintext, nil }
func (testCipher) Decrypt(_ string, ciphertext []byte) ([]byte, error) { return ciphertext, nil }

func officialMail(provider string) Settings {
	value := DefaultSettings()
	value.MailProvider, value.MailFrom = provider, "noreply@example.com"
	if provider == MailProviderAliyun {
		value.MailAccessKeyID = "LTAI-id"
	}
	return value
}

func TestSaveRejectsUnknownMailProviderBeforeStorage(t *testing.T) {
	for _, provider := range []string{"ses", "SMTP", "smtp ", "Aliyun", "plugin:", "plugin:Bad_ID", "plugin:com.example.mail/x", "plugin:x"} {
		t.Run(provider, func(t *testing.T) {
			value := DefaultSettings()
			value.MailProvider = provider
			if err := saveWithoutStore(t, SaveRequest{Value: value}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestSaveRejectsIncompleteOfficialMailProviderBeforeStorage(t *testing.T) {
	cases := map[string]SaveRequest{
		"aliyun without access key id": {Value: func() Settings { v := officialMail(MailProviderAliyun); v.MailAccessKeyID = ""; return v }(), MailSecret: "s"},
		"sendgrid with access key id":  {Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailAccessKeyID = "x"; return v }(), MailSecret: "SG.k"},
		"no sender":                    {Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailFrom = ""; return v }(), MailSecret: "SG.k"},
		"sender with display name":     {Value: func() Settings { v := officialMail(MailProviderSendGrid); v.MailFrom = "A <a@example.com>"; return v }(), MailSecret: "SG.k"},
		"unknown region":               {Value: func() Settings { v := officialMail(MailProviderAliyun); v.MailRegion = "mars-1"; return v }(), MailSecret: "s"},
		"secret with newline":          {Value: officialMail(MailProviderSendGrid), MailSecret: "SG.k\nBcc"},
		"secret for smtp":              {Value: DefaultSettings(), MailSecret: "SG.k"},
		"secret for plugin":            {Value: func() Settings { v := DefaultSettings(); v.MailProvider = "plugin:com.example.mail"; return v }(), MailSecret: "x"},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if err := saveWithoutStore(t, request); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v, want ErrInvalidInput", err)
			}
		})
	}
}

// The official fields stay saved while SMTP or a plugin sends.
func TestValidMailProviderKeepsOfficialFieldsForOtherSenders(t *testing.T) {
	for _, provider := range []string{"", MailProviderSMTP, "plugin:com.example.mail"} {
		value := officialMail(MailProviderAliyun)
		value.MailProvider = provider
		if !validMailProvider(value, "") {
			t.Errorf("%q with saved official fields rejected", provider)
		}
	}
}

func TestMailProviderKinds(t *testing.T) {
	for provider, want := range map[string]string{"": MailKindSMTP, "aliyun": MailKindOfficial, "sendgrid": MailKindOfficial,
		"plugin:com.example.mail": MailKindPlugin, "ses": ""} {
		if got := MailProviderKind(provider); got != want {
			t.Errorf("%q kind %q, want %q", provider, got, want)
		}
	}
	if id, ok := MailPluginID("plugin:com.example.mail"); !ok || id != "com.example.mail" {
		t.Fatalf("plugin id %q %v", id, ok)
	}
}

// The official credential is kept while another kind of sender is chosen
// (switching back to that provider works without re-entry) but never reused
// for a different official provider.
func TestMailSecretDecision(t *testing.T) {
	cases := map[string]struct {
		stored, provider string
		newSecret        bool
		keep, ok         bool
	}{
		"same provider keeps":           {MailProviderAliyun, MailProviderAliyun, false, true, true},
		"switch to smtp keeps":          {MailProviderAliyun, "", false, true, true},
		"switch to plugin keeps":        {MailProviderAliyun, "plugin:com.example.mail", false, true, true},
		"other official needs a secret": {MailProviderAliyun, MailProviderSendGrid, false, false, false},
		"other official with secret":    {MailProviderAliyun, MailProviderSendGrid, true, false, true},
		"first official without secret": {"", MailProviderAliyun, false, false, false},
		"smtp without stored":           {"", "", false, true, true},
	}
	for name, c := range cases {
		keep, ok := mailSecretDecision(c.stored, c.provider, c.newSecret)
		if ok != c.ok || ok && keep != c.keep {
			t.Errorf("%s: keep=%v ok=%v", name, keep, ok)
		}
	}
}
