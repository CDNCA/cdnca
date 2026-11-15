package systemmailsettings

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func TestSMSAuthTokenFieldError(t *testing.T) {
	text := func(value string) *string { return &value }
	gateway := DefaultSettings()
	gateway.SMSProvider, gateway.SMSAccessKeyID = SMSProviderHTTPSJSON, "account"
	withReference := gateway
	withReference.SMSAccessKeyReference = "vault://sms/token"
	native := gateway
	native.SMSProvider = SMSProviderAliyun
	for name, tc := range map[string]struct {
		value  Settings
		token  *string
		stored bool
		field  string
	}{
		"omitted":               {value: gateway},
		"omitted keeps stored":  {value: gateway, stored: true},
		"plaintext":             {value: gateway, token: text("gateway token")},
		"clear":                 {value: withReference, token: text(""), stored: true},
		"reference alone":       {value: withReference},
		"token with reference":  {value: withReference, token: text("t"), field: "sms_auth_token"},
		"reference next stored": {value: withReference, stored: true, field: "value.sms_access_key_reference"},
		"native provider":       {value: native, token: text("t"), field: "sms_auth_token"},
		"native clear":          {value: native, token: text(""), stored: true},
		"line break":            {value: gateway, token: text("a\nb"), field: "sms_auth_token"},
		"too long":              {value: gateway, token: text(strings.Repeat("x", 4097)), field: "sms_auth_token"},
	} {
		err := smsAuthTokenFieldError(tc.value, tc.token, tc.stored)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field):
			t.Errorf("%s: %v, want field %s", name, err, tc.field)
		}
	}
}

// The token is sealed to the scope under its own domain, opened back through
// RuntimeSettings, and never reaches the request digest in plaintext.
func TestSMSAuthTokenSealOpenAndDigest(t *testing.T) {
	scope := uuid.New()
	const token = "plain-sms-gateway-token"
	keyID, sealed, err := sealSMSAuthToken(reverseCipher{}, scope.String(), token)
	if err != nil || bytes.Contains(sealed, []byte(token)) {
		t.Fatalf("seal=(%q,%v)", sealed, err)
	}
	settings := RuntimeSettings{Configured: true, scopeID: scope, smsTokenKeyID: &keyID, smsTokenCiphertext: sealed}
	if !settings.HasSMSAuthToken() || settings.HasSMTPPassword() {
		t.Fatal("stored token not reported apart from the SMTP password")
	}
	opened, err := settings.OpenSMSAuthToken(reverseCipher{})
	if err != nil || string(opened) != token {
		t.Fatalf("open=(%q,%v)", opened, err)
	}
	if _, err := openSMTPPassword(reverseCipher{}, scope.String(), keyID, sealed); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("token opened as an SMTP password: %v", err)
	}
	if _, err := openSMSAuthToken(reverseCipher{}, uuid.NewString(), keyID, sealed); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opened under another scope: %v", err)
	}
	if smsAuthTokenFingerprint(token) == smtpPasswordFingerprint(token) || len(smsAuthTokenFingerprint(token)) != 16 {
		t.Fatal("fingerprint is not domain separated")
	}

	request := SaveRequest{Value: DefaultSettings(), IdempotencyKey: "k", RequestID: "r"}
	omitted, _ := requestDigest(request)
	empty := ""
	request.SMSAuthToken = &empty
	cleared, _ := requestDigest(request)
	value := token
	request.SMSAuthToken = &value
	replaced, _ := requestDigest(request)
	if omitted == cleared || cleared == replaced || omitted == replaced {
		t.Fatal("omitted, cleared and replaced share a request digest")
	}
}
