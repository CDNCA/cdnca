package systemusersettings

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func TestSecretsFieldError(t *testing.T) {
	text := func(value string) *string { return &value }
	withReference := DefaultSettings()
	withReference.CaptchaSecretKeyReference = "vault://captcha/secret-key"
	for name, tc := range map[string]struct {
		value   Settings
		secrets map[string]*string
		stored  []string
		field   string
	}{
		"omitted":                {value: DefaultSettings()},
		"omitted keeps stored":   {value: DefaultSettings(), stored: []string{SecretCaptchaSecretKey}},
		"plaintext":              {value: DefaultSettings(), secrets: map[string]*string{SecretCaptchaSecretKey: text("AKIDplain")}},
		"clear next to ref":      {value: withReference, secrets: map[string]*string{SecretCaptchaSecretKey: text("")}, stored: []string{SecretCaptchaSecretKey}},
		"reference alone":        {value: withReference},
		"plaintext with ref":     {value: withReference, secrets: map[string]*string{SecretCaptchaSecretKey: text("p")}, field: SecretCaptchaSecretKey},
		"ref next to stored":     {value: withReference, stored: []string{SecretCaptchaSecretKey}, field: "value.captcha_secret_key_reference"},
		"line break":             {value: DefaultSettings(), secrets: map[string]*string{SecretKYCAPIKey: text("a\nb")}, field: SecretKYCAPIKey},
		"surrounding space":      {value: DefaultSettings(), secrets: map[string]*string{SecretCaptchaAppSecret: text(" a")}, field: SecretCaptchaAppSecret},
		"too long":               {value: DefaultSettings(), secrets: map[string]*string{SecretCaptchaSecretKey: text(strings.Repeat("x", 1025))}, field: SecretCaptchaSecretKey},
		"kyc api key":            {value: DefaultSettings(), secrets: map[string]*string{SecretKYCAPIKey: text("kyc-api-key-0123456789")}},
		"kyc api key short":      {value: DefaultSettings(), secrets: map[string]*string{SecretKYCAPIKey: text("short")}, field: SecretKYCAPIKey},
		"kyc hmac":               {value: DefaultSettings(), secrets: map[string]*string{SecretKYCCallbackHMACKey: text(base64.StdEncoding.EncodeToString(make([]byte, 32)))}},
		"kyc hmac not base64":    {value: DefaultSettings(), secrets: map[string]*string{SecretKYCCallbackHMACKey: text("not-base64-but-long-enough-0123456789")}, field: SecretKYCCallbackHMACKey},
		"kyc hmac too small":     {value: DefaultSettings(), secrets: map[string]*string{SecretKYCCallbackHMACKey: text(base64.StdEncoding.EncodeToString(make([]byte, 16)))}, field: SecretKYCCallbackHMACKey},
		"kyc clear":              {value: DefaultSettings(), secrets: map[string]*string{SecretKYCAPIKey: text("")}, stored: []string{SecretKYCAPIKey}},
		"unknown secret":         {value: DefaultSettings(), secrets: map[string]*string{"smtp_password": text("x")}, field: "smtp_password"},
		"other ref, other saved": {value: withReference, stored: []string{SecretCaptchaSecretID}},
	} {
		err := secretsFieldError(tc.value, tc.secrets, tc.stored)
		located, ok := fielderr.As(err)
		switch {
		case tc.field == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.field != "" && (!errors.Is(err, ErrInvalidInput) || !ok || located.Field != tc.field):
			t.Errorf("%s: %v, want field %s", name, err, tc.field)
		}
	}
}

// A saved secret stands in for its empty reference in the external CAPTCHA
// check; enterprise verification needs no page secret (the KYC credentials
// may come from the environment).
func TestSettingsFieldErrorAcceptsSavedSecrets(t *testing.T) {
	value := DefaultSettings()
	value.EmailAntiAbuseMode, value.CaptchaProvider, value.CaptchaAppID = "tencent", "tencent", "190000000"
	value.EnterpriseVerificationEnabled = true
	if err := settingsFieldError(value); err == nil {
		t.Fatal("nothing configured was accepted")
	}
	if err := settingsFieldError(value, SecretCaptchaSecretID, SecretCaptchaSecretKey, SecretCaptchaAppSecret); err != nil {
		t.Fatalf("captcha secrets saved, enterprise on without page KYC credentials: %v", err)
	}
	// a reference still works for the same secret
	value.CaptchaAppSecretReference = "vault://captcha/app-secret"
	if err := settingsFieldError(value, SecretCaptchaSecretID, SecretCaptchaSecretKey); err != nil {
		t.Fatalf("saved secrets plus a reference: %v", err)
	}
}

// Until the page saves the identity policy every kind may start (the earlier
// behaviour whenever the KYC provider is configured); afterwards the page
// decides.
func TestIdentityVerificationRuntimeKindEnabled(t *testing.T) {
	unsaved := IdentityVerificationRuntime{}
	for _, kind := range []string{"personal_initial", "personal_reverification", "enterprise"} {
		if !unsaved.KindEnabled(kind) {
			t.Fatalf("unsaved policy refused %s", kind)
		}
	}
	saved := IdentityVerificationRuntime{PolicySaved: true, PersonalEnabled: true}
	if !saved.KindEnabled("personal_initial") || !saved.KindEnabled("personal_reverification") || saved.KindEnabled("enterprise") {
		t.Fatalf("personal only: %+v", saved)
	}
	saved = IdentityVerificationRuntime{PolicySaved: true, EnterpriseEnabled: true}
	if saved.KindEnabled("personal_initial") || !saved.KindEnabled("enterprise") {
		t.Fatalf("enterprise only: %+v", saved)
	}
}

func TestNextSecretsKeepReplaceClear(t *testing.T) {
	text := func(value string) *string { return &value }
	current := map[string]string{SecretCaptchaSecretID: "id-1", SecretCaptchaSecretKey: "key-1"}
	next, changes := nextSecrets(current, map[string]*string{
		SecretCaptchaSecretKey: text("key-2"), SecretCaptchaSecretID: nil, SecretCaptchaAppSecret: text(""),
		SecretKYCAPIKey: text("kyc-1"),
	})
	if next[SecretCaptchaSecretID] != "id-1" || next[SecretCaptchaSecretKey] != "key-2" || next[SecretKYCAPIKey] != "kyc-1" || len(next) != 3 {
		t.Fatalf("next=%v", next)
	}
	if changes[SecretCaptchaSecretID] != "unchanged" || changes[SecretCaptchaSecretKey] != "replaced" ||
		changes[SecretCaptchaAppSecret] != "unchanged" || changes[SecretKYCAPIKey] != "replaced" {
		t.Fatalf("changes=%v", changes)
	}
	if current[SecretCaptchaSecretKey] != "key-1" {
		t.Fatal("current was modified")
	}
	cleared, changes := nextSecrets(next, map[string]*string{SecretCaptchaSecretID: text("")})
	if _, ok := cleared[SecretCaptchaSecretID]; ok || changes[SecretCaptchaSecretID] != "cleared" {
		t.Fatalf("clear=%v %v", cleared, changes)
	}
	if secretsChange(map[string]*string{SecretCaptchaSecretID: text("")}, nil) ||
		!secretsChange(map[string]*string{SecretCaptchaSecretID: text("")}, []string{SecretCaptchaSecretID}) ||
		secretsChange(map[string]*string{SecretCaptchaSecretID: nil}, []string{SecretCaptchaSecretID}) {
		t.Fatal("secretsChange misjudged a save")
	}
}

// The secrets are sealed to the scope, opened back through CaptchaRuntime's
// helper, fingerprinted per name and never reach the request digest in
// plaintext.
func TestSecretsSealOpenAndDigest(t *testing.T) {
	scope := uuid.New()
	const secret = "plain-captcha-app-secret"
	keyID, sealed, err := sealSecrets(xorCipher{}, scope.String(), map[string]string{SecretCaptchaAppSecret: secret})
	if err != nil || bytes.Contains(sealed, []byte(secret)) {
		t.Fatalf("seal=(%q,%v)", sealed, err)
	}
	opened, err := openSecrets(xorCipher{}, scope.String(), keyID, sealed)
	if err != nil || opened[SecretCaptchaAppSecret] != secret || len(opened) != 1 {
		t.Fatalf("open=(%v,%v)", opened, err)
	}
	if _, err := openSecrets(xorCipher{}, uuid.NewString(), keyID, sealed); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opened under another scope: %v", err)
	}
	if _, err := openSecrets(nil, scope.String(), keyID, sealed); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("opened without a cipher: %v", err)
	}
	if _, _, err := sealSecrets(nil, scope.String(), map[string]string{SecretCaptchaAppSecret: secret}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("sealed without a cipher: %v", err)
	}
	if len(secretFingerprint(SecretCaptchaAppSecret, secret)) != 16 ||
		secretFingerprint(SecretCaptchaAppSecret, secret) == secretFingerprint(SecretCaptchaSecretKey, secret) {
		t.Fatal("fingerprint is not separated by secret name")
	}
	if _, stored, err := decodeFingerprints([]byte(`{"captcha_secret_key":"0123456789abcdef","captcha_secret_id":"0123456789abcdef"}`)); err != nil ||
		strings.Join(stored, ",") != "captcha_secret_id,captcha_secret_key" {
		t.Fatalf("decode fingerprints=(%v,%v)", stored, err)
	}
	if _, _, err := decodeFingerprints([]byte(`{"smtp_password":"0123456789abcdef"}`)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown stored secret accepted: %v", err)
	}

	request := SaveRequest{Value: DefaultSettings(), IdempotencyKey: "k", RequestID: "r"}
	omitted := requestDigest(request)
	empty, value := "", secret
	request.Secrets = map[string]*string{SecretCaptchaAppSecret: &empty}
	cleared := requestDigest(request)
	request.Secrets = map[string]*string{SecretCaptchaAppSecret: &value}
	replaced := requestDigest(request)
	if omitted == cleared || cleared == replaced || omitted == replaced {
		t.Fatal("omitted, cleared and replaced share a request digest")
	}
}
