package systemusersettings

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// the CAPTCHA secrets and KYC provider credentials
// typed on the settings page are encrypted and never returned; omitted keeps
// them, "" clears them, a CAPTCHA reference still works but never next to a
// stored secret, CaptchaRuntime / IdentityVerificationRuntime hand the
// decrypted values to their users, and the identity policy applies only once
// the page saved it.
func TestPostgresSystemUserSettingsPageSecrets(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	text := func(value string) *string { return &value }
	save := func(revision int64, value Settings, secrets map[string]*string, key string) (Document, error) {
		return service.Save(t.Context(), actor, SaveRequest{ExpectedRevision: revision, Value: value, Secrets: secrets,
			RequestID: key, IdempotencyKey: key})
	}
	refused := func(err error, field string) bool {
		located, ok := fielderr.As(err)
		return errors.Is(err, ErrInvalidInput) && ok && located.Field == field
	}
	value := DefaultSettings()
	value.CaptchaProvider, value.SMSAntiAbuseMode, value.CaptchaAppID = "tencent", "tencent", "190000001"

	// 0. The dependent checks still refuse a page without any secret.
	if _, err := save(0, value, nil, "page-secrets-0"); !refused(err, "value.sms_anti_abuse_mode") {
		t.Fatalf("captcha mode without secrets: %v", err)
	}

	// 1. Plaintext secrets: saved encrypted, only fingerprints come back.
	const secretID, secretKey, appSecret = "AKIDpagesecretid0001", "page-secret-key-0001", "page-app-secret-0001"
	kycKey, kycHMAC := "kyc-api-key-page-0001", base64.StdEncoding.EncodeToString([]byte("kyc-callback-hmac-key-0123456789"))
	saved, err := save(0, value, map[string]*string{SecretCaptchaSecretID: text(secretID), SecretCaptchaSecretKey: text(secretKey),
		SecretCaptchaAppSecret: text(appSecret), SecretKYCAPIKey: text(kycKey), SecretKYCCallbackHMACKey: text(kycHMAC)},
		"page-secrets-1")
	if err != nil || saved.Revision != 1 || !saved.CaptchaSecretIDConfigured || !saved.CaptchaSecretKeyConfigured ||
		!saved.CaptchaAppSecretConfigured || !saved.KYCAPIKeyConfigured || !saved.KYCCallbackHMACKeyConfigured ||
		len(saved.CaptchaAppSecretFingerprint) != 16 {
		t.Fatalf("plaintext save=(%+v,%v)", saved, err)
	}
	var stored []byte
	var settingsJSON, fingerprints, receipts, payloads string
	if err := pool.QueryRow(t.Context(), `SELECT secrets_ciphertext,settings::text,secrets_fingerprints::text FROM platform_system_user_settings
		WHERE platform_scope_id=$1`, scopeID).Scan(&stored, &settingsJSON, &fingerprints); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(request_digest::text || coalesce(response_body::text,''),'')
		FROM platform_system_user_settings_write_requests WHERE target_scope_id=$1`, scopeID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT coalesce(string_agg(payload::text,''),'') FROM audit_events WHERE request_id LIKE 'page-secrets-%'`).
		Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	got, err := service.Get(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	for _, secret := range []string{secretID, secretKey, appSecret, kycKey, kycHMAC} {
		if len(stored) == 0 || bytes.Contains(stored, []byte(secret)) || strings.Contains(settingsJSON, secret) ||
			strings.Contains(fingerprints, secret) || strings.Contains(receipts, secret) || strings.Contains(payloads, secret) ||
			strings.Contains(string(encoded), secret) {
			t.Fatalf("secret %q stored, logged or returned in plaintext", secret)
		}
	}
	if got.CaptchaAppSecretFingerprint != saved.CaptchaAppSecretFingerprint || !got.KYCCallbackHMACKeyConfigured {
		t.Fatalf("get after save: %+v", got)
	}

	// 2. The CAPTCHA verifier gets the decrypted values.
	runtime, err := service.CaptchaRuntime(t.Context())
	if err != nil || runtime.SecretID != secretID || runtime.SecretKey != secretKey || runtime.AppSecret != appSecret ||
		runtime.AppID != "190000001" || runtime.SecretIDReference != "" {
		t.Fatalf("captcha runtime=(%+v,%v)", runtime, err)
	}
	// without the keyring the stored secrets cannot be opened (fail closed)
	plain, err := NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.CaptchaRuntime(t.Context()); err == nil {
		t.Fatal("captcha runtime opened secrets without the keyring")
	}

	// 3. Omitted keeps them, even when other settings change; one replaced alone keeps the rest.
	changed := value
	changed.SessionTTLSeconds = 3600
	kept, err := save(1, changed, map[string]*string{SecretCaptchaSecretKey: text("page-secret-key-0002")}, "page-secrets-2")
	if err != nil || !kept.CaptchaSecretIDConfigured || kept.CaptchaSecretIDFingerprint != saved.CaptchaSecretIDFingerprint ||
		kept.CaptchaSecretKeyFingerprint == saved.CaptchaSecretKeyFingerprint {
		t.Fatalf("omitted/replaced=(%+v,%v)", kept, err)
	}
	if runtime, err := service.CaptchaRuntime(t.Context()); err != nil || runtime.SecretID != secretID || runtime.SecretKey != "page-secret-key-0002" {
		t.Fatalf("runtime after partial replace=(%+v,%v)", runtime, err)
	}

	// 4. A reference next to a secret is refused either way.
	referenced := changed
	referenced.CaptchaAppSecretReference = "vault://captcha/app-secret"
	if _, err := save(2, referenced, map[string]*string{SecretCaptchaAppSecret: text("other")}, "page-secrets-3"); !refused(err, SecretCaptchaAppSecret) {
		t.Fatalf("secret with reference: %v", err)
	}
	if _, err := save(2, referenced, nil, "page-secrets-4"); !refused(err, "value.captcha_app_secret_reference") {
		t.Fatalf("reference while a secret is stored: %v", err)
	}

	// 5. "" clears one together with switching to its reference; the reference is then used.
	switched, err := save(2, referenced, map[string]*string{SecretCaptchaAppSecret: text("")}, "page-secrets-5")
	if err != nil || switched.CaptchaAppSecretConfigured || switched.CaptchaAppSecretFingerprint != "" || !switched.CaptchaSecretIDConfigured {
		t.Fatalf("clear and switch=(%+v,%v)", switched, err)
	}
	if runtime, err := service.CaptchaRuntime(t.Context()); err != nil || runtime.AppSecret != "" ||
		runtime.AppSecretReference != "vault://captcha/app-secret" || runtime.SecretID != secretID {
		t.Fatalf("runtime after switch=(%+v,%v)", runtime, err)
	}

	// 6. The KYC runtime gets the decrypted credentials; the identity policy is
	// not authoritative until the page saves it.
	kyc, err := service.IdentityVerificationRuntime(t.Context())
	if err != nil || string(kyc.KYCAPIKey) != kycKey || string(kyc.KYCCallbackHMAC) != kycHMAC || kyc.PolicySaved ||
		!kyc.KindEnabled("personal_initial") || !kyc.KindEnabled("enterprise") {
		t.Fatalf("identity runtime=(%+v,%v)", kyc, err)
	}
	if _, err := save(3, referenced, map[string]*string{SecretKYCCallbackHMACKey: text("not base64")}, "page-secrets-6"); !refused(err, SecretKYCCallbackHMACKey) {
		t.Fatalf("invalid KYC callback key: %v", err)
	}
	policy := referenced
	policy.IdentityPolicySaved, policy.IdentityVerificationMethod, policy.EnterpriseVerificationEnabled = true, "none", true
	if _, err := save(3, policy, nil, "page-secrets-6b"); err != nil {
		t.Fatal(err)
	}
	if kyc, err := service.IdentityPolicy(t.Context()); err != nil || kyc.KYCAPIKey != nil || kyc.KindEnabled("personal_initial") || !kyc.KindEnabled("enterprise") {
		t.Fatalf("saved policy=(%+v,%v)", kyc, err)
	}

	// 7. Clearing all of them empties the envelope columns.
	off := referenced
	off.SMSAntiAbuseMode, off.EnterpriseVerificationEnabled = "native", false
	all := map[string]*string{}
	for _, name := range secretNames {
		all[name] = text("")
	}
	cleared, err := save(4, off, all, "page-secrets-7")
	if err != nil || cleared.CaptchaSecretIDConfigured || cleared.KYCAPIKeyConfigured {
		t.Fatalf("clear all=(%+v,%v)", cleared, err)
	}
	var keyID *string
	var rawPrints []byte
	if err := pool.QueryRow(t.Context(), `SELECT secrets_key_id,secrets_fingerprints FROM platform_system_user_settings WHERE platform_scope_id=$1`,
		scopeID).Scan(&keyID, &rawPrints); err != nil || keyID != nil || rawPrints != nil {
		t.Fatalf("cleared row key=%v prints=%s err=%v", keyID, rawPrints, err)
	}

	// 8. A new secret without the keyring is refused before anything is stored.
	if _, err := plain.Save(t.Context(), actor, SaveRequest{ExpectedRevision: 5, Value: off,
		Secrets: map[string]*string{SecretCaptchaSecretID: text("x")}, RequestID: "page-secrets-8", IdempotencyKey: "page-secrets-8"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("save without keyring: %v", err)
	}
}

// the HTTPS SMS gateway token typed on the page is
// encrypted like the SMTP password; the runtime opens it in place of
// NOTIFICATION_SMS_AUTH_TOKEN.
func TestPostgresSystemMailSMSAuthToken(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSecretCipher(xorCipher{})
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	save := func(revision int64, value systemmailsettings.Settings, token *string, key string) (systemmailsettings.Document, error) {
		return service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: revision, Value: value,
			SMSAuthToken: token, RequestID: key, IdempotencyKey: key})
	}
	text := func(value string) *string { return &value }
	refused := func(err error, field string) bool {
		located, ok := fielderr.As(err)
		return errors.Is(err, systemmailsettings.ErrInvalidInput) && ok && located.Field == field
	}
	gateway := systemmailsettings.DefaultSettings()
	gateway.SMSProvider, gateway.SMSAccessKeyID = systemmailsettings.SMSProviderHTTPSJSON, "sms-account"

	const token = "plain-sms-gateway-token"
	saved, err := save(0, gateway, text(token), "sms-token-1")
	if err != nil || !saved.SMSAuthTokenConfigured || len(saved.SMSAuthTokenFingerprint) != 16 || saved.SMSSecretConfigured {
		t.Fatalf("plaintext save=(%+v,%v)", saved, err)
	}
	var stored []byte
	if err := pool.QueryRow(t.Context(), `SELECT sms_auth_token_ciphertext FROM platform_system_mail_settings WHERE platform_scope_id=$1`,
		scopeID).Scan(&stored); err != nil || len(stored) == 0 || bytes.Contains(stored, []byte(token)) {
		t.Fatalf("stored token %q err %v", stored, err)
	}
	encoded, _ := json.Marshal(mustGetMail(t, service, actor))
	if strings.Contains(string(encoded), token) || !strings.Contains(string(encoded), `"sms_auth_token_configured":true`) {
		t.Fatalf("get returned %s", encoded)
	}
	runtime, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil || !runtime.HasSMSAuthToken() {
		t.Fatalf("runtime=(%+v,%v)", runtime, err)
	}
	if opened, err := runtime.OpenSMSAuthToken(xorCipher{}); err != nil || string(opened) != token {
		t.Fatalf("open token=%q err=%v", opened, err)
	}

	// omitted keeps; a reference next to it is refused; "" clears and the reference works again
	kept, err := save(1, gateway, nil, "sms-token-2")
	if err != nil || kept.SMSAuthTokenFingerprint != saved.SMSAuthTokenFingerprint {
		t.Fatalf("omitted=(%+v,%v)", kept, err)
	}
	referenced := gateway
	referenced.SMSAccessKeyReference = "vault://sms/token"
	if _, err := save(2, referenced, nil, "sms-token-3"); !refused(err, "value.sms_access_key_reference") {
		t.Fatalf("reference while a token is stored: %v", err)
	}
	if _, err := save(2, referenced, text("other"), "sms-token-4"); !refused(err, "sms_auth_token") {
		t.Fatalf("token with reference: %v", err)
	}
	cleared, err := save(2, referenced, text(""), "sms-token-5")
	if err != nil || cleared.SMSAuthTokenConfigured || cleared.Value.SMSAccessKeyReference != "vault://sms/token" {
		t.Fatalf("clear and switch=(%+v,%v)", cleared, err)
	}
	if runtime, err := systemmailsettings.ReadRuntime(t.Context(), pool); err != nil || runtime.HasSMSAuthToken() {
		t.Fatalf("runtime after clear=(%+v,%v)", runtime, err)
	}
}
