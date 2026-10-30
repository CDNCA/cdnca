package systemusersettings

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

type xorCipher struct{}

func (xorCipher) Encrypt(plaintext []byte) (string, []byte, error) {
	out := make([]byte, len(plaintext)+29)
	for index, value := range plaintext {
		out[index+29] = value ^ 0x5a
	}
	return "test-key", out, nil
}

func (xorCipher) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID != "test-key" || len(ciphertext) < 29 {
		return nil, errors.New("bad envelope")
	}
	out := make([]byte, len(ciphertext)-29)
	for index, value := range ciphertext[29:] {
		out[index] = value ^ 0x5a
	}
	return out, nil
}

// FX66：原生阿里云/submail 凭据加密存储，接口只回显掩码（指纹）。
func TestPostgresSystemMailNativeSMSCredential(t *testing.T) {
	pool := systemUserSettingsPool(t)
	scopeID, userID, _ := seedSystemUserSettingsActor(t, pool)
	service, err := systemmailsettings.NewService(pool, audit.New(pool), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := systemmailsettings.Actor{UserID: userID, ScopeID: scopeID, ScopeKind: "platform"}
	value := systemmailsettings.DefaultSettings()
	value.SMSProvider, value.SMSAccessKeyID, value.SMSSignatureName = "aliyun", "LTAI-id", "CDNCA"
	value.SMSTemplateMap = `{"node.availability.offline.zh-cn":{"code":"SMS_100","variables":{"node_name":"name"}}}`
	const secret = "aliyun-access-key-secret"
	request := systemmailsettings.SaveRequest{Value: value, SMSAccessKeySecret: secret,
		RequestID: "native-sms-1", IdempotencyKey: "native-sms-1"}
	if _, err := service.Save(t.Context(), actor, request); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
		t.Fatalf("secret accepted without a credential cipher: %v", err)
	}
	service.WithSecretCipher(xorCipher{})
	saved, err := service.Save(t.Context(), actor, request)
	if err != nil || saved.Revision != 1 || !saved.SMSSecretConfigured || len(saved.SMSSecretFingerprint) != 16 {
		t.Fatalf("save native provider=(%+v,%v)", saved, err)
	}
	var stored []byte
	var settingsJSON string
	if err := pool.QueryRow(t.Context(), `SELECT sms_secret_ciphertext,settings::text FROM platform_system_mail_settings
		WHERE platform_scope_id=$1`, scopeID).Scan(&stored, &settingsJSON); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(secret)) || strings.Contains(settingsJSON, secret) {
		t.Fatal("secret stored in plaintext")
	}
	for _, document := range []systemmailsettings.Document{saved, mustGetMail(t, service, actor)} {
		encoded, _ := json.Marshal(document)
		if strings.Contains(string(encoded), secret) || !strings.Contains(string(encoded), `"sms_secret_fingerprint":"`+saved.SMSSecretFingerprint+`"`) {
			t.Fatalf("document leaks secret or misses mask: %s", encoded)
		}
	}
	// 重放同一请求返回同一结果、不写第二次；回执里同样没有明文。
	replayed, err := service.Save(t.Context(), actor, request)
	if err != nil || !replayed.Replayed || replayed.Revision != 1 {
		t.Fatalf("replay=(%+v,%v)", replayed, err)
	}
	var receipts string
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(response_body::text,'') FROM platform_system_mail_settings_write_requests
		WHERE target_scope_id=$1`, scopeID).Scan(&receipts); err != nil || strings.Contains(receipts, secret) {
		t.Fatalf("write receipt leaks secret (%v)", err)
	}
	runtimeSettings, err := systemmailsettings.ReadRuntime(t.Context(), pool)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtimeSettings.OpenSMSSecret(xorCipher{})
	if err != nil || string(opened) != secret {
		t.Fatalf("open secret=%q err=%v", opened, err)
	}
	// 留空保存 = 保留原密钥。
	value.SMSSignatureName = "CDNCA2"
	kept, err := service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: 1, Value: value,
		RequestID: "native-sms-2", IdempotencyKey: "native-sms-2"})
	if err != nil || kept.SMSSecretFingerprint != saved.SMSSecretFingerprint {
		t.Fatalf("keep secret=(%+v,%v)", kept, err)
	}
	for name, invalid := range map[string]systemmailsettings.Settings{
		"bad template map": withMail(value, func(v *systemmailsettings.Settings) { v.SMSTemplateMap = `{"x":` }),
		"aliyun no sign":   withMail(value, func(v *systemmailsettings.Settings) { v.SMSSignatureName = "" }),
		"vault reference":  withMail(value, func(v *systemmailsettings.Settings) { v.SMSAccessKeyReference = "vault://sms" }),
	} {
		if _, err := service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: 2, Value: invalid,
			RequestID: "native-sms-bad", IdempotencyKey: "native-sms-bad-" + strings.ReplaceAll(name, " ", "-")}); !errors.Is(err, systemmailsettings.ErrInvalidInput) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	// 切回自定义网关：库中密钥一并清除。
	value.SMSProvider, value.SMSTemplateMap = "https_json", ""
	cleared, err := service.Save(t.Context(), actor, systemmailsettings.SaveRequest{ExpectedRevision: 2, Value: value,
		RequestID: "native-sms-3", IdempotencyKey: "native-sms-3"})
	if err != nil || cleared.SMSSecretConfigured {
		t.Fatalf("switch provider=(%+v,%v)", cleared, err)
	}
	var keyID *string
	if err := pool.QueryRow(t.Context(), `SELECT sms_secret_key_id FROM platform_system_mail_settings WHERE platform_scope_id=$1`, scopeID).Scan(&keyID); err != nil || keyID != nil {
		t.Fatalf("secret not cleared: %v %v", keyID, err)
	}
}

func mustGetMail(t *testing.T, service *systemmailsettings.Service, actor systemmailsettings.Actor) systemmailsettings.Document {
	t.Helper()
	document, err := service.Get(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func withMail(value systemmailsettings.Settings, change func(*systemmailsettings.Settings)) systemmailsettings.Settings {
	change(&value)
	return value
}
